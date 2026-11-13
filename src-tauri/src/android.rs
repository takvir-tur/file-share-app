use std::fs::OpenOptions;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use jni::objects::{JClass, JObject, JObjectArray, JString, JValue};
use jni::JNIEnv;
use tauri::{AppHandle, Emitter, Manager};

#[derive(Debug, Clone)]
pub struct AndroidDownloadDirs {
    /// Directory where `TransferEngine` writes incoming files and `.beamdrop.part` chunks.
    pub engine_dir: PathBuf,
    /// Public `Download/BeamDrop` folder visible in Samsung My Files / Files app.
    pub public_dir: PathBuf,
    /// `true` when scoped storage forced staging inside app-private storage prior to MediaStore export.
    pub uses_staging: bool,
}

static PENDING_ANDROID_SHARE_PATHS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static ANDROID_APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();
static ANDROID_DOWNLOAD_DIRS: OnceLock<AndroidDownloadDirs> = OnceLock::new();

/// Resolves the public `Download/BeamDrop` folder and probes direct POSIX write access.
///
/// If Android 11+ scoped storage denies direct POSIX writes in public Downloads,
/// incoming transfers stage in app-local storage and export via `MediaStore.Downloads`
/// as soon as checksum verification completes.
pub fn resolve_download_dirs(app_local_data_dir: Option<PathBuf>) -> AndroidDownloadDirs {
    if let Some(existing) = ANDROID_DOWNLOAD_DIRS.get() {
        return existing.clone();
    }

    let public_base = std::env::var_os("EXTERNAL_STORAGE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/storage/emulated/0"));
    let public_dir = public_base.join("Download").join("BeamDrop");

    let resolved = if is_dir_posix_writable(&public_dir) {
        AndroidDownloadDirs {
            engine_dir: public_dir.clone(),
            public_dir,
            uses_staging: false,
        }
    } else {
        let staging_root = app_local_data_dir
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/data/local/tmp"));
        let engine_dir = staging_root.join("BeamDropStaging");
        let _ = std::fs::create_dir_all(&engine_dir);
        AndroidDownloadDirs {
            engine_dir,
            public_dir,
            uses_staging: true,
        }
    };

    let _ = ANDROID_DOWNLOAD_DIRS.set(resolved.clone());
    resolved
}

/// Returns the user-facing public Downloads directory (`Download/BeamDrop`) if initialized.
pub fn public_download_dir() -> Option<PathBuf> {
    ANDROID_DOWNLOAD_DIRS
        .get()
        .map(|dirs| dirs.public_dir.clone())
}

fn is_dir_posix_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".beamdrop_write_probe_{}", std::process::id()));
    let writable = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(mut file) => file.write_all(b"probe").is_ok() && file.flush().is_ok(),
        Err(_) => false,
    };
    let _ = std::fs::remove_file(&probe);
    writable
}

/// Drains paths shared from Android before `AppState` was created.
pub fn take_initial_shared_paths() -> Vec<String> {
    match PENDING_ANDROID_SHARE_PATHS.lock() {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(_) => Vec::new(),
    }
}

/// Binds the active Tauri `AppHandle` and flushes any share paths queued during cold start.
pub fn bind_app_handle(app: AppHandle) {
    let leftover = match PENDING_ANDROID_SHARE_PATHS.lock() {
        Ok(mut guard) => {
            let _ = ANDROID_APP_HANDLE.set(app.clone());
            std::mem::take(&mut *guard)
        }
        Err(_) => {
            let _ = ANDROID_APP_HANDLE.set(app.clone());
            Vec::new()
        }
    };

    if !leftover.is_empty() {
        let state = app.state::<crate::commands::AppState>();
        state.queue_send_paths(leftover.clone());
        let _ = app.emit(crate::commands::EVENT_SEND_PATHS, &leftover);
    }
}

fn enqueue_shared_paths(paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }

    if let Ok(mut guard) = PENDING_ANDROID_SHARE_PATHS.lock() {
        if let Some(app) = ANDROID_APP_HANDLE.get() {
            let state = app.state::<crate::commands::AppState>();
            state.queue_send_paths(paths.clone());
            let _ = app.emit(crate::commands::EVENT_SEND_PATHS, &paths);
        } else {
            guard.extend(paths);
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeQueueSharedPaths<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    paths: JObjectArray<'local>,
) {
    let Ok(len) = env.get_array_length(&paths) else {
        clear_jni_exception(&mut env);
        return;
    };

    let mut collected = Vec::with_capacity(len.max(0) as usize);
    for idx in 0..len {
        let Ok(elem) = env.get_object_array_element(&paths, idx) else {
            clear_jni_exception(&mut env);
            continue;
        };
        if elem.is_null() {
            continue;
        }
        let jstr = JString::from(elem);
        let text = match env.get_string(&jstr) {
            Ok(java_str) => Some(java_str.to_string_lossy().into_owned()),
            Err(_) => {
                clear_jni_exception(&mut env);
                None
            }
        };
        if let Some(s) = text {
            if !s.is_empty() {
                collected.push(s);
            }
        }
    }

    enqueue_shared_paths(collected);
}

/// Scans or exports completed received files into the public Android `Download/BeamDrop` folder,
/// returning the user-facing `Download/BeamDrop` path when files are available there.
pub fn finalize_completed_transfer(output_dir: PathBuf, files: Vec<PathBuf>) -> Option<PathBuf> {
    let public_dir = ANDROID_DOWNLOAD_DIRS
        .get()
        .map(|cfg| cfg.public_dir.clone());
    let uses_staging = ANDROID_DOWNLOAD_DIRS
        .get()
        .map(|cfg| cfg.uses_staging)
        .unwrap_or(false);

    if files.is_empty() {
        return if uses_staging {
            None
        } else {
            public_dir
        };
    }

    match notify_completed_transfer_jni(&output_dir, &files, uses_staging) {
        Ok(true) => public_dir,
        Ok(false) => None,
        Err(err) => {
            tracing::warn!(%err, "Android media notification/export failed");
            if uses_staging {
                None
            } else {
                public_dir
            }
        }
    }
}

/// Opens the system Downloads UI on Android via `BeamDropStorage.openDownloadsFolder`.
pub fn open_public_downloads() -> Result<(), String> {
    with_storage_class(|env, context, storage_cls| {
        let opened = env
            .call_static_method(
                storage_cls,
                "openDownloadsFolder",
                "(Landroid/content/Context;)Z",
                &[JValue::Object(context)],
            )?
            .z()?;
        if !opened {
            return Err(jni::errors::Error::JavaException);
        }
        Ok(())
    })
    .map_err(|err| format!("Failed to open Android Downloads folder: {err}"))
}

fn notify_completed_transfer_jni(
    output_dir: &Path,
    files: &[PathBuf],
    uses_staging: bool,
) -> jni::errors::Result<bool> {
    let abs_paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    with_storage_class(|env, context, storage_cls| {
        let j_paths = build_string_array(env, &abs_paths)?;

        if uses_staging {
            let rel_subdirs: Vec<String> = files
                .iter()
                .map(|file| relative_parent_dir(output_dir, file))
                .collect();
            let j_subdirs = build_string_array(env, &rel_subdirs)?;

            let exported = env
                .call_static_method(
                    storage_cls,
                    "exportFilesToPublicDownloads",
                    "(Landroid/content/Context;[Ljava/lang/String;[Ljava/lang/String;)Z",
                    &[
                        JValue::Object(context),
                        JValue::Object(j_paths.as_ref()),
                        JValue::Object(j_subdirs.as_ref()),
                    ],
                )?
                .z()?;

            if exported {
                cleanup_exported_staging(output_dir, files);
            }
            Ok(exported)
        } else {
            env.call_static_method(
                storage_cls,
                "scanCompletedFiles",
                "(Landroid/content/Context;[Ljava/lang/String;)V",
                &[JValue::Object(context), JValue::Object(j_paths.as_ref())],
            )?;
            Ok(true)
        }
    })
}

fn relative_parent_dir(root: &Path, file: &Path) -> String {
    let Ok(rel) = file.strip_prefix(root) else {
        return String::new();
    };
    let Some(parent) = rel.parent() else {
        return String::new();
    };
    let mut parts = Vec::new();
    for component in parent.components() {
        let piece = component.as_os_str().to_string_lossy();
        if !piece.is_empty() && piece != "." {
            parts.push(piece.into_owned());
        }
    }
    parts.join("/")
}

fn cleanup_exported_staging(output_dir: &Path, files: &[PathBuf]) {
    for file in files {
        let _ = std::fs::remove_file(file);
        let mut cursor = file.parent();
        while let Some(dir) = cursor {
            if dir == output_dir {
                break;
            }
            if std::fs::remove_dir(dir).is_err() {
                break;
            }
            cursor = dir.parent();
        }
    }
}

fn build_string_array<'local>(
    env: &mut JNIEnv<'local>,
    items: &[String],
) -> jni::errors::Result<JObjectArray<'local>> {
    let string_cls = env.find_class("java/lang/String")?;
    let empty = env.new_string("")?;
    let arr = env.new_object_array(items.len() as i32, &string_cls, &empty)?;
    for (idx, item) in items.iter().enumerate() {
        let js = env.new_string(item)?;
        env.set_object_array_element(&arr, idx as i32, &js)?;
    }
    Ok(arr)
}

fn with_storage_class<T, F>(op: F) -> jni::errors::Result<T>
where
    F: for<'local> FnOnce(
        &mut JNIEnv<'local>,
        &JObject<'local>,
        &JClass<'local>,
    ) -> jni::errors::Result<T>,
{
    let android_ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(android_ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    let context = ManuallyDrop::new(unsafe { JObject::from_raw(android_ctx.context().cast()) });

    let class_loader = env
        .call_method(&*context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;
    let cls_name = env.new_string("com.beamdrop.app.BeamDropStorage")?;
    let cls_obj = env
        .call_method(
            &class_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&cls_name)],
        )?
        .l()?;
    let storage_cls = JClass::from(cls_obj);

    let result = op(&mut env, &context, &storage_cls);
    if result.is_err() {
        clear_jni_exception(&mut env);
    }
    result
}

fn clear_jni_exception(env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
}
