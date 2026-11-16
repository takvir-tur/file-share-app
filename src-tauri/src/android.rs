use std::fs::OpenOptions;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use jni::objects::{JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::jstring;
use jni::JNIEnv;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::{self, AppState, TargetedSendRequest};

#[derive(Debug, Clone)]
pub struct AndroidDownloadDirs {
    /// Directory where `TransferEngine` writes incoming files and `.beamdrop.part` chunks.
    pub engine_dir: PathBuf,
    /// Public `Download/BeamDrop` folder visible in Samsung My Files / Files app.
    pub public_dir: PathBuf,
    /// `true` when scoped storage forced staging inside app-private storage prior to MediaStore export.
    pub uses_staging: bool,
}

#[derive(Default)]
struct PendingAndroidQueues {
    paths: Vec<String>,
    targeted: Vec<TargetedSendRequest>,
    pairing_uris: Vec<String>,
}

static PENDING_ANDROID_QUEUES: Mutex<PendingAndroidQueues> = Mutex::new(PendingAndroidQueues {
    paths: Vec::new(),
    targeted: Vec::new(),
    pairing_uris: Vec::new(),
});
static ANDROID_APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();
static ANDROID_CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();
static ANDROID_DOWNLOAD_DIRS: OnceLock<AndroidDownloadDirs> = OnceLock::new();

#[derive(Serialize)]
struct TrustedPeerShortcutJson {
    node_id: String,
    friendly_alias: String,
    os_type: String,
}

/// Records the resolved Tauri config directory so background shortcut refreshes can read `trusted_peers.json`.
pub fn set_config_dir(dir: PathBuf) {
    let _ = ANDROID_CONFIG_DIR.set(dir);
}

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
    match PENDING_ANDROID_QUEUES.lock() {
        Ok(mut guard) => std::mem::take(&mut guard.paths),
        Err(_) => Vec::new(),
    }
}

/// Binds the active Tauri `AppHandle` and flushes any shares or pairing URIs queued during cold start.
pub fn bind_app_handle(app: AppHandle) {
    let (leftover_paths, leftover_targeted, leftover_pairing_uris) =
        match PENDING_ANDROID_QUEUES.lock() {
            Ok(mut guard) => {
                let _ = ANDROID_APP_HANDLE.set(app.clone());
                (
                    std::mem::take(&mut guard.paths),
                    std::mem::take(&mut guard.targeted),
                    std::mem::take(&mut guard.pairing_uris),
                )
            }
            Err(_) => {
                let _ = ANDROID_APP_HANDLE.set(app.clone());
                (Vec::new(), Vec::new(), Vec::new())
            }
        };

    let state = app.state::<AppState>();
    if !leftover_paths.is_empty() {
        state.queue_send_paths(leftover_paths.clone());
        let _ = app.emit(commands::EVENT_SEND_PATHS, &leftover_paths);
    }

    for req in leftover_targeted {
        commands::resolve_and_dispatch_targeted_send(app.clone(), state.inner().clone(), req);
    }

    for uri in leftover_pairing_uris {
        state.queue_pairing_uri(uri.clone());
        let _ = app.emit(commands::EVENT_PAIR_URI, &uri);
    }

    // Flip `rustReady = true` on Android and drain Java-side cold-start buffers now that
    // `AppState` and `ANDROID_APP_HANDLE` are initialized.
    if let Err(err) = with_app_class("com.beamdrop.app.BeamDropBridge", |env, _ctx, cls| {
        env.call_static_method(cls, "drainPendingToNative", "()V", &[])?;
        Ok(())
    }) {
        tracing::warn!(%err, "Failed to drain Java cold-start queues to Rust");
    }
}

fn enqueue_shared_paths(paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }

    if let Ok(mut guard) = PENDING_ANDROID_QUEUES.lock() {
        if let Some(app) = ANDROID_APP_HANDLE.get() {
            let state = app.state::<AppState>();
            state.queue_send_paths(paths.clone());
            let _ = app.emit(commands::EVENT_SEND_PATHS, &paths);
        } else {
            guard.paths.extend(paths);
        }
    }
}

fn enqueue_targeted_send(target_node_id: String, paths: Vec<String>) {
    if target_node_id.trim().is_empty() || paths.is_empty() {
        return;
    }

    let request = TargetedSendRequest {
        target_node_id,
        paths,
    };

    let immediate_app = {
        let Ok(mut guard) = PENDING_ANDROID_QUEUES.lock() else {
            return;
        };
        if let Some(app) = ANDROID_APP_HANDLE.get() {
            Some(app.clone())
        } else {
            guard.targeted.push(request);
            return;
        }
    };

    if let Some(app) = immediate_app {
        let state = app.state::<AppState>();
        commands::resolve_and_dispatch_targeted_send(app.clone(), state.inner().clone(), request);
    }
}

fn enqueue_pairing_uri(uri: String) {
    let trimmed = uri.trim().to_string();
    if trimmed.is_empty() {
        return;
    }

    if let Ok(mut guard) = PENDING_ANDROID_QUEUES.lock() {
        if let Some(app) = ANDROID_APP_HANDLE.get() {
            let state = app.state::<AppState>();
            state.queue_pairing_uri(trimmed.clone());
            let _ = app.emit(commands::EVENT_PAIR_URI, &trimmed);
        } else {
            guard.pairing_uris.push(trimmed);
        }
    }
}

/// Resolves Android `content://` / `file://` URIs returned by `@tauri-apps/plugin-dialog`
/// into readable POSIX file paths inside `cacheDir/beamdrop_share/`.
pub fn resolve_content_uris(raw_uris: &[String]) -> Result<Vec<String>, String> {
    if raw_uris.is_empty() {
        return Ok(Vec::new());
    }

    with_app_class("com.beamdrop.app.BeamDropBridge", |env, context, cls| {
        let j_uris = build_string_array(env, raw_uris)?;
        let out_obj = env
            .call_static_method(
                cls,
                "resolveContentUris",
                "(Landroid/content/Context;[Ljava/lang/String;)[Ljava/lang/String;",
                &[JValue::Object(context), JValue::Object(j_uris.as_ref())],
            )?
            .l()?;
        if out_obj.is_null() {
            return Ok(Vec::new());
        }
        let arr = JObjectArray::from(out_obj);
        Ok(collect_string_array(env, &arr))
    })
    .map_err(|err| format!("Failed to resolve Android content URI(s): {err}"))
}

/// Triggers an asynchronous Android Sharing Shortcuts sync via `BeamDropShortcuts.syncShortcuts`.
pub fn sync_direct_share_shortcuts() {
    std::thread::spawn(|| {
        if let Err(err) = with_app_class("com.beamdrop.app.BeamDropShortcuts", |env, context, cls| {
            env.call_static_method(
                cls,
                "syncShortcuts",
                "(Landroid/content/Context;)V",
                &[JValue::Object(context)],
            )?;
            Ok(())
        }) {
            tracing::warn!(%err, "Android Direct Share shortcut sync failed");
        }
    });
}

/// Returns `true` when Android's active network is a metered cellular connection (mobile data).
pub fn is_on_metered_cellular() -> bool {
    with_app_class("com.beamdrop.app.BeamDropBridge", |env, context, cls| {
        let metered = env
            .call_static_method(
                cls,
                "isOnMeteredCellular",
                "(Landroid/content/Context;)Z",
                &[JValue::Object(context)],
            )?
            .z()?;
        Ok(metered)
    })
    .unwrap_or(false)
}

fn collect_string_array<'local>(
    env: &mut JNIEnv<'local>,
    paths: &JObjectArray<'local>,
) -> Vec<String> {
    let Ok(len) = env.get_array_length(paths) else {
        clear_jni_exception(env);
        return Vec::new();
    };

    let mut collected = Vec::with_capacity(len.max(0) as usize);
    for idx in 0..len {
        let Ok(elem) = env.get_object_array_element(paths, idx) else {
            clear_jni_exception(env);
            continue;
        };
        if elem.is_null() {
            continue;
        }
        let jstr = JString::from(elem);
        let text = match env.get_string(&jstr) {
            Ok(java_str) => Some(java_str.to_string_lossy().into_owned()),
            Err(_) => {
                clear_jni_exception(env);
                None
            }
        };
        if let Some(s) = text {
            if !s.is_empty() {
                collected.push(s);
            }
        }
    }
    collected
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeQueueSharedPaths<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    paths: JObjectArray<'local>,
) {
    let collected = collect_string_array(&mut env, &paths);
    enqueue_shared_paths(collected);
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeQueueTargetedSend<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    target_node_id: JString<'local>,
    paths: JObjectArray<'local>,
) {
    let target = match env.get_string(&target_node_id) {
        Ok(s) => s.to_string_lossy().trim().to_string(),
        Err(_) => {
            clear_jni_exception(&mut env);
            return;
        }
    };
    let collected = collect_string_array(&mut env, &paths);
    enqueue_targeted_send(target, collected);
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeQueuePairingUri<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    uri: JString<'local>,
) {
    let value = match env.get_string(&uri) {
        Ok(s) => s.to_string_lossy().trim().to_string(),
        Err(_) => {
            clear_jni_exception(&mut env);
            return;
        }
    };
    enqueue_pairing_uri(value);
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeRespondToOffer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    transfer_id: JString<'local>,
    accept: jni::sys::jboolean,
) {
    let id = match env.get_string(&transfer_id) {
        Ok(s) => s.to_string_lossy().trim().to_string(),
        Err(_) => {
            clear_jni_exception(&mut env);
            return;
        }
    };
    if id.is_empty() {
        return;
    }
    let accepted = accept != 0;
    if let Some(app) = ANDROID_APP_HANDLE.get().cloned() {
        tauri::async_runtime::spawn(async move {
            let state = app.state::<crate::commands::AppState>();
            let _ = crate::commands::process_offer_response(&app, state.inner(), &id, accepted)
                .await;
        });
    }
}

#[no_mangle]
pub extern "system" fn Java_com_beamdrop_app_BeamDropBridge_nativeGetTrustedPeersJson<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let peers = if let Some(trust) = ANDROID_APP_HANDLE.get().and_then(clone_trust_store) {
        tauri::async_runtime::block_on(async move { trust.list_peers().await })
    } else if let Some(dir) = ANDROID_CONFIG_DIR.get() {
        let store_path = dir.join(beamdrop_core::TRUSTED_PEERS_FILENAME);
        beamdrop_core::TrustStore::read_peers_snapshot(store_path).unwrap_or_default()
    } else if let Some(files_dir) = query_android_files_dir(&mut env) {
        let candidates = [
            files_dir.join(beamdrop_core::TRUSTED_PEERS_FILENAME),
            files_dir
                .join("com.beamdrop.app")
                .join(beamdrop_core::TRUSTED_PEERS_FILENAME),
        ];
        candidates
            .into_iter()
            .find(|p| p.exists())
            .and_then(|p| beamdrop_core::TrustStore::read_peers_snapshot(p).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let payload: Vec<TrustedPeerShortcutJson> = peers
        .into_iter()
        .map(|p| TrustedPeerShortcutJson {
            node_id: p.node_id.to_string(),
            friendly_alias: p.friendly_alias,
            os_type: p.os_type.to_string(),
        })
        .collect();

    let json = serde_json::to_string(&payload).unwrap_or_else(|_| "[]".to_string());
    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            clear_jni_exception(&mut env);
            env.new_string("[]")
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

fn clone_trust_store(app: &AppHandle) -> Option<std::sync::Arc<beamdrop_core::TrustStore>> {
    app.state::<AppState>()
        .node
        .try_read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|node| std::sync::Arc::clone(node.trust_store())))
}

fn query_android_files_dir(env: &mut JNIEnv<'_>) -> Option<PathBuf> {
    let activity_thread_cls = env.find_class("android/app/ActivityThread").ok()?;
    let app_obj = env
        .call_static_method(
            activity_thread_cls,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )
        .ok()?
        .l()
        .ok()?;
    if app_obj.is_null() {
        return None;
    }
    let files_dir_obj = env
        .call_method(&app_obj, "getFilesDir", "()Ljava/io/File;", &[])
        .ok()?
        .l()
        .ok()?;
    if files_dir_obj.is_null() {
        return None;
    }
    let abs_obj = env
        .call_method(&files_dir_obj, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .ok()?
        .l()
        .ok()?;
    if abs_obj.is_null() {
        return None;
    }
    let abs_jstr = JString::from(abs_obj);
    let abs = env.get_string(&abs_jstr).ok()?.to_string_lossy().into_owned();
    if abs.is_empty() {
        None
    } else {
        Some(PathBuf::from(abs))
    }
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
    with_app_class("com.beamdrop.app.BeamDropStorage", |env, context, storage_cls| {
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

/// Posts a high-importance heads-up Android notification for an incoming transfer request.
pub fn show_incoming_transfer_notification(
    transfer_id: &str,
    title: &str,
    body: &str,
) -> Result<(), String> {
    with_app_class("com.beamdrop.app.BeamDropBridge", |env, context, bridge_cls| {
        let j_transfer_id = env.new_string(transfer_id)?;
        let j_title = env.new_string(title)?;
        let j_body = env.new_string(body)?;
        env.call_static_method(
            bridge_cls,
            "showIncomingTransferNotification",
            "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(context),
                JValue::Object(&j_transfer_id),
                JValue::Object(&j_title),
                JValue::Object(&j_body),
            ],
        )?;
        Ok(())
    })
    .map_err(|err| format!("Failed to show Android incoming notification: {err}"))
}

/// Dismisses any visible incoming transfer heads-up notification on Android.
pub fn dismiss_incoming_transfer_notification() {
    let _ = with_app_class("com.beamdrop.app.BeamDropBridge", |env, context, bridge_cls| {
        env.call_static_method(
            bridge_cls,
            "dismissIncomingTransferNotification",
            "(Landroid/content/Context;)V",
            &[JValue::Object(context)],
        )?;
        Ok(())
    });
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

    with_app_class("com.beamdrop.app.BeamDropStorage", |env, context, storage_cls| {
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

fn with_app_class<T, F>(class_name: &str, op: F) -> jni::errors::Result<T>
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
    let cls_name = env.new_string(class_name)?;
    let cls_obj = env
        .call_method(
            &class_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&cls_name)],
        )?
        .l()?;
    let app_cls = JClass::from(cls_obj);

    let result = op(&mut env, &context, &app_cls);
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
