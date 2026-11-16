use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use beamdrop_core::TrustedPeer;
use serde::Serialize;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SHORTCUT_PREFIX: &str = "ZapDrop (";
const LEGACY_SHORTCUT_PREFIX: &str = "BeamDrop (";
const SHORTCUT_SUFFIX: &str = ").lnk";

#[derive(Serialize)]
struct SendToShortcutSpec {
    lnk: String,
    target: String,
    args: String,
    workdir: String,
}

/// Synchronizes Windows Explorer "Send to" `.lnk` shortcuts for all paired peers,
/// creating `BeamDrop (<friendly_alias>).lnk` with `--send-to <node_id>` and deleting stale entries.
pub fn sync_sendto_shortcuts(peers: &[TrustedPeer]) {
    let Some(sendto_dir) = resolve_sendto_dir() else {
        return;
    };
    if let Err(err) = fs::create_dir_all(&sendto_dir) {
        tracing::warn!(%err, dir = %sendto_dir.display(), "Failed to prepare Windows SendTo directory");
        return;
    }

    let Ok(exe_path) = std::env::current_exe() else {
        tracing::warn!("Failed to resolve current executable path for Windows SendTo shortcuts");
        return;
    };
    let target_str = exe_path.to_string_lossy().into_owned();
    let workdir_str = exe_path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let desired = build_shortcut_specs(&sendto_dir, &target_str, &workdir_str, peers);
    let desired_names: HashSet<String> = desired
        .iter()
        .filter_map(|spec| {
            Path::new(&spec.lnk)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_ascii_lowercase())
        })
        .collect();

    remove_stale_shortcuts(&sendto_dir, &desired_names);

    if desired.is_empty() {
        return;
    }

    if let Err(err) = write_shortcuts_powershell(&desired) {
        tracing::warn!(%err, "Failed to update Windows SendTo shortcuts");
    }
}

fn resolve_sendto_dir() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    if appdata.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("SendTo"),
    )
}

fn build_shortcut_specs(
    sendto_dir: &Path,
    target_exe: &str,
    workdir: &str,
    peers: &[TrustedPeer],
) -> Vec<SendToShortcutSpec> {
    let mut alias_counts: HashMap<String, usize> = HashMap::new();
    for peer in peers {
        let base = sanitize_shortcut_alias(&peer.friendly_alias);
        *alias_counts.entry(base.to_ascii_lowercase()).or_insert(0) += 1;
    }

    let mut used_names = HashSet::new();
    let mut specs = Vec::with_capacity(peers.len());

    for peer in peers {
        let base_alias = sanitize_shortcut_alias(&peer.friendly_alias);
        let duplicate_alias = alias_counts
            .get(&base_alias.to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
            > 1;

        let mut display_label = if duplicate_alias {
            let id_str = peer.node_id.to_string();
            let short_id = &id_str[..id_str.len().min(6)];
            format!("{base_alias} [{short_id}]")
        } else {
            base_alias
        };

        let mut file_name = format!("{SHORTCUT_PREFIX}{display_label}{SHORTCUT_SUFFIX}");
        if !used_names.insert(file_name.to_ascii_lowercase()) {
            let id_str = peer.node_id.to_string();
            let short_id = &id_str[..id_str.len().min(8)];
            display_label = format!("{display_label} [{short_id}]");
            file_name = format!("{SHORTCUT_PREFIX}{display_label}{SHORTCUT_SUFFIX}");
            used_names.insert(file_name.to_ascii_lowercase());
        }

        let lnk_path = sendto_dir.join(file_name);
        specs.push(SendToShortcutSpec {
            lnk: lnk_path.to_string_lossy().into_owned(),
            target: target_exe.to_string(),
            args: format!("--send-to {}", peer.node_id),
            workdir: workdir.to_string(),
        });
    }

    specs
}

fn sanitize_shortcut_alias(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c < ' ' => ' ',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        "Peer".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

fn remove_stale_shortcuts(sendto_dir: &Path, desired_names_lower: &HashSet<String>) {
    let Ok(entries) = fs::read_dir(sendto_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let lower = name_str.to_ascii_lowercase();
        let is_zapdrop_lnk = (lower.starts_with(&SHORTCUT_PREFIX.to_ascii_lowercase())
            || lower.starts_with(&LEGACY_SHORTCUT_PREFIX.to_ascii_lowercase()))
            && lower.ends_with(&SHORTCUT_SUFFIX.to_ascii_lowercase());
        if is_zapdrop_lnk && !desired_names_lower.contains(&lower) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn write_shortcuts_powershell(specs: &[SendToShortcutSpec]) -> Result<(), String> {
    let payload = serde_json::to_string(specs)
        .map_err(|e| format!("Failed to encode SendTo specs JSON: {e}"))?;

    let script = r#"
$raw = $env:BEAMDROP_SENDTO_SPECS
if (-not $raw) { exit 0 }
$items = ConvertFrom-Json -InputObject $raw
if ($items -isnot [System.Array]) { $items = @($items) }
$shell = New-Object -ComObject WScript.Shell
foreach ($item in $items) {
    $shortcut = $shell.CreateShortcut($item.lnk)
    $shortcut.TargetPath = $item.target
    $shortcut.Arguments = $item.args
    if ($item.workdir) { $shortcut.WorkingDirectory = $item.workdir }
    $shortcut.IconLocation = "$($item.target),0"
    $shortcut.Description = "Send via ZapDrop"
    $shortcut.Save()
}
"#;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            script,
        ])
        .env("BEAMDROP_SENDTO_SPECS", payload)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to invoke powershell for SendTo shortcuts: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("PowerShell exited with {}: {stderr}", output.status));
    }

    Ok(())
}

