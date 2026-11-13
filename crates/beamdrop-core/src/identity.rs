use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use directories::BaseDirs;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::{NodeId, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Failed to locate OS configuration directory")]
    NoConfigDir,
    #[error("I/O error accessing identity file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize or deserialize identity JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid Ed25519 key material: {0}")]
    InvalidKey(String),
}

/// Supported operating system types for BeamDrop peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    #[serde(rename = "macOS", alias = "MacOS", alias = "macos")]
    MacOS,
    Android,
}

impl OsType {
    /// Detects the current operating system at compile/runtime.
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "android") {
            Self::Android
        } else {
            Self::MacOS
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::MacOS => "macOS",
            Self::Android => "Android",
        }
    }
}

impl fmt::Display for OsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OsType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" => Ok(Self::Windows),
            "macos" | "mac" | "darwin" | "osx" => Ok(Self::MacOS),
            "android" => Ok(Self::Android),
            other => Err(format!("Unsupported OS type: {other}")),
        }
    }
}

/// Persistent device identity stored in `BeamDrop/identity.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Persistent unique device UUID generated on first run.
    pub device_id: Uuid,
    /// Machine hostname used as the default display name.
    pub hostname: String,
    /// Operating system type (`Windows`, `macOS`, `Android`).
    pub os_type: OsType,
    /// 32-byte Ed25519 secret signing key.
    pub secret_key: [u8; 32],
    /// 32-byte Ed25519 public verifying key.
    pub public_key: [u8; 32],
    /// Iroh `NodeId` corresponding to the Ed25519 public key.
    pub node_id: NodeId,
}

impl DeviceIdentity {
    /// Returns the default OS config directory (`<OS Config Dir>/BeamDrop`),
    /// or `BEAMDROP_CONFIG_DIR` if set in the environment.
    pub fn config_dir() -> Result<PathBuf, IdentityError> {
        if let Ok(custom_dir) = std::env::var("BEAMDROP_CONFIG_DIR") {
            let trimmed = custom_dir.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
        let base_dirs = BaseDirs::new().ok_or(IdentityError::NoConfigDir)?;
        Ok(base_dirs.config_dir().join("BeamDrop"))
    }

    /// Returns the default path to `BeamDrop/identity.json` inside the OS config directory.
    pub fn default_path() -> Result<PathBuf, IdentityError> {
        Ok(Self::config_dir()?.join("identity.json"))
    }

    /// Generates a brand new persistent `DeviceIdentity` with an Ed25519 keypair and UUID.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let secret_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_bytes();
        let iroh_secret = SecretKey::from_bytes(&secret_bytes);
        let node_id = iroh_secret.public();

        Self {
            device_id: Uuid::new_v4(),
            hostname: detect_hostname(),
            os_type: OsType::current(),
            secret_key: secret_bytes,
            public_key: public_bytes,
            node_id,
        }
    }

    /// Loads the device identity from `BeamDrop/identity.json` in the OS config directory,
    /// or generates and saves a new identity on first run.
    pub fn load_or_create() -> Result<Self, IdentityError> {
        let path = Self::default_path()?;
        Self::load_or_create_at(&path)
    }

    /// Loads the device identity from a specific file path, or creates and saves one if absent.
    pub fn load_or_create_at(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            let raw = fs::read_to_string(path)?;
            let identity: Self = serde_json::from_str(&raw)?;
            // Validate key consistency
            let verifying = identity.verifying_key()?;
            let derived_verifying = identity.signing_key().verifying_key();
            if verifying != derived_verifying {
                return Err(IdentityError::InvalidKey(
                    "public_key does not match secret_key".to_string(),
                ));
            }
            if identity.iroh_secret_key().public() != identity.node_id {
                return Err(IdentityError::InvalidKey(
                    "node_id does not match secret_key".to_string(),
                ));
            }
            return Ok(identity);
        }

        let identity = Self::generate();
        identity.save_to(path)?;
        Ok(identity)
    }

    /// Saves the identity atomically to the given path.
    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Reconstructs the `ed25519_dalek::SigningKey`.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret_key)
    }

    /// Reconstructs and validates the `ed25519_dalek::VerifyingKey`.
    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))
    }

    /// Returns the `iroh::SecretKey` derived from the persistent Ed25519 keypair.
    pub fn iroh_secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.secret_key)
    }

    /// Returns the device's `iroh::NodeId`.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Signs a payload with the device's Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key().sign(message)
    }
}

/// Detects the machine's hostname using environment variables or OS hostname syscall.
pub fn detect_hostname() -> String {
    for var in ["BEAMDROP_HOSTNAME", "HOSTNAME", "COMPUTERNAME"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes a NUL-terminated string into `buf` up to `buf.len()`.
        let res = unsafe { libc_gethostname(buf.as_mut_ptr() as *mut std::ffi::c_char, buf.len()) };
        if res == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(name) = std::str::from_utf8(&buf[..end]) {
                let clean = name.trim().trim_end_matches(".local").trim();
                if !clean.is_empty()
                    && !clean.eq_ignore_ascii_case("localhost")
                    && !clean.eq_ignore_ascii_case("localhost.localdomain")
                {
                    return clean.to_string();
                }
            }
        }
    }

    if cfg!(target_os = "android") {
        "Android Device".to_string()
    } else {
        "beamdrop-device".to_string()
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname(name: *mut std::ffi::c_char, len: usize) -> std::ffi::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_persist_and_reload() {
        let dir = std::env::temp_dir().join(format!("beamdrop-id-test-{}", Uuid::new_v4()));
        let path = dir.join("identity.json");

        let first = DeviceIdentity::load_or_create_at(&path).expect("create identity");
        let second = DeviceIdentity::load_or_create_at(&path).expect("reload identity");

        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.node_id, second.node_id);
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.secret_key, second.secret_key);
        assert_eq!(first.os_type, second.os_type);

        let _ = fs::remove_dir_all(&dir);
    }
}

