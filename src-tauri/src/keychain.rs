//! OS credential storage: device keypairs + a separate local DB key.
//!
//! Primary store: the OS keychain (Windows Credential Manager via DPAPI, macOS
//! Keychain). A raw file fallback exists only for tests or explicit development
//! opt-in via `FWOOSH_ALLOW_FILE_KEY_FALLBACK=1`.
//!
//! Security note: OS keychain storage protects against other *users* reading
//! secrets, but not against malware running as the same logged-in user. The
//! file fallback is weaker and must not be used for normal app runs. This is
//! the standard limitation of credential storage; see the threat model.

use crate::crypto::DeviceKeypairs;
use keyring::Entry;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Service name under which Fwoosh stores its secrets.
const SERVICE: &str = "fwoosh";

/// Sub-entries stored under the service.
const ENTRY_CORE_SECRETS: &str = "core-secrets-v1";
const ENTRY_DEVICE_KEYS: &str = "device-keypairs";
const ENTRY_DB_KEY: &str = "history-db-key";
const CORE_SECRETS_MAGIC: &[u8] = b"fwoosh-core-v1\0";

#[derive(Debug)]
pub enum KeychainError {
    /// No secret found for this entry (first run / not yet created).
    NotFound,
    /// The OS credential store rejected the operation.
    Backend(String),
    /// Stored bytes were malformed (truncated / wrong length).
    Corrupt(&'static str),
    Io(std::io::Error),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no secret found in keychain"),
            Self::Backend(m) => write!(f, "keychain backend error: {m}"),
            Self::Corrupt(m) => write!(f, "corrupt keychain entry: {m}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for KeychainError {}
impl From<std::io::Error> for KeychainError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Set the directory for the file fallback. Set once at startup from lib.rs.
static FALLBACK_DIR: OnceLock<PathBuf> = OnceLock::new();
static KEYRING_INIT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn set_fallback_dir(dir: PathBuf) {
    let _ = std::fs::create_dir_all(&dir);
    let _ = FALLBACK_DIR.set(dir);
}

fn init_platform_store() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new().map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new().map_err(|e| e.to_string())?;
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    let store = zbus_secret_service_keyring_store::Store::new().map_err(|e| e.to_string())?;

    #[cfg(all(any(unix, windows), not(any(target_os = "ios", target_os = "android"))))]
    keyring_core::set_default_store(store);

    Ok(())
}

fn ensure_platform_store() -> Result<(), KeychainError> {
    KEYRING_INIT
        .get_or_init(init_platform_store)
        .as_ref()
        .map(|_| ())
        .map_err(|e| KeychainError::Backend(e.clone()))
}

fn fallback_path(name: &str) -> PathBuf {
    FALLBACK_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::temp_dir())
        .join(format!("{name}.bin"))
}

fn fallback_enabled() -> bool {
    cfg!(test) || std::env::var_os("FWOOSH_ALLOW_FILE_KEY_FALLBACK").is_some()
}

fn prefer_file_fallback() -> bool {
    cfg!(test) && FALLBACK_DIR.get().is_some()
}

/// Read a secret: try the OS keychain first, fall back to the file.
fn get_secret(name: &str) -> Result<Vec<u8>, KeychainError> {
    if prefer_file_fallback() {
        return fallback_read(name);
    }
    if let Err(e) = ensure_platform_store() {
        if fallback_enabled() {
            eprintln!("keychain unavailable for {name}, using file fallback: {e}");
            return fallback_read(name);
        }
        return Err(e);
    }

    match Entry::new(SERVICE, name) {
        Ok(entry) => match entry.get_secret() {
            Ok(blob) => Ok(blob),
            Err(keyring::Error::NoEntry) => fallback_read(name),
            Err(e) => {
                // Keychain read failures fail closed unless the development
                // file fallback is explicitly enabled.
                if fallback_enabled() {
                    eprintln!("keychain read for {name} failed, trying fallback: {e}");
                    fallback_read(name)
                } else {
                    Err(KeychainError::Backend(e.to_string()))
                }
            }
        },
        Err(e) => {
            if fallback_enabled() {
                eprintln!("keychain unavailable for {name}, using file fallback: {e}");
                fallback_read(name)
            } else {
                Err(KeychainError::Backend(e.to_string()))
            }
        }
    }
}

/// Write a secret: try the OS keychain first, fall back to the file.
fn set_secret(name: &str, blob: &[u8]) -> Result<(), KeychainError> {
    if prefer_file_fallback() {
        return fallback_write(name, blob);
    }
    if let Err(e) = ensure_platform_store() {
        if fallback_enabled() {
            eprintln!("keychain unavailable for {name}, using file fallback: {e}");
            return fallback_write(name, blob);
        }
        return Err(e);
    }

    match Entry::new(SERVICE, name) {
        Ok(entry) => match entry.set_secret(blob) {
            Ok(()) => Ok(()),
            Err(e) => {
                if fallback_enabled() {
                    eprintln!("keychain write for {name} failed, using fallback: {e}");
                    fallback_write(name, blob)
                } else {
                    Err(KeychainError::Backend(e.to_string()))
                }
            }
        },
        Err(e) => {
            if fallback_enabled() {
                eprintln!("keychain unavailable for {name}, using file fallback: {e}");
                fallback_write(name, blob)
            } else {
                Err(KeychainError::Backend(e.to_string()))
            }
        }
    }
}

fn fallback_read(name: &str) -> Result<Vec<u8>, KeychainError> {
    if !fallback_enabled() {
        return Err(KeychainError::NotFound);
    }
    let path = fallback_path(name);
    match std::fs::read(&path) {
        Ok(blob) => Ok(blob),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeychainError::NotFound),
        Err(e) => Err(KeychainError::Io(e)),
    }
}

fn fallback_write(name: &str, blob: &[u8]) -> Result<(), KeychainError> {
    if !fallback_enabled() {
        return Err(KeychainError::Backend(
            "file key fallback is disabled; use the OS keychain".to_string(),
        ));
    }
    let path = fallback_path(name);
    std::fs::write(&path, blob)?;
    Ok(())
}

// ---------------------------------------------------------------------------
//  Combined app secrets
// ---------------------------------------------------------------------------

fn encode_device_keypairs(kp: &DeviceKeypairs) -> Vec<u8> {
    let (ed, x25519) = kp.to_bytes();
    let mut blob = Vec::with_capacity(64);
    blob.extend_from_slice(&ed);
    blob.extend_from_slice(&x25519);
    blob
}

fn decode_device_keypairs(blob: &[u8]) -> Result<DeviceKeypairs, KeychainError> {
    if blob.len() != 64 {
        return Err(KeychainError::Corrupt("expected 64 bytes (ed||x25519)"));
    }
    let mut ed = [0u8; 32];
    let mut x25519 = [0u8; 32];
    ed.copy_from_slice(&blob[..32]);
    x25519.copy_from_slice(&blob[32..]);
    Ok(DeviceKeypairs::from_bytes(ed, x25519))
}

fn decode_db_key(blob: &[u8]) -> Result<[u8; 32], KeychainError> {
    if blob.len() != 32 {
        return Err(KeychainError::Corrupt("db key must be 32 bytes"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(blob);
    Ok(k)
}

fn generate_db_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut k);
    k
}

fn encode_core_secrets(kp: &DeviceKeypairs, db_key: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(CORE_SECRETS_MAGIC.len() + 96);
    blob.extend_from_slice(CORE_SECRETS_MAGIC);
    blob.extend_from_slice(&encode_device_keypairs(kp));
    blob.extend_from_slice(db_key);
    blob
}

fn decode_core_secrets(blob: &[u8]) -> Result<(DeviceKeypairs, [u8; 32]), KeychainError> {
    if !blob.starts_with(CORE_SECRETS_MAGIC) {
        return Err(KeychainError::Corrupt("unknown core secrets format"));
    }
    let payload = &blob[CORE_SECRETS_MAGIC.len()..];
    if payload.len() != 96 {
        return Err(KeychainError::Corrupt("expected 96 bytes of core secrets"));
    }
    let device = decode_device_keypairs(&payload[..64])?;
    let db_key = decode_db_key(&payload[64..])?;
    Ok((device, db_key))
}

fn load_core_secrets() -> Result<(DeviceKeypairs, [u8; 32]), KeychainError> {
    let blob = get_secret(ENTRY_CORE_SECRETS)?;
    decode_core_secrets(&blob)
}

fn save_core_secrets(kp: &DeviceKeypairs, db_key: &[u8; 32]) -> Result<(), KeychainError> {
    set_secret(ENTRY_CORE_SECRETS, &encode_core_secrets(kp, db_key))
}

/// Load both app secrets through one keychain item. Older builds stored the
/// device keys and history DB key separately; migrate them into the combined
/// item the first time this newer code runs.
pub fn load_or_create_core_secrets() -> Result<(DeviceKeypairs, [u8; 32]), KeychainError> {
    match load_core_secrets() {
        Ok(secrets) => Ok(secrets),
        Err(KeychainError::NotFound) => {
            let device = match load_device_keypairs() {
                Ok(kp) => kp,
                Err(KeychainError::NotFound) => DeviceKeypairs::generate(),
                Err(e) => return Err(e),
            };
            let db_key = match load_db_key() {
                Ok(k) => k,
                Err(KeychainError::NotFound) => generate_db_key(),
                Err(e) => return Err(e),
            };
            save_core_secrets(&device, &db_key)?;
            Ok((device, db_key))
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
//  Device keypairs
// ---------------------------------------------------------------------------

/// Persist a device's keypairs. Stores 64 bytes: `ed25519_secret(32) ||
/// x25519_secret(32)`.
pub fn save_device_keypairs(kp: &DeviceKeypairs) -> Result<(), KeychainError> {
    set_secret(ENTRY_DEVICE_KEYS, &encode_device_keypairs(kp))
}

/// Load the device keypairs, or generate + persist new ones on first run.
pub fn load_or_create_device_keypairs() -> Result<DeviceKeypairs, KeychainError> {
    match load_device_keypairs() {
        Ok(kp) => Ok(kp),
        Err(KeychainError::NotFound) => {
            let kp = DeviceKeypairs::generate();
            save_device_keypairs(&kp)?;
            Ok(kp)
        }
        Err(e) => Err(e),
    }
}

/// Load existing keypairs (returns NotFound if absent).
pub fn load_device_keypairs() -> Result<DeviceKeypairs, KeychainError> {
    let blob = get_secret(ENTRY_DEVICE_KEYS)?;
    decode_device_keypairs(&blob)
}

// ---------------------------------------------------------------------------
//  Local history DB key  (SEPARATE from device keys — see threat model)
// ---------------------------------------------------------------------------

/// Persist a fresh 256-bit key used to encrypt the local history store. This
/// key is distinct from the device keypairs so that leaking the group/device
/// secrets does not by itself expose stored history.
pub fn save_db_key(key: &[u8; 32]) -> Result<(), KeychainError> {
    set_secret(ENTRY_DB_KEY, key)
}

/// Load the history DB key, or generate + persist a fresh one on first run.
pub fn load_or_create_db_key() -> Result<[u8; 32], KeychainError> {
    match load_db_key() {
        Ok(k) => Ok(k),
        Err(KeychainError::NotFound) => {
            let k = generate_db_key();
            save_db_key(&k)?;
            Ok(k)
        }
        Err(e) => Err(e),
    }
}

/// Load the existing history DB key (returns NotFound if absent).
pub fn load_db_key() -> Result<[u8; 32], KeychainError> {
    let blob = get_secret(ENTRY_DB_KEY)?;
    decode_db_key(&blob)
}

/// Delete all Fwoosh secrets (used by "leave room" / factory reset).
pub fn delete_all() -> Result<(), KeychainError> {
    for user in [ENTRY_CORE_SECRETS, ENTRY_DEVICE_KEYS, ENTRY_DB_KEY] {
        if let Ok(entry) = Entry::new(SERVICE, user) {
            let _ = entry.delete_credential();
        }
        let _ = std::fs::remove_file(fallback_path(user));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_key_roundtrips_via_fallback() {
        // Use the fallback file path explicitly (no reliance on OS keychain in
        // the test environment). This verifies the (de)serialization path.
        let dir = std::env::temp_dir().join("fwoosh-keychain-test");
        let _ = std::fs::create_dir_all(&dir);
        set_fallback_dir(dir.clone());

        let kp = DeviceKeypairs::generate();
        save_device_keypairs(&kp).unwrap();
        let key = [7u8; 32];
        save_db_key(&key).unwrap();
        let got = load_db_key().unwrap();
        assert_eq!(got, key);
        let (migrated_kp, migrated_key) = load_or_create_core_secrets().unwrap();
        assert_eq!(migrated_kp.signing_pub, kp.signing_pub);
        assert_eq!(migrated_key, key);
        let _ = delete_all();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
