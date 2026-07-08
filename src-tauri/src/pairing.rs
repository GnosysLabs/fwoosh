//! Pairing: encode/decode the join URI + proof-of-knowledge.
//!
//! Flow (frozen spec):
//! 1. Admin (room creator) generates a one-time secret `s` (32 random bytes)
//!    and encodes a pairing URI:
//!      `fwoosh://pair?t=<topic>&pub=<base64url admin-ed25519>&s=<base64url s>`
//!    rendered as a QR code (in-app only; never logged). Short-lived + single-use.
//! 2. Joining device scans/pastes the URI, learns (topic, admin_pub, s).
//! 3. Joining device derives an HMAC key from `s` and produces a proof MAC over
//!    its own (ed25519_pub, x25519_pub, label, nonce). It sends this proof +
//!    its identity to the admin.
//! 4. Admin verifies the proof (knows s -> can recompute the MAC). Only after a
//!    valid proof does it add the device to the roster via a new signed epoch.
//!
//! This stops topic-only eavesdroppers from injecting bogus pubkeys: without
//! `s`, they can't forge the proof.
//!
//! SECURITY: the secret `s` is the entire bootstrap secret. It MUST NOT be
//! logged, sent over an insecure channel, or persisted. Functions here never
//! log it.

use crate::crypto::Ed25519PubKey;
use crate::roster::DeviceIdentity;
use base64::Engine;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The pairing scheme prefix.
const SCHEME: &str = "fwoosh://pair";

#[derive(Debug)]
pub enum PairingError {
    /// URI doesn't start with the expected scheme.
    BadScheme,
    /// Missing or duplicate query parameters.
    BadParams(&'static str),
    /// Base64 decoding failed.
    BadEncoding,
    /// Proof MAC did not verify.
    InvalidProof,
    /// Public key bytes were the wrong length.
    BadKeyLength,
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadScheme => write!(f, "not a fwoosh pairing URI"),
            Self::BadParams(m) => write!(f, "bad pairing params: {m}"),
            Self::BadEncoding => write!(f, "base64 decoding failed"),
            Self::InvalidProof => write!(f, "proof-of-knowledge verification failed"),
            Self::BadKeyLength => write!(f, "public key has wrong length"),
        }
    }
}
impl std::error::Error for PairingError {}

/// A decoded pairing invitation (held by the joining device).
#[derive(Clone)]
pub struct PairingInvite {
    pub topic: String,
    pub admin_pub: Ed25519PubKey,
    /// One-time secret. NEVER log or persist this.
    pub secret: [u8; 32],
}

/// A device's join request: identity + proof MAC. Sent to the admin.
#[derive(Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub identity: DeviceIdentity,
    pub nonce: [u8; 16],
    /// HMAC-SHA256(HKDF(secret), identity || nonce).
    pub proof: [u8; 32],
}

// ---------------------------------------------------------------------------
//  URI encode / decode
// ---------------------------------------------------------------------------

/// Build a pairing URI from the invite components. The caller generates the
/// random `topic` and `secret` (see `roster::new_topic` + `random_secret`).
///
/// NOTE: the returned string contains the full bootstrap secret. Handle with
/// care — render to a QR in-app and do not log it.
pub fn build_uri(topic: &str, admin_pub: &Ed25519PubKey, secret: &[u8; 32]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{SCHEME}?t={}&pub={}&s={}",
        urlenc(topic),
        b64.encode(admin_pub.0),
        b64.encode(secret),
    )
}

/// Parse a pairing URI into an invite. Does NOT log the secret.
pub fn parse_uri(uri: &str) -> Result<PairingInvite, PairingError> {
    let rest = uri.strip_prefix(SCHEME).ok_or(PairingError::BadScheme)?;
    let rest = rest.strip_prefix('?').ok_or(PairingError::BadParams("missing query"))?;

    let mut topic = None;
    let mut pub_b64 = None;
    let mut sec_b64 = None;
    for pair in rest.split('&') {
        let (k, v) = pair.split_once('=').ok_or(PairingError::BadParams("malformed pair"))?;
        match k {
            "t" => topic = Some(urldec(v)),
            "pub" => pub_b64 = Some(v),
            "s" => sec_b64 = Some(v),
            _ => {} // ignore unknown params (forward compat)
        }
    }
    let topic = topic.ok_or(PairingError::BadParams("missing t"))?;
    let pub_b64 = pub_b64.ok_or(PairingError::BadParams("missing pub"))?;
    let sec_b64 = sec_b64.ok_or(PairingError::BadParams("missing s"))?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut pub_bytes = [0u8; 32];
    let pub_vec = b64.decode(pub_b64).map_err(|_| PairingError::BadEncoding)?;
    if pub_vec.len() != 32 {
        return Err(PairingError::BadKeyLength);
    }
    pub_bytes.copy_from_slice(&pub_vec);

    let mut secret = [0u8; 32];
    let sec_vec = b64.decode(sec_b64).map_err(|_| PairingError::BadEncoding)?;
    if sec_vec.len() != 32 {
        return Err(PairingError::BadKeyLength);
    }
    secret.copy_from_slice(&sec_vec);

    Ok(PairingInvite {
        topic,
        admin_pub: Ed25519PubKey(pub_bytes),
        secret,
    })
}

/// Generate a fresh 32-byte one-time pairing secret.
pub fn random_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut s);
    s
}

// ---------------------------------------------------------------------------
//  Proof-of-knowledge: joining device proves it knows `secret` without
//  revealing it. We HKDF the secret to a MAC key, then HMAC the identity.
// ---------------------------------------------------------------------------

/// Derive the HMAC key from the one-time secret (HKDF-SHA256, fixed info/salt).
/// This binds the MAC to Fwoosh pairing so the secret can't be reused
/// against some other protocol's expectation.
fn mac_key(secret: &[u8; 32]) -> [u8; 32] {
    // Simple, deterministic HKDF-like extract+expand using SHA-256. We use a
    // fixed salt + info to derive a 32-byte MAC key from the pairing secret.
    // (hkdf crate isn't a direct dep; this is equivalent and avoids adding it.)
    let salt = b"Fwoosh pairing v1\0salt";
    let info = b"Fwoosh pairing v1\0mac-key";

    // Extract: prk = HMAC(salt, secret)
    let mut prk_mac = <HmacSha256 as KeyInit>::new_from_slice(salt).expect("hmac key");
    prk_mac.update(secret);
    let prk = prk_mac.finalize().into_bytes();

    // Expand: okm = HMAC(prk, info)
    let mut okm_mac = <HmacSha256 as KeyInit>::new_from_slice(&prk).expect("hmac key");
    okm_mac.update(info);
    let okm = okm_mac.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// Material that the joining device MACs: its identity + nonce.
fn proof_input(identity: &DeviceIdentity, nonce: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 32 + nonce.len() + identity.label.len());
    buf.extend_from_slice(&identity.signing_pub.0);
    buf.extend_from_slice(&identity.x25519_pub.0);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(identity.label.as_bytes());
    buf
}

/// The joining device builds its join request: identity + nonce + proof.
pub fn build_join_request(identity: DeviceIdentity, secret: &[u8; 32]) -> JoinRequest {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let key = mac_key(secret);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).expect("hmac key");
    mac.update(&proof_input(&identity, &nonce));
    let tag = mac.finalize().into_bytes();
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&tag);
    JoinRequest { identity, nonce, proof }
}

/// The admin verifies a join request against the one-time secret it generated.
/// Returns Ok(()) only if the proof MAC is valid.
pub fn verify_join_request(req: &JoinRequest, secret: &[u8; 32]) -> Result<(), PairingError> {
    let key = mac_key(secret);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).expect("hmac key");
    mac.update(&proof_input(&req.identity, &req.nonce));
    mac.verify_slice(&req.proof).map_err(|_| PairingError::InvalidProof)
}

// ---------------------------------------------------------------------------
//  Minimal URL percent-encoding for the topic (it's random base64url-ish but
//  may contain characters we want to be safe in a query value).
// ---------------------------------------------------------------------------

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn urldec(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DeviceKeypairs;
    use crate::roster;

    #[test]
    fn uri_roundtrips() {
        let admin = DeviceKeypairs::generate();
        let topic = roster::new_topic();
        let secret = random_secret();
        let uri = build_uri(&topic, &admin.signing_pub, &secret);
        let invite = parse_uri(&uri).unwrap();
        assert_eq!(invite.topic, topic);
        assert_eq!(invite.admin_pub, admin.signing_pub);
        assert_eq!(invite.secret, secret);
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(parse_uri("https://example.com/pair?t=x&pub=y&s=z").is_err());
        assert!(parse_uri("fwoosh://join?t=x").is_err());
    }

    #[test]
    fn rejects_missing_param() {
        let uri = "fwoosh://pair?t=foo&pub=AAAA";
        assert!(parse_uri(uri).is_err());
    }

    #[test]
    fn proof_roundtrip_succeeds() {
        let joining = DeviceKeypairs::generate();
        let identity = DeviceIdentity::from_keypairs(&joining, "phone");
        let secret = random_secret();
        let req = build_join_request(identity.clone(), &secret);
        assert!(verify_join_request(&req, &secret).is_ok());
    }

    #[test]
    fn proof_rejects_wrong_secret() {
        let joining = DeviceKeypairs::generate();
        let identity = DeviceIdentity::from_keypairs(&joining, "phone");
        let secret = random_secret();
        let wrong = random_secret();
        let req = build_join_request(identity, &secret);
        assert!(matches!(
            verify_join_request(&req, &wrong),
            Err(PairingError::InvalidProof)
        ));
    }

    #[test]
    fn proof_rejects_tampered_identity() {
        let joining = DeviceKeypairs::generate();
        let identity = DeviceIdentity::from_keypairs(&joining, "phone");
        let secret = random_secret();
        let mut req = build_join_request(identity, &secret);
        // Tamper with the label after the proof was computed.
        req.identity.label = "tablet".to_string();
        assert!(matches!(
            verify_join_request(&req, &secret),
            Err(PairingError::InvalidProof)
        ));
    }

    #[test]
    fn proof_rejects_tampered_proof_tag() {
        let joining = DeviceKeypairs::generate();
        let identity = DeviceIdentity::from_keypairs(&joining, "phone");
        let secret = random_secret();
        let mut req = build_join_request(identity, &secret);
        req.proof[0] ^= 0xff; // flip bits
        assert!(matches!(
            verify_join_request(&req, &secret),
            Err(PairingError::InvalidProof)
        ));
    }

    #[test]
    fn topic_with_special_chars_roundtrips() {
        let admin = DeviceKeypairs::generate();
        let topic = "a+b c/d%e".to_string();
        let secret = random_secret();
        let uri = build_uri(&topic, &admin.signing_pub, &secret);
        let invite = parse_uri(&uri).unwrap();
        assert_eq!(invite.topic, topic);
    }
}
