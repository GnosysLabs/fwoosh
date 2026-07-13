//! Pairing: durable invitation URIs + proof-of-knowledge.
//!
//! The invitation carries an id, the admin's signing and encryption public
//! keys, and a secret. The secret derives an unguessable rendezvous topic and
//! authenticates the encrypted join request. The admin explicitly approves a
//! valid request before adding the device to the signed roster.
//!
//! This stops topic-only eavesdroppers from injecting bogus pubkeys: without
//! the invitation secret, they can't forge the proof.
//!
//! SECURITY: the secret `s` is the entire bootstrap secret. It MUST NOT be
//! logged or sent over an insecure channel. Admin-created invitations persist
//! it only in the OS keychain; functions here never log it.

use crate::crypto::{Ed25519PubKey, X25519PubKey};
use crate::roster::DeviceIdentity;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    pub invite_id: String,
    pub rendezvous_topic: String,
    pub admin_pub: Ed25519PubKey,
    pub admin_x25519: X25519PubKey,
    /// Invitation secret. NEVER log this. Admin persistence must use keychain.
    pub secret: [u8; 32],
}

/// Reusable join request. The invitation id, timestamp, and requested
/// identity are all covered by the proof MAC.
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkJoinRequest {
    pub invite_id: String,
    pub identity: DeviceIdentity,
    pub nonce: [u8; 16],
    pub requested_at: u64,
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
/// Build a durable device-sync invitation. It deliberately contains no
/// mutable group relay topic; the stable rendezvous topic is derived from
/// the secret by both endpoints.
pub fn build_network_uri(
    invite_id: &str,
    admin_pub: &Ed25519PubKey,
    admin_x25519: &X25519PubKey,
    secret: &[u8; 32],
) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{SCHEME}?v=2&scope=device-sync&i={}&pub={}&x={}&s={}",
        urlenc(invite_id),
        b64.encode(admin_pub.0),
        b64.encode(admin_x25519.0),
        b64.encode(secret),
    )
}

/// Parse a pairing URI into an invite. Does NOT log the secret.
pub fn parse_uri(uri: &str) -> Result<PairingInvite, PairingError> {
    let rest = uri.strip_prefix(SCHEME).ok_or(PairingError::BadScheme)?;
    let rest = rest
        .strip_prefix('?')
        .ok_or(PairingError::BadParams("missing query"))?;

    let mut version = None;
    let mut scope = None;
    let mut invite_id = None;
    let mut pub_b64 = None;
    let mut x_b64 = None;
    let mut sec_b64 = None;
    for pair in rest.split('&') {
        let (k, v) = pair
            .split_once('=')
            .ok_or(PairingError::BadParams("malformed pair"))?;
        match k {
            "v" if version.replace(v).is_some() => {
                return Err(PairingError::BadParams("duplicate v"));
            }
            "scope" if scope.replace(v).is_some() => {
                return Err(PairingError::BadParams("duplicate scope"));
            }
            "i" if invite_id.replace(urldec(v)).is_some() => {
                return Err(PairingError::BadParams("duplicate i"));
            }
            "pub" if pub_b64.replace(v).is_some() => {
                return Err(PairingError::BadParams("duplicate pub"));
            }
            "x" if x_b64.replace(v).is_some() => {
                return Err(PairingError::BadParams("duplicate x"));
            }
            "s" if sec_b64.replace(v).is_some() => {
                return Err(PairingError::BadParams("duplicate s"));
            }
            "v" | "scope" | "i" | "pub" | "x" | "s" => {}
            _ => {} // ignore unknown params (forward compat)
        }
    }
    if version != Some("2") {
        return Err(PairingError::BadParams("unsupported version"));
    }
    if scope != Some("device-sync") {
        return Err(PairingError::BadParams("unsupported scope"));
    }
    let pub_b64 = pub_b64.ok_or(PairingError::BadParams("missing pub"))?;
    let sec_b64 = sec_b64.ok_or(PairingError::BadParams("missing s"))?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut pub_bytes = [0u8; 32];
    let pub_vec = b64.decode(pub_b64).map_err(|_| PairingError::BadEncoding)?;
    if pub_vec.len() != 32 {
        return Err(PairingError::BadKeyLength);
    }
    pub_bytes.copy_from_slice(&pub_vec);

    let x_b64 = x_b64.ok_or(PairingError::BadParams("missing x"))?;
    let x_vec = b64.decode(x_b64).map_err(|_| PairingError::BadEncoding)?;
    if x_vec.len() != 32 {
        return Err(PairingError::BadKeyLength);
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&x_vec);
    let admin_x25519 = X25519PubKey(x);

    let mut secret = [0u8; 32];
    let sec_vec = b64.decode(sec_b64).map_err(|_| PairingError::BadEncoding)?;
    if sec_vec.len() != 32 {
        return Err(PairingError::BadKeyLength);
    }
    secret.copy_from_slice(&sec_vec);

    let invite_id = invite_id.ok_or(PairingError::BadParams("missing i"))?;
    if !crate::network::valid_id(&invite_id) {
        return Err(PairingError::BadParams("invalid i"));
    }
    let rendezvous_topic = rendezvous_topic(&secret);

    Ok(PairingInvite {
        invite_id,
        rendezvous_topic,
        admin_pub: Ed25519PubKey(pub_bytes),
        admin_x25519,
        secret,
    })
}

/// Stable, unguessable relay topic used only for invitation rendezvous.
pub fn rendezvous_topic(secret: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"Fwoosh pairing v2\0rendezvous");
    h.update(secret);
    let digest = h.finalize();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..24]);
    format!("fw-invite-{token}")
}

/// Generate a fresh 32-byte pairing secret.
pub fn random_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut s);
    s
}

// ---------------------------------------------------------------------------
//  Proof-of-knowledge: joining device proves it knows `secret` without
//  revealing it. We derive a domain-separated MAC key, then HMAC the request.
// ---------------------------------------------------------------------------

/// Derive the HMAC key from the invitation secret with a two-stage HMAC KDF.
/// This binds the MAC to Fwoosh pairing so the secret can't be reused
/// against some other protocol's expectation.
fn mac_key(secret: &[u8; 32]) -> [u8; 32] {
    let salt = b"Fwoosh pairing v2\0salt";
    let info = b"Fwoosh pairing v2\0mac-key";

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

fn network_proof_input(req: &NetworkJoinRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        req.invite_id.len() + 32 + 32 + req.nonce.len() + req.identity.label.len() + 8,
    );
    buf.extend_from_slice(b"Fwoosh pairing v2\0join");
    buf.extend_from_slice(req.invite_id.as_bytes());
    buf.extend_from_slice(&req.identity.signing_pub.0);
    buf.extend_from_slice(&req.identity.x25519_pub.0);
    buf.extend_from_slice(&req.nonce);
    buf.extend_from_slice(&req.requested_at.to_be_bytes());
    buf.extend_from_slice(req.identity.label.as_bytes());
    buf
}

pub fn build_network_join_request(
    invite_id: String,
    identity: DeviceIdentity,
    secret: &[u8; 32],
    requested_at: u64,
) -> NetworkJoinRequest {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let mut req = NetworkJoinRequest {
        invite_id,
        identity,
        nonce,
        requested_at,
        proof: [0u8; 32],
    };
    let key = mac_key(secret);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).expect("hmac key");
    mac.update(&network_proof_input(&req));
    req.proof.copy_from_slice(&mac.finalize().into_bytes());
    req
}

pub fn verify_network_join_request(
    req: &NetworkJoinRequest,
    secret: &[u8; 32],
) -> Result<(), PairingError> {
    let key = mac_key(secret);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).expect("hmac key");
    mac.update(&network_proof_input(req));
    mac.verify_slice(&req.proof)
        .map_err(|_| PairingError::InvalidProof)
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
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
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

    #[test]
    fn durable_network_uri_roundtrips_without_room_topic() {
        let admin = DeviceKeypairs::generate();
        let invite_id = crate::network::new_id();
        let secret = random_secret();
        let uri = build_network_uri(&invite_id, &admin.signing_pub, &admin.x25519_pub, &secret);
        let invite = parse_uri(&uri).unwrap();
        assert_eq!(invite.invite_id, invite_id);
        assert_eq!(invite.rendezvous_topic, rendezvous_topic(&secret));
        assert_eq!(invite.admin_pub, admin.signing_pub);
        assert_eq!(invite.admin_x25519, admin.x25519_pub);
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
    fn rejects_legacy_pairing_uri() {
        let admin = DeviceKeypairs::generate();
        let secret = random_secret();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let uri = format!(
            "{SCHEME}?t=topic&pub={}&s={}",
            b64.encode(admin.signing_pub.0),
            b64.encode(secret),
        );
        assert!(matches!(
            parse_uri(&uri),
            Err(PairingError::BadParams("unsupported version"))
        ));
    }

    #[test]
    fn rejects_duplicate_pairing_parameters() {
        let admin = DeviceKeypairs::generate();
        let secret = random_secret();
        let uri = build_network_uri(
            &crate::network::new_id(),
            &admin.signing_pub,
            &admin.x25519_pub,
            &secret,
        );
        let duplicate = format!(
            "{uri}&s={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret)
        );
        assert!(matches!(
            parse_uri(&duplicate),
            Err(PairingError::BadParams("duplicate s"))
        ));
    }

    #[test]
    fn reusable_join_proof_binds_invitation_and_timestamp() {
        let joining = DeviceKeypairs::generate();
        let identity = DeviceIdentity::from_keypairs(&joining, "phone");
        let secret = random_secret();
        let mut req = build_network_join_request(crate::network::new_id(), identity, &secret, 42);
        assert!(verify_network_join_request(&req, &secret).is_ok());
        req.requested_at += 1;
        assert!(matches!(
            verify_network_join_request(&req, &secret),
            Err(PairingError::InvalidProof)
        ));
    }
}
