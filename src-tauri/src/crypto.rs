//! ClipVault crypto core: signed envelope encryption with roster epochs.
//!
//! Design (frozen spec):
//! - Per device: X25519 encryption keypair + Ed25519 signing keypair.
//! - Per clip: one fresh random content key; payload encrypted ONCE with
//!   XChaCha20-Poly1305 (chunked); content key wrapped once per recipient via
//!   HPKE (RFC 9180, base mode, X25519+HKDF-SHA256+ChaCha20-Poly1305).
//! - The full manifest (incl. a chunk Merkle root) is signed with Ed25519 over
//!   canonical postcard bytes with a domain separator — the single source of
//!   sender authenticity + envelope integrity.
//! - Nonces: xchacha_nonce = random_128_bit_clip_prefix || u64_be(chunk_index),
//!   constructed ONLY inside `seal_clip()`. Callers never supply nonces.
//!
//! See the plan / security caveats for the full threat model. Notable accepted
//! tradeoff: no forward secrecy (ratcheting deferred).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable, single_shot_open, single_shot_seal};
// Ciphersuite: HPKE base mode, X25519+HKDF-SHA256+ChaCha20-Poly1305.
use hpke::{aead::ChaCha20Poly1305 as HpkeAead, kdf::HkdfSha256, kem::X25519HkdfSha256 as KemImpl};
// rand 0.9: use rand::rng() (ThreadRng) which implements rand_core 0.9's
// CryptoRng + RngCore (matching hpke 0.13's bound). Note: ed25519-dalek 2.x /
// x25519-dalek 2.x use rand_core 0.6, while hpke 0.13 uses rand_core 0.9 —
// three rand_core versions coexist. To avoid the cross-version RNG-trait
// mismatch, we generate random BYTES via rand 0.9 and construct dalek keys
// via from_bytes(), and pass the rand 0.9 RNG to hpke directly.
use rand::RngCore as _;
// hpke re-exports rand_core 0.9; use it for the RNG generic bound on wrap.
use hpke::rand_core;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// hpke wraps x25519-dalek types in internal PublicKey/PrivateKey wrappers.
// We reach them only via the KEM's associated types to avoid the private
// `dhkex` module.
type HpkePriv = <KemImpl as Kem>::PrivateKey;
type HpkePub = <KemImpl as Kem>::PublicKey;

/// Max plaintext bytes per encrypted chunk. Stays under ntfy's 4096-byte body
/// threshold after base64 + envelope overhead. Public ntfy treats larger bodies
/// as attachments, which we avoid in v1.
pub const CHUNK_SIZE: usize = 3072;
/// Nonce = 128-bit random clip prefix + 64-bit big-endian chunk index.
const CLIP_NONCE_PREFIX_LEN: usize = 16;
const CLIP_NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce length (XNonce)

/// Domain separator bound into every signature to prevent cross-protocol /
/// cross-version signature reuse.
const SIG_DOMAIN: &[u8] = b"ClipVault envelope v1";

/// X25519 public key bytes (32). Wrapped for serde + newtype semantics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X25519PubKey(pub [u8; 32]);

impl std::fmt::Debug for X25519PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X25519PubKey").field(&hex::encode(self.0)).finish()
    }
}

/// Ed25519 verifying (public) key bytes (32) — the device identity.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519PubKey(pub [u8; 32]);

impl std::fmt::Debug for Ed25519PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519PubKey").field(&hex::encode(self.0)).finish()
    }
}

// ============================================================================
//  Device keypairs
// ============================================================================

/// A device's long-term keypairs. The private halves are held in memory only
/// after being loaded from the OS keychain (see keychain.rs).
pub struct DeviceKeypairs {
    pub signing: SigningKey,           // Ed25519
    pub signing_pub: Ed25519PubKey,    // = signing.verifying_key()
    pub x25519_secret: HpkePriv,       // HPKE encryption private (wraps dalek)
    pub x25519_pub: X25519PubKey,      // encryption public (raw bytes for serde)
}

impl DeviceKeypairs {
    /// Generate fresh keypairs using the OS CSPRNG. We draw random bytes via
    /// rand 0.9 (which targets rand_core 0.9, matching hpke), then build keys
    /// from bytes — this sidesteps the ed25519-dalek/x25519-dalek rand_core 0.6
    /// vs hpke rand_core 0.9 version split.
    pub fn generate() -> Self {
        let mut ed_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut ed_sk_bytes);
        let signing = SigningKey::from_bytes(&ed_sk_bytes);

        let mut x_sk_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut x_sk_bytes);
        Self::assemble(signing, x_sk_bytes)
    }

    /// Shared assembly: derive the matching X25519 pubkey + identity from the
    /// given ed25519 signing key and raw x25519 secret bytes.
    fn assemble(signing: SigningKey, x_sk_bytes: [u8; 32]) -> Self {
        let signing_pub = Ed25519PubKey(signing.verifying_key().to_bytes());
        let x25519_secret =
            HpkePriv::from_bytes(&x_sk_bytes).expect("32-byte x25519 secret");
        let x25519_pub_obj = KemImpl::sk_to_pk(&x25519_secret);
        let x25519_pub = X25519PubKey(x25519_pub_obj.to_bytes().into());
        Self { signing, signing_pub, x25519_secret, x25519_pub }
    }

    /// Reconstruct from raw keychain bytes: (ed25519_sk, x25519_sk).
    pub fn from_bytes(signing_key: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&signing_key);
        Self::assemble(signing, x25519_secret)
    }

    /// Serialize to keychain bytes: (ed25519_sk, x25519_sk).
    pub fn to_bytes(&self) -> ([u8; 32], [u8; 32]) {
        let sk = self.signing.to_bytes();
        let xsk_bytes = Serializable::to_bytes(&self.x25519_secret);
        let mut xsk = [0u8; 32];
        xsk.copy_from_slice(&xsk_bytes);
        (sk, xsk)
    }
}

// ============================================================================
//  Envelope types
// ============================================================================

/// How the receiver treats the plaintext after decrypt.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum StorePolicy {
    /// Sync once; do NOT persist to ClipVault history.
    Private,
    /// Persist to ClipVault history.
    History,
}

/// One recipient's wrapped content key (HPKE single-shot seal).
#[derive(Clone, Serialize, Deserialize)]
pub struct RecipientWrap {
    /// Ed25519 identity pubkey of the recipient (lookup key).
    pub recipient_id: Ed25519PubKey,
    /// X25519 pubkey the wrap was sealed to (lets us detect rotation).
    pub recipient_x25519: X25519PubKey,
    /// HPKE encapped ephemeral pubkey (32 bytes for X25519).
    pub encapped: [u8; 32],
    /// Wrapped content key ciphertext (PT is 32 bytes; CT includes tag).
    pub wrapped_ct: Vec<u8>,
}

/// The signed manifest header. `signature` covers the canonical postcard
/// encoding of the manifest *without* the signature field, prefixed by
/// `SIG_DOMAIN`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub msg_id: [u8; 16],            // UUIDv4 bytes
    pub room_id: String,             // ntfy topic
    pub roster_epoch: u64,
    pub sender_id: Ed25519PubKey,
    pub sender_x25519: X25519PubKey, // for reference; auth is via signature
    pub ts: u64,                     // unix seconds
    pub payload_type: PayloadType,
    pub declared_size: u64,          // plaintext byte length
    pub chunk_count: u32,
    pub merkle_root: [u8; 32],       // SHA-256 Merkle root over chunk ciphertexts
    pub recipients: Vec<RecipientWrap>,
    pub store_policy: StorePolicy,
    /// Ed25519 signature over `SIG_DOMAIN || postcard(Self without this field)`.
    pub signature: Vec<u8>,
}

/// Payload type tag. v1 = text only.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum PayloadType {
    Text,
}

/// A single encrypted chunk published to the relay.
#[derive(Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub msg_id: [u8; 16],
    pub index: u32,
    pub nonce: [u8; CLIP_NONCE_LEN],
    pub ct: Vec<u8>,
}

// ============================================================================
//  Errors
// ============================================================================

#[derive(Debug)]
pub enum CryptoError {
    /// Sender's epoch is older than the receiver's current roster epoch.
    StaleEpoch { got: u64, have: u64 },
    /// Sender is not in the receiver's current (non-revoked) roster.
    UnknownSender,
    /// We are not a recipient of this clip (no wrap for our device).
    NotARecipient,
    /// Ed25519 signature did not verify.
    InvalidSignature,
    /// HPKE decapsulation or AEAD open failed.
    Hpke(HpkeError),
    /// AEAD decryption of a chunk failed.
    Decrypt,
    /// Chunk index out of range / mismatched count.
    ChunkRange,
    /// Merkle root mismatch (chunk swap/truncation detected).
    MerkleMismatch,
    /// Invalid input length / encoding.
    BadInput(&'static str),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleEpoch { got, have } => write!(f, "stale roster epoch {got} (have {have})"),
            Self::UnknownSender => write!(f, "sender not in current roster"),
            Self::NotARecipient => write!(f, "device is not a recipient of this clip"),
            Self::InvalidSignature => write!(f, "envelope signature verification failed"),
            Self::Hpke(e) => write!(f, "HPKE error: {e:?}"),
            Self::Decrypt => write!(f, "chunk decryption failed"),
            Self::ChunkRange => write!(f, "chunk index/count out of range"),
            Self::MerkleMismatch => write!(f, "chunk Merkle root mismatch"),
            Self::BadInput(m) => write!(f, "bad input: {m}"),
        }
    }
}
impl std::error::Error for CryptoError {}

impl From<HpkeError> for CryptoError {
    fn from(e: HpkeError) -> Self { Self::Hpke(e) }
}

// ============================================================================
//  Signing — sign canonical bytes, not a fuzzy hash expression.
// ============================================================================

/// Manifest with the signature field removed, for canonical signing.
/// Serialized with postcard (deterministic) and prefixed by SIG_DOMAIN.
#[derive(Serialize)]
struct ManifestForSigning<'a> {
    msg_id: &'a [u8; 16],
    room_id: &'a str,
    roster_epoch: u64,
    sender_id: &'a Ed25519PubKey,
    sender_x25519: &'a X25519PubKey,
    ts: u64,
    payload_type: PayloadType,
    declared_size: u64,
    chunk_count: u32,
    merkle_root: &'a [u8; 32],
    recipients: &'a [RecipientWrap],
    store_policy: StorePolicy,
}

fn to_signing_bytes(m: &Manifest) -> Vec<u8> {
    let view = ManifestForSigning {
        msg_id: &m.msg_id,
        room_id: &m.room_id,
        roster_epoch: m.roster_epoch,
        sender_id: &m.sender_id,
        sender_x25519: &m.sender_x25519,
        ts: m.ts,
        payload_type: m.payload_type,
        declared_size: m.declared_size,
        chunk_count: m.chunk_count,
        merkle_root: &m.merkle_root,
        recipients: &m.recipients,
        store_policy: m.store_policy,
    };
    let mut buf = SIG_DOMAIN.to_vec();
    buf.extend_from_slice(&postcard::to_allocvec(&view).expect("postcard encode manifest"));
    buf
}

fn verify_manifest_sig(m: &Manifest) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&m.sender_id.0)
        .map_err(|_| CryptoError::BadInput("bad sender ed25519 pubkey"))?;
    let sig = Signature::from_slice(&m.signature)
        .map_err(|_| CryptoError::BadInput("bad signature bytes"))?;
    let signing_bytes = to_signing_bytes(m);
    vk.verify(&signing_bytes, &sig).map_err(|_| CryptoError::InvalidSignature)
}

// ============================================================================
//  Merkle root over chunk ciphertexts (SHA-256)
//  Leaf i = SHA-256(ct_i || index_be32); interior = SHA-256(left||right).
// ============================================================================

fn merkle_root_of(chunks: &[impl AsRef<[u8]>]) -> [u8; 32] {
    fn h(b: &[u8]) -> [u8; 32] {
        let mut s = Sha256::new();
        s.update(b);
        s.finalize().into()
    }
    let mut level: Vec<[u8; 32]> = chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut leaf_input = Vec::with_capacity(c.as_ref().len() + 4);
            leaf_input.extend_from_slice(c.as_ref());
            leaf_input.extend_from_slice(&(i as u32).to_be_bytes());
            h(&leaf_input)
        })
        .collect();

    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(h(&pair));
            i += 2;
        }
        level = next;
    }
    level[0]
}

// ============================================================================
//  Nonce construction — the ONLY place nonces are built. `seal_clip()` is the
//  sole encrypt entry point; callers never supply a nonce.
// ============================================================================

fn build_nonce(clip_prefix: &[u8; CLIP_NONCE_PREFIX_LEN], index: u32) -> [u8; CLIP_NONCE_LEN] {
    let mut n = [0u8; CLIP_NONCE_LEN];
    n[..CLIP_NONCE_PREFIX_LEN].copy_from_slice(clip_prefix);
    n[CLIP_NONCE_PREFIX_LEN..].copy_from_slice(&(index as u64).to_be_bytes());
    n
}

// ============================================================================
//  HPKE wrap/unwrap of the content key
// ============================================================================

type KdfImpl = HkdfSha256;
type AeadImpl = HpkeAead;

/// `info` bound to (sender, recipient, room, epoch, msg_id) so a wrap record
/// can't be replayed into a different message context.
fn hpke_info(
    sender: &Ed25519PubKey,
    recipient: &Ed25519PubKey,
    room: &str,
    epoch: u64,
    msg_id: &[u8; 16],
) -> Vec<u8> {
    let mut info = b"ClipVault wrap v1\0".to_vec();
    info.extend_from_slice(&sender.0);
    info.extend_from_slice(&recipient.0);
    info.extend_from_slice(room.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(msg_id);
    info
}

/// Wrap `content_key` for `recipient_x25519` (HPKE base mode). Returns a
/// RecipientWrap. Authenticity comes from the Ed25519 signature, NOT HPKE auth
/// mode, so we keep the HPKE dependency surface minimal.
fn wrap_content_key(
    recipient_id: Ed25519PubKey,
    recipient_x25519: X25519PubKey,
    content_key: &[u8],
    sender_id: &Ed25519PubKey,
    room: &str,
    epoch: u64,
    msg_id: &[u8; 16],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<RecipientWrap, CryptoError> {
    let mode = OpModeS::<KemImpl>::Base;
    let pk_r = HpkePub::from_bytes(&recipient_x25519.0)
        .map_err(|_| CryptoError::BadInput("bad recipient x25519 pubkey"))?;
    let info = hpke_info(sender_id, &recipient_id, room, epoch, msg_id);
    let (encapped, wrapped_ct) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
        &mode, &pk_r, &info, content_key, b"", rng,
    )?;
    let enc_bytes = Serializable::to_bytes(&encapped);
    if enc_bytes.len() != 32 {
        return Err(CryptoError::BadInput("unexpected encapped key length"));
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&enc_bytes);
    Ok(RecipientWrap { recipient_id, recipient_x25519, encapped: enc, wrapped_ct })
}

/// Unwrap the content key for our device.
fn unwrap_content_key(
    wrap: &RecipientWrap,
    my_x25519_secret: &HpkePriv,
    sender_id: &Ed25519PubKey,
    room: &str,
    epoch: u64,
    msg_id: &[u8; 16],
) -> Result<[u8; 32], CryptoError> {
    let mode = OpModeR::<KemImpl>::Base;
    let encapped = <KemImpl as Kem>::EncappedKey::from_bytes(&wrap.encapped)
        .map_err(|_| CryptoError::BadInput("bad encapped key"))?;
    let info = hpke_info(sender_id, &wrap.recipient_id, room, epoch, msg_id);
    let pt = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
        &mode, my_x25519_secret, &encapped, &info, &wrap.wrapped_ct, b"",
    )?;
    if pt.len() != 32 {
        return Err(CryptoError::BadInput("decrypted content key has wrong length"));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&pt);
    Ok(k)
}

// ============================================================================
//  Public seal/open API
// ============================================================================

/// A recipient: their identity (Ed25519) + encryption (X25519) pubkeys.
#[derive(Clone)]
pub struct Recipient {
    pub id: Ed25519PubKey,
    pub x25519: X25519PubKey,
}

/// Output of `seal_clip`: the signed manifest + the encrypted chunks to publish.
pub struct SealedClip {
    pub manifest: Manifest,
    pub chunks: Vec<Chunk>,
}

/// Encrypts a text clip into a signed envelope + chunks.
///
/// - `recipients`: who can decrypt (caller excludes revoked devices).
/// - `room`/`epoch`: the current ntfy topic and roster epoch.
/// - `store_policy`: Private = sync once, History = persist locally.
///
/// This is the ONLY encryption entry point; it owns nonce construction.
pub fn seal_clip(
    sender: &DeviceKeypairs,
    recipients: &[Recipient],
    plaintext: &str,
    room: &str,
    epoch: u64,
    store_policy: StorePolicy,
    now_unix: u64,
) -> Result<SealedClip, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::BadInput("no recipients"));
    }
    let mut rng = rand::rng();

    // 1. Fresh per-clip content key + nonce prefix.
    let mut content_key = [0u8; 32];
    rng.fill_bytes(&mut content_key);
    let mut nonce_prefix = [0u8; CLIP_NONCE_PREFIX_LEN];
    rng.fill_bytes(&mut nonce_prefix);

    let cipher = XChaCha20Poly1305::new(&content_key.into());

    // 2. Chunk + encrypt.
    let pt_bytes = plaintext.as_bytes();
    let chunks_iter: Vec<&[u8]> = if pt_bytes.is_empty() {
        vec![&[][..]]
    } else {
        pt_bytes.chunks(CHUNK_SIZE).collect()
    };
    let chunk_count = chunks_iter.len() as u32;

    let mut encrypted_chunks: Vec<Vec<u8>> = Vec::with_capacity(chunks_iter.len());
    let mut chunk_objs: Vec<Chunk> = Vec::with_capacity(chunks_iter.len());
    for (i, pt_chunk) in chunks_iter.iter().enumerate() {
        let nonce_bytes = build_nonce(&nonce_prefix, i as u32);
        let aad = chunk_aad(room, epoch, &sender.signing_pub.0, i as u32, chunk_count);
        let ct = cipher
            .encrypt(&XNonce::from(nonce_bytes), Payload { msg: pt_chunk, aad: &aad })
            .map_err(|_| CryptoError::Decrypt)?;
        encrypted_chunks.push(ct.clone());
        chunk_objs.push(Chunk {
            msg_id: [0u8; 16], // filled after msg_id is assigned
            index: i as u32,
            nonce: nonce_bytes,
            ct,
        });
    }

    // 3. Merkle root over chunk ciphertexts (binds chunk integrity into sig).
    let merkle_root = merkle_root_of(&encrypted_chunks);

    // 4. msg_id (UUIDv4).
    let mut msg_id = [0u8; 16];
    rng.fill_bytes(&mut msg_id);
    msg_id[6] = (msg_id[6] & 0x0f) | 0x40; // version 4
    msg_id[8] = (msg_id[8] & 0x3f) | 0x80; // variant
    for c in chunk_objs.iter_mut() {
        c.msg_id = msg_id;
    }

    // 5. Wrap content key for each recipient via HPKE.
    let mut wraps = Vec::with_capacity(recipients.len());
    for r in recipients {
        let w = wrap_content_key(
            r.id.clone(),
            r.x25519.clone(),
            &content_key,
            &sender.signing_pub,
            room,
            epoch,
            &msg_id,
            &mut rng,
        )?;
        wraps.push(w);
    }

    // 6. Build manifest (unsigned), then sign.
    let mut manifest = Manifest {
        msg_id,
        room_id: room.to_string(),
        roster_epoch: epoch,
        sender_id: sender.signing_pub.clone(),
        sender_x25519: sender.x25519_pub.clone(),
        ts: now_unix,
        payload_type: PayloadType::Text,
        declared_size: pt_bytes.len() as u64,
        chunk_count,
        merkle_root,
        recipients: wraps,
        store_policy,
        signature: Vec::new(),
    };
    let signing_bytes = to_signing_bytes(&manifest);
    manifest.signature = sender.signing.sign(&signing_bytes).to_bytes().to_vec();

    Ok(SealedClip { manifest, chunks: chunk_objs })
}

/// AAD bound to each chunk's AEAD: binds room, epoch, sender, index, count.
fn chunk_aad(room: &str, epoch: u64, sender: &[u8; 32], index: u32, count: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(room.len() + 32 + 8 + 4 + 4);
    a.extend_from_slice(room.as_bytes());
    a.extend_from_slice(&epoch.to_be_bytes());
    a.extend_from_slice(sender);
    a.extend_from_slice(&index.to_be_bytes());
    a.extend_from_slice(&count.to_be_bytes());
    a
}

/// Result of opening a clip: recovered plaintext + metadata.
#[derive(Debug)]
pub struct OpenedClip {
    pub sender_id: Ed25519PubKey,
    pub epoch: u64,
    pub plaintext: String,
    pub store_policy: StorePolicy,
    pub ts: u64,
}

/// Verifies and decrypts a sealed clip for our device.
///
/// `current_epoch`: the receiver's latest known roster epoch. Messages with a
/// strictly smaller epoch are rejected as stale (replay/old-state protection).
/// `is_active_member`: closure returning whether (sender_id, epoch) is in the
/// receiver's current, non-revoked roster.
pub fn open_clip(
    manifest: &Manifest,
    chunks: &[Chunk],
    me: &DeviceKeypairs,
    current_epoch: u64,
    is_active_member: impl Fn(&Ed25519PubKey, u64) -> bool,
) -> Result<OpenedClip, CryptoError> {
    // 1. Epoch check: reject strictly stale epochs.
    if manifest.roster_epoch < current_epoch {
        return Err(CryptoError::StaleEpoch {
            got: manifest.roster_epoch,
            have: current_epoch,
        });
    }

    // 2. Sender membership in the current roster.
    if !is_active_member(&manifest.sender_id, manifest.roster_epoch) {
        return Err(CryptoError::UnknownSender);
    }

    // 3. Signature over canonical bytes (single source of authenticity).
    verify_manifest_sig(manifest)?;

    // 4. Find our wrap and unwrap the content key.
    let my_id = &me.signing_pub;
    let my_wrap = manifest
        .recipients
        .iter()
        .find(|w| &w.recipient_id == my_id)
        .ok_or(CryptoError::NotARecipient)?;
    let content_key = unwrap_content_key(
        my_wrap,
        &me.x25519_secret,
        &manifest.sender_id,
        &manifest.room_id,
        manifest.roster_epoch,
        &manifest.msg_id,
    )?;

    // 5. Validate chunk count + indices.
    if chunks.len() as u32 != manifest.chunk_count {
        return Err(CryptoError::ChunkRange);
    }
    for (i, c) in chunks.iter().enumerate() {
        if c.index != i as u32 || c.msg_id != manifest.msg_id {
            return Err(CryptoError::ChunkRange);
        }
    }
    // Recompute Merkle root over ciphertexts.
    let ct_refs: Vec<&[u8]> = chunks.iter().map(|c| c.ct.as_slice()).collect();
    if merkle_root_of(&ct_refs) != manifest.merkle_root {
        return Err(CryptoError::MerkleMismatch);
    }

    // 6. Decrypt chunks in order.
    let cipher = XChaCha20Poly1305::new(&content_key.into());
    let mut plaintext = Vec::with_capacity(manifest.declared_size as usize);
    for c in chunks {
        let aad = chunk_aad(
            &manifest.room_id,
            manifest.roster_epoch,
            &manifest.sender_id.0,
            c.index,
            manifest.chunk_count,
        );
        let pt = cipher
            .decrypt(&XNonce::from(c.nonce), Payload { msg: &c.ct, aad: &aad })
            .map_err(|_| CryptoError::Decrypt)?;
        plaintext.extend_from_slice(&pt);
    }
    if plaintext.len() as u64 != manifest.declared_size {
        return Err(CryptoError::MerkleMismatch);
    }

    let plaintext = String::from_utf8(plaintext)
        .map_err(|_| CryptoError::BadInput("plaintext is not valid UTF-8"))?;

    Ok(OpenedClip {
        sender_id: manifest.sender_id.clone(),
        epoch: manifest.roster_epoch,
        plaintext,
        store_policy: manifest.store_policy,
        ts: manifest.ts,
    })
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 { 1_750_000_000 }

    fn recipients_of(devices: &[&DeviceKeypairs]) -> Vec<Recipient> {
        devices
            .iter()
            .map(|d| Recipient { id: d.signing_pub.clone(), x25519: d.x25519_pub.clone() })
            .collect()
    }

    fn always_alice(alice: &DeviceKeypairs) -> impl Fn(&Ed25519PubKey, u64) -> bool + Copy {
        let id = alice.signing_pub.0; // [u8; 32] is Copy
        move |x: &Ed25519PubKey, _: u64| x.0 == id
    }

    #[test]
    fn roundtrip_single_recipient_text() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "hello bob",
            "room-ab",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        let opened = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .expect("open");
        assert_eq!(opened.plaintext, "hello bob");
        assert_eq!(opened.store_policy, StorePolicy::History);
    }

    #[test]
    fn roundtrip_multi_recipient() {
        let alice = DeviceKeypairs::generate();
        let others: Vec<DeviceKeypairs> = (0..4).map(|_| DeviceKeypairs::generate()).collect();
        let refs: Vec<&DeviceKeypairs> = others.iter().collect();
        let sealed = seal_clip(
            &alice,
            &recipients_of(&refs),
            "group message",
            "room-grp",
            3,
            StorePolicy::Private,
            now(),
        )
        .expect("seal");
        let pred = always_alice(&alice);
        for dev in &others {
            let opened = open_clip(&sealed.manifest, &sealed.chunks, dev, 3, pred).expect("open");
            assert_eq!(opened.plaintext, "group message");
        }
    }

    #[test]
    fn large_text_chunks_correctly() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let big = "A".repeat(CHUNK_SIZE * 5 + 123);
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            &big,
            "room-big",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        assert!(sealed.chunks.len() > 1);
        let opened = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .expect("open");
        assert_eq!(opened.plaintext.len(), big.len());
        assert_eq!(opened.plaintext, big);
    }

    #[test]
    fn empty_text_roundtrips() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "",
            "room-empty",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        assert_eq!(sealed.chunks.len(), 1);
        let opened = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .expect("open");
        assert_eq!(opened.plaintext, "");
    }

    #[test]
    fn keypair_roundtrip_preserves_identity() {
        let kp = DeviceKeypairs::generate();
        let (sk, xsk) = kp.to_bytes();
        let kp2 = DeviceKeypairs::from_bytes(sk, xsk);
        assert_eq!(kp.signing_pub, kp2.signing_pub);
        assert_eq!(kp.x25519_pub, kp2.x25519_pub);
    }

    #[test]
    fn revoked_sender_rejected() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "should be rejected",
            "room-rev",
            2,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        // Same epoch, but alice is no longer in bob's current roster.
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            2, // current epoch matches (not stale)
            |_, _| false, // alice revoked from roster
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::UnknownSender), "got {err:?}");
    }

    #[test]
    fn stale_epoch_rejected() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "old",
            "room-stale",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            5, // current epoch is newer
            always_alice(&alice),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::StaleEpoch { .. }), "got {err:?}");
    }

    #[test]
    fn tampered_chunk_rejected_by_merkle() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let big = "B".repeat(CHUNK_SIZE * 3);
        let mut sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            &big,
            "room-tamper",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        // Swap two chunks' ciphertext — should break the Merkle root or decrypt.
        let len = sealed.chunks.len();
        let (first, rest) = sealed.chunks.split_at_mut(len - 1);
        first[0].ct.swap_with_slice(&mut rest[0].ct);
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .unwrap_err();
        assert!(
            matches!(err, CryptoError::MerkleMismatch | CryptoError::Decrypt),
            "got {err:?}"
        );
    }

    #[test]
    fn forged_signature_rejected() {
        let alice = DeviceKeypairs::generate();
        let mallory = DeviceKeypairs::generate(); // different signing key
        let bob = DeviceKeypairs::generate();
        let mut sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "legit",
            "room-forg",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        // Mallory re-signs the manifest but keeps alice's sender_id.
        let signing_bytes = to_signing_bytes(&sealed.manifest);
        sealed.manifest.signature = mallory.signing.sign(&signing_bytes).to_bytes().to_vec();
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature), "got {err:?}");
    }

    #[test]
    fn non_recipient_cannot_decrypt() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let eve = DeviceKeypairs::generate(); // not a recipient
        let sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            "secret for bob",
            "room-eve",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &eve,
            1,
            always_alice(&alice),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::NotARecipient), "got {err:?}");
    }

    #[test]
    fn truncated_chunks_rejected() {
        let alice = DeviceKeypairs::generate();
        let bob = DeviceKeypairs::generate();
        let big = "C".repeat(CHUNK_SIZE * 3);
        let mut sealed = seal_clip(
            &alice,
            &recipients_of(&[&bob]),
            &big,
            "room-trunc",
            1,
            StorePolicy::History,
            now(),
        )
        .expect("seal");
        sealed.chunks.pop(); // drop last chunk
        let err = open_clip(
            &sealed.manifest,
            &sealed.chunks,
            &bob,
            1,
            always_alice(&alice),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::ChunkRange), "got {err:?}");
    }
}
