//! ntfy transport: HTTPS publish + WSS subscribe with reconnect + catch-up.
//!
//! Wire format (all encrypted by `crypto` before reaching here):
//! - Publish: POST `<base>/<topic>` with JSON `{"topic","message","title"}`,
//!   where `message` = base64(postcard(envelope_or_chunk)).
//! - Subscribe: WSS `<base>/<topic>/ws?since=<last>` for streaming + catch-up.
//!
//! Security: we ENFORCE TLS (fail closed). A non-https/non-wss base URL is
//! rejected. The default base is the public `ntfy.sh` relay; users may point at
//! a self-hosted ntfy server via settings.
//!
//! This module is transport-only: it does not know about crypto. Callers pass
//! opaque bytes to publish and receive opaque bytes on subscribe.

use base64::Engine;
use futures_util::StreamExt;
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::mpsc;

/// Default public relay. Zero infra cost for the user.
pub const DEFAULT_BASE: &str = "https://ntfy.sh";

/// Cap a single message body well under ntfy's 4096-byte attachment threshold
/// (after base64 expansion). See crypto::CHUNK_SIZE for the plaintext cap.
pub const MAX_BODY_BYTES: usize = 3500;
/// Fwoosh's encrypted attachment ceiling. This leaves ample room below the
/// public ntfy.sh 2 MB limit for a 1 MiB text clip plus framing overhead.
pub const MAX_ATTACHMENT_BYTES: usize = 1_500_000;

/// Verify that the configured relay is reachable without publishing a topic
/// message. Returns the round-trip latency of the relay health endpoint.
pub async fn diagnose_relay(base: &str) -> Result<u64, NtfyError> {
    ensure_rustls_crypto_provider();
    let https_base = require_tls_base(base)?;
    let url = format!("{https_base}/v1/health");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()?;
    let started = std::time::Instant::now();
    let response = client.get(url).send().await?;
    let elapsed = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(NtfyError::BadStatus(status.as_u16(), text));
    }
    Ok(elapsed)
}

/// Relay-side caching behavior for a published message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCache {
    /// Use the relay default. On public ntfy.sh this enables short catch-up
    /// caching for offline or reconnecting subscribers.
    Default,
    /// Ask the relay not to cache this message server-side. Subscribers must be
    /// connected at publish time to receive it.
    NoStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishOptions {
    pub cache: RelayCache,
}

impl PublishOptions {
    pub const fn no_cache() -> Self {
        Self {
            cache: RelayCache::NoStore,
        }
    }
}

impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            cache: RelayCache::Default,
        }
    }
}

fn ensure_rustls_crypto_provider() {
    // WebRTC and the HTTPS/WebSocket stack can enable different Rustls crypto
    // backends transitively. Pick one explicitly before any TLS client starts.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
pub enum NtfyError {
    /// A non-TLS base URL was configured. We never allow plaintext transport.
    InsecureBase(String),
    Http(reqwest::Error),
    WebSocket(tokio_tungstenite::tungstenite::Error),
    BadStatus(u16, String),
    BadMessage(String),
    /// Message body exceeds the relay limit.
    TooLarge,
    /// An attachment URL did not resolve to the configured TLS relay.
    UnsafeAttachmentUrl,
    /// Downloaded attachment bytes did not match the relay event metadata.
    AttachmentSizeMismatch,
    /// The publish/subscribe task was cancelled or the channel closed.
    Cancelled,
}

impl std::fmt::Display for NtfyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureBase(b) => {
                write!(f, "refusing non-TLS relay base URL: {b}")
            }
            Self::Http(e) => write!(f, "http: {e}"),
            Self::WebSocket(e) => write!(f, "websocket: {e}"),
            Self::BadStatus(code, body) => write!(f, "relay returned {code}: {body}"),
            Self::BadMessage(m) => write!(f, "bad message: {m}"),
            Self::TooLarge => write!(f, "message exceeds relay body limit"),
            Self::UnsafeAttachmentUrl => {
                write!(f, "attachment URL does not belong to the configured relay")
            }
            Self::AttachmentSizeMismatch => write!(f, "attachment size does not match metadata"),
            Self::Cancelled => write!(f, "transport cancelled"),
        }
    }
}
impl std::error::Error for NtfyError {}
impl From<reqwest::Error> for NtfyError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e)
    }
}
impl From<tokio_tungstenite::tungstenite::Error> for NtfyError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(e)
    }
}

/// Ensure the base URL uses TLS. Returns the https base (no trailing slash).
/// We also derive the wss base by replacing the scheme.
fn require_tls_base(base: &str) -> Result<String, NtfyError> {
    let trimmed = base.trim_end_matches('/');
    if trimmed.starts_with("https://") {
        Ok(trimmed.to_string())
    } else if trimmed.starts_with("http://") || trimmed.starts_with("ws://") {
        Err(NtfyError::InsecureBase(base.to_string()))
    } else if trimmed.starts_with("wss://") {
        // accept wss, convert to https for the publish path
        Ok(trimmed.replacen("wss://", "https://", 1))
    } else {
        // bare host: assume https (default relay style)
        Ok(format!("https://{trimmed}"))
    }
}

/// Derive the wss subscribe URL from an https base + topic + since cursor.
fn ws_url(https_base: &str, topic: &str, since: Option<&str>) -> String {
    let ws = https_base.replacen("https://", "wss://", 1);
    let since_query = match since {
        Some(s) => format!("?since={s}"),
        None => String::new(),
    };
    format!("{ws}/{topic}/ws{since_query}")
}

/// A decoded ntfy message delivered to the app.
#[derive(Debug, Clone)]
pub struct RelayMessage {
    /// ntfy message id (used as the `since` cursor for catch-up).
    pub id: String,
    /// Base64-decoded payload bytes (postcard of a manifest or chunk).
    pub payload: Vec<u8>,
    /// The event time (unix ms from ntfy).
    pub time_ms: u64,
    /// Uploaded attachment metadata supplied by the relay, when present.
    pub attachment: Option<RelayAttachment>,
}

#[derive(Debug, Clone)]
pub struct RelayAttachment {
    pub url: String,
    pub size: u64,
}

// ntfy JSON message shape (subset we care about).
#[derive(Debug, Deserialize)]
struct NtfyJson {
    id: Option<String>,
    message: Option<String>,
    time: Option<u64>,
    event: Option<String>,
    attachment: Option<NtfyAttachment>,
}

#[derive(Debug, Deserialize)]
struct NtfyAttachment {
    url: String,
    size: Option<u64>,
}

/// Publish a single encrypted payload (manifest or one chunk) to the relay.
///
/// `payload` is already-serialized bytes; we base64-encode them and POST the
/// raw base64 string as the request body (NOT as JSON). ntfy stores the raw
/// body as the `message` field, so subscribers receive exactly the base64.
///
/// (Posting JSON like `{"topic":...,"message":"..."}` causes ntfy to store the
/// *entire JSON document* as the message, which breaks decoding.)
pub async fn publish(
    base: &str,
    topic: &str,
    payload: &[u8],
    _title: &str,
) -> Result<String, NtfyError> {
    publish_with_options(base, topic, payload, _title, PublishOptions::default()).await
}

/// Publish a single encrypted payload with explicit relay options.
pub async fn publish_with_options(
    base: &str,
    topic: &str,
    payload: &[u8],
    _title: &str,
    options: PublishOptions,
) -> Result<String, NtfyError> {
    ensure_rustls_crypto_provider();
    let https_base = require_tls_base(base)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    if b64.len() > MAX_BODY_BYTES {
        return Err(NtfyError::TooLarge);
    }
    let url = format!("{https_base}/{topic}");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // POST the raw base64 string as the body (text/plain). ntfy treats the
    // request body as the message content.
    let b64_len = b64.len();
    let resp = client
        .execute(build_publish_request(&client, &url, b64, options)?)
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        eprintln!("[ntfy] publish failed: {status} {text}");
        return Err(NtfyError::BadStatus(status.as_u16(), text));
    }
    eprintln!(
        "[ntfy] published {} bytes ({} b64) to topic",
        payload.len(),
        b64_len
    );
    Ok(String::from("ok"))
}

/// Publish encrypted clip chunks as one ntfy attachment while keeping the
/// signed manifest in the normal, small message field.
pub async fn publish_attachment_with_options(
    base: &str,
    topic: &str,
    notice: &[u8],
    attachment: Vec<u8>,
    options: PublishOptions,
) -> Result<(), NtfyError> {
    ensure_rustls_crypto_provider();
    let https_base = require_tls_base(base)?;
    let notice = base64::engine::general_purpose::STANDARD.encode(notice);
    if notice.len() > MAX_BODY_BYTES || attachment.len() > MAX_ATTACHMENT_BYTES {
        return Err(NtfyError::TooLarge);
    }
    let url = format!("{https_base}/{topic}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let response = client
        .execute(build_attachment_request(
            &client, &url, notice, attachment, options,
        )?)
        .await?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(NtfyError::BadStatus(status.as_u16(), text));
    }
    Ok(())
}

fn build_attachment_request(
    client: &reqwest::Client,
    url: &str,
    notice: String,
    attachment: Vec<u8>,
    options: PublishOptions,
) -> Result<reqwest::Request, reqwest::Error> {
    let mut request = client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .header("X-Filename", "fwoosh.clip")
        .header("X-Message", notice);
    if options.cache == RelayCache::NoStore {
        request = request.header("Cache", "no");
    }
    request.body(attachment).build()
}

/// Download one uploaded attachment without allowing the relay event to turn
/// into an arbitrary URL fetch. Size is checked before and during streaming.
pub async fn download_attachment(
    base: &str,
    attachment: &RelayAttachment,
) -> Result<Vec<u8>, NtfyError> {
    if attachment.size == 0 || attachment.size > MAX_ATTACHMENT_BYTES as u64 {
        return Err(NtfyError::TooLarge);
    }
    let https_base = require_tls_base(base)?;
    validate_attachment_url(&https_base, &attachment.url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        // The event URL is validated as same-origin. Do not let a relay-side
        // redirect silently turn the subsequent request into a cross-origin
        // fetch.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client.get(&attachment.url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(NtfyError::BadStatus(status.as_u16(), text));
    }
    if response
        .content_length()
        .is_some_and(|size| size != attachment.size || size > MAX_ATTACHMENT_BYTES as u64)
    {
        return Err(NtfyError::AttachmentSizeMismatch);
    }
    let mut bytes = Vec::with_capacity(attachment.size as usize);
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_ATTACHMENT_BYTES {
            return Err(NtfyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() as u64 != attachment.size {
        return Err(NtfyError::AttachmentSizeMismatch);
    }
    Ok(bytes)
}

fn validate_attachment_url(base: &str, attachment: &str) -> Result<(), NtfyError> {
    let base = reqwest::Url::parse(base).map_err(|_| NtfyError::UnsafeAttachmentUrl)?;
    let attachment = reqwest::Url::parse(attachment).map_err(|_| NtfyError::UnsafeAttachmentUrl)?;
    let same_origin = attachment.scheme() == "https"
        && attachment.host_str() == base.host_str()
        && attachment.port_or_known_default() == base.port_or_known_default()
        && attachment.username().is_empty()
        && attachment.password().is_none();
    if !same_origin || !attachment.path().starts_with("/file/") {
        return Err(NtfyError::UnsafeAttachmentUrl);
    }
    Ok(())
}

fn build_publish_request(
    client: &reqwest::Client,
    url: &str,
    b64: String,
    options: PublishOptions,
) -> Result<reqwest::Request, reqwest::Error> {
    let mut request = client.post(url).header("Content-Type", "text/plain");
    if options.cache == RelayCache::NoStore {
        request = request.header("Cache", "no");
    }
    request.body(b64).build()
}

/// Configuration for a subscription.
pub struct SubscribeConfig {
    pub base: String,
    pub topic: String,
    /// Last seen message id, for `since=` catch-up on reconnect.
    pub since: Option<String>,
}

/// Spawn a subscriber task. It connects via WSS, decodes incoming messages, and
/// sends them on `out`. On disconnect it reconnects with backoff, resuming from
/// the last id it delivered. Cancellation: drop the returned handle / the
/// `shutdown` receiver.
///
/// Returns the join handle. The task runs until `shutdown` is signaled.
pub fn spawn_subscriber(
    cfg: SubscribeConfig,
    out: mpsc::Sender<RelayMessage>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    ensure_rustls_crypto_provider();
    tokio::spawn(async move {
        let https_base = match require_tls_base(&cfg.base) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ntfy subscribe aborting: {e}");
                let _ = out
                    .send(RelayMessage {
                        id: String::new(),
                        payload: Vec::new(),
                        time_ms: 0,
                        attachment: None,
                    })
                    .await; // sentinel: empty payload signals fatal error
                return;
            }
        };

        let mut last_id: Option<String> = cfg.since.clone();
        let mut backoff = Duration::from_secs(1);

        loop {
            let url = ws_url(&https_base, &cfg.topic, last_id.as_deref());
            eprintln!("[ntfy] connecting to relay (topic hidden)…");
            let stream = tokio::select! {
                _ = &mut shutdown => return,
                stream = tokio_tungstenite::connect_async(&url) => stream,
            };
            match stream {
                Ok((mut ws, _)) => {
                    eprintln!("[ntfy] WebSocket connected, listening for messages");
                    backoff = Duration::from_secs(1); // reset on success
                    loop {
                        let msg_result = tokio::select! {
                            _ = &mut shutdown => {
                                let _ = ws.close(None).await;
                                eprintln!("[ntfy] subscriber shutting down");
                                return;
                            }
                            msg = ws.next() => msg,
                        };
                        let Some(msg_result) = msg_result else {
                            break;
                        };
                        let msg = match msg_result {
                            Ok(m) => m,
                            Err(e) => {
                                eprintln!("[ntfy] ws read error: {e}");
                                break;
                            }
                        };
                        if let Ok(text) = msg.into_text() {
                            let is_idle_event = text.contains(r#""event":"open""#)
                                || text.contains(r#""event":"keepalive""#);
                            if !is_idle_event {
                                match serde_json::from_str::<NtfyJson>(&text) {
                                    Ok(parsed) => eprintln!(
                                        "[ntfy] received event={} id={} message_bytes={}",
                                        parsed.event.as_deref().unwrap_or("message"),
                                        parsed.id.as_deref().unwrap_or("<none>"),
                                        parsed.message.as_ref().map(|m| m.len()).unwrap_or(0)
                                    ),
                                    Err(_) => eprintln!(
                                        "[ntfy] received non-json websocket message ({} bytes)",
                                        text.len()
                                    ),
                                }
                            }
                            if let Some(rm) = decode_ntfy_json(&text) {
                                eprintln!(
                                    "[ntfy] decoded message, {} bytes payload",
                                    rm.payload.len()
                                );
                                last_id = Some(rm.id.clone());
                                tokio::select! {
                                    _ = &mut shutdown => {
                                        let _ = ws.close(None).await;
                                        eprintln!("[ntfy] subscriber shutting down");
                                        return;
                                    }
                                    result = out.send(rm) => {
                                        if result.is_err() {
                                            eprintln!("[ntfy] consumer gone, stopping");
                                            return; // consumer gone
                                        }
                                    }
                                }
                            }
                        }
                    }
                    eprintln!("[ntfy] stream ended, reconnecting…");
                    // stream ended; fall through to reconnect
                }
                Err(e) => {
                    eprintln!("[ntfy] ws connect failed: {e}");
                }
            }

            // Reconnect with backoff, unless shutting down.
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    })
}

/// Decode one ntfy JSON line into a RelayMessage, or None if it's not a
/// message event (e.g. open/keepalive).
fn decode_ntfy_json(line: &str) -> Option<RelayMessage> {
    let parsed: NtfyJson = serde_json::from_str(line).ok()?;
    // ntfy sends `event: "open"` / `"keepalive"` on the WS stream; ignore those.
    if matches!(
        parsed.event.as_deref(),
        Some("open") | Some("keepalive") | Some("poll_request")
    ) {
        return None;
    }
    let msg = parsed.message?;
    if msg.len() > MAX_BODY_BYTES {
        eprintln!("ntfy: skipping oversized message body");
        return None;
    }
    let id = parsed.id.unwrap_or_default();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&msg)
        .map_err(|e| eprintln!("ntfy: skipping non-base64 message: {e}"))
        .ok()?;
    if payload.is_empty() {
        return None;
    }
    let attachment = parsed.attachment.and_then(|attachment| {
        attachment.size.map(|size| RelayAttachment {
            url: attachment.url,
            size,
        })
    });
    Some(RelayMessage {
        id,
        payload,
        time_ms: parsed.time.unwrap_or(0),
        attachment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_insecure_base() {
        assert!(matches!(
            require_tls_base("http://ntfy.sh"),
            Err(NtfyError::InsecureBase(_))
        ));
        assert!(matches!(
            require_tls_base("ws://ntfy.sh"),
            Err(NtfyError::InsecureBase(_))
        ));
    }

    #[test]
    fn accepts_https_and_wss() {
        assert_eq!(
            require_tls_base("https://ntfy.sh").unwrap(),
            "https://ntfy.sh"
        );
        assert_eq!(
            require_tls_base("wss://ntfy.sh").unwrap(),
            "https://ntfy.sh"
        );
        assert_eq!(require_tls_base("ntfy.sh").unwrap(), "https://ntfy.sh");
        // trailing slash stripped
        assert_eq!(
            require_tls_base("https://ntfy.sh/").unwrap(),
            "https://ntfy.sh"
        );
    }

    #[test]
    fn ws_url_includes_since() {
        let url = ws_url("https://ntfy.sh", "mytopic", Some("abc123"));
        assert_eq!(url, "wss://ntfy.sh/mytopic/ws?since=abc123");
    }

    #[test]
    fn ws_url_without_since() {
        let url = ws_url("https://ntfy.sh", "mytopic", None);
        assert_eq!(url, "wss://ntfy.sh/mytopic/ws");
    }

    #[test]
    fn decode_ignores_keepalive() {
        assert!(decode_ntfy_json(r#"{"event":"keepalive"}"#).is_none());
        assert!(decode_ntfy_json(r#"{"event":"open"}"#).is_none());
    }

    #[test]
    fn decode_extracts_base64_payload() {
        // base64 of "hello"
        let line = r#"{"id":"msg1","message":"aGVsbG8=","time":12345}"#;
        let rm = decode_ntfy_json(line).unwrap();
        assert_eq!(rm.id, "msg1");
        assert_eq!(rm.payload, b"hello");
        assert_eq!(rm.time_ms, 12345);
        assert!(rm.attachment.is_none());
    }

    #[test]
    fn decode_extracts_uploaded_attachment_metadata() {
        let line = r#"{
            "id":"msg2",
            "message":"aGVsbG8=",
            "attachment":{"url":"https://ntfy.sh/file/msg2.clip","size":1234}
        }"#;
        let rm = decode_ntfy_json(line).unwrap();
        let attachment = rm.attachment.unwrap();

        assert_eq!(attachment.url, "https://ntfy.sh/file/msg2.clip");
        assert_eq!(attachment.size, 1234);
    }

    #[test]
    fn decode_skips_non_base64() {
        let line = r#"{"id":"msg1","message":"!!!not-base64!!!","time":1}"#;
        assert!(decode_ntfy_json(line).is_none());
    }

    #[test]
    fn publish_request_defaults_to_relay_cache() {
        let client = reqwest::Client::new();
        let request = build_publish_request(
            &client,
            "https://ntfy.sh/topic",
            "payload".to_string(),
            PublishOptions::default(),
        )
        .unwrap();

        assert!(request.headers().get("Cache").is_none());
    }

    #[test]
    fn publish_request_can_disable_relay_cache() {
        let client = reqwest::Client::new();
        let request = build_publish_request(
            &client,
            "https://ntfy.sh/topic",
            "payload".to_string(),
            PublishOptions::no_cache(),
        )
        .unwrap();

        assert_eq!(request.headers().get("Cache").unwrap(), "no");
    }

    #[test]
    fn attachment_request_carries_notice_and_binary_body() {
        let client = reqwest::Client::new();
        let request = build_attachment_request(
            &client,
            "https://ntfy.sh/topic",
            "bm90aWNl".to_string(),
            vec![1, 2, 3],
            PublishOptions::default(),
        )
        .unwrap();

        assert_eq!(request.headers().get("X-Message").unwrap(), "bm90aWNl");
        assert_eq!(request.headers().get("X-Filename").unwrap(), "fwoosh.clip");
        assert_eq!(
            request.body().and_then(reqwest::Body::as_bytes),
            Some(&[1, 2, 3][..])
        );
    }

    #[test]
    fn attachment_url_must_be_on_the_configured_relay() {
        assert!(
            validate_attachment_url("https://ntfy.sh", "https://ntfy.sh/file/message.clip").is_ok()
        );
        assert!(validate_attachment_url(
            "https://ntfy.sh",
            "https://example.com/file/message.clip"
        )
        .is_err());
        assert!(validate_attachment_url("https://ntfy.sh", "https://ntfy.sh/admin").is_err());
    }
}
