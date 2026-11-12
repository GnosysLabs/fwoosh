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
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::tungstenite::{self, Message};

/// Default public relay. Zero infra cost for the user.
pub const DEFAULT_BASE: &str = "https://ntfy.sh";

/// Cap a single message body well under ntfy's 4096-byte attachment threshold
/// (after base64 expansion). See crypto::CHUNK_SIZE for the plaintext cap.
pub const MAX_BODY_BYTES: usize = 3500;
/// Fwoosh's encrypted attachment ceiling. This leaves ample room below the
/// public ntfy.sh 2 MB limit for a 1 MiB text clip plus framing overhead.
pub const MAX_ATTACHMENT_BYTES: usize = 1_500_000;

const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Live status transitions emitted by a subscriber task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriberStatusEvent {
    Connecting,
    Connected,
    Healthy,
    Reconnecting(String),
}

#[derive(Clone, Copy)]
struct WsHealthTimeouts {
    ping_interval: Duration,
    idle_timeout: Duration,
    watchdog_tick: Duration,
    write_timeout: Duration,
    probe_timeout: Duration,
    sleep_jump_threshold: Duration,
}

impl Default for WsHealthTimeouts {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(75),
            watchdog_tick: Duration::from_secs(15),
            write_timeout: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            sleep_jump_threshold: Duration::from_secs(45),
        }
    }
}

#[derive(Debug)]
enum StreamPumpOutcome {
    Shutdown,
    ConsumerGone,
    Disconnected(String),
}

/// Verify that the configured relay is reachable without publishing a topic
/// message. Returns the round-trip latency of the relay health endpoint.
pub async fn diagnose_relay(base: &str) -> Result<u64, NtfyError> {
    ensure_rustls_crypto_provider();
    let https_base = require_tls_base(base)?;
    let url = format!("{https_base}/v1/health");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
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
        .connect_timeout(Duration::from_secs(10))
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
        .connect_timeout(Duration::from_secs(10))
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
        .connect_timeout(Duration::from_secs(10))
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
    /// Optional channel for reporting live subscriber health to the app.
    pub status_tx: Option<mpsc::UnboundedSender<SubscriberStatusEvent>>,
    /// Optional wakeup handle used to interrupt backoff or probe a potentially
    /// stale socket when the user wakes/reveals the app or sends a clip.
    pub reconnect_notify: Option<Arc<Notify>>,
}

fn emit_subscriber_status(
    status_tx: &Option<mpsc::UnboundedSender<SubscriberStatusEvent>>,
    event: SubscriberStatusEvent,
) {
    if let Some(tx) = status_tx {
        let _ = tx.send(event);
    }
}

fn is_bad_request_ws_error(err: &tungstenite::Error) -> bool {
    matches!(err, tungstenite::Error::Http(resp) if resp.status().as_u16() == 400)
}

fn friendly_ws_error(err: &tungstenite::Error) -> String {
    match err {
        tungstenite::Error::Http(resp) => {
            format!(
                "Relay returned HTTP {} while connecting",
                resp.status().as_u16()
            )
        }
        tungstenite::Error::Io(io_err) => {
            format!("Network error connecting to relay ({io_err})")
        }
        tungstenite::Error::Tls(tls_err) => {
            format!("TLS error connecting to relay ({tls_err})")
        }
        other => format!("Relay connection error ({other})"),
    }
}

async fn pump_ws_stream<S>(
    ws: &mut S,
    out: &mpsc::Sender<RelayMessage>,
    shutdown: &mut tokio::sync::oneshot::Receiver<()>,
    last_id: &mut Option<String>,
    received_any_frame: &mut bool,
    status_tx: &Option<mpsc::UnboundedSender<SubscriberStatusEvent>>,
    reconnect_notify: &Option<Arc<Notify>>,
    timeouts: WsHealthTimeouts,
) -> StreamPumpOutcome
where
    S: Stream<Item = Result<Message, tungstenite::Error>>
        + Sink<Message, Error = tungstenite::Error>
        + Unpin,
{
    let mut last_inbound = tokio::time::Instant::now();
    let mut probe_deadline: Option<tokio::time::Instant> = None;
    let mut reported_healthy = false;
    let mut last_wall_clock = std::time::SystemTime::now();

    let mut ping_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + timeouts.ping_interval,
        timeouts.ping_interval,
    );
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut watchdog_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + timeouts.watchdog_tick,
        timeouts.watchdog_tick,
    );
    watchdog_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut *shutdown => {
                let _ = tokio::time::timeout(Duration::from_secs(2), ws.close()).await;
                eprintln!("[ntfy] subscriber shutting down");
                return StreamPumpOutcome::Shutdown;
            }
            _ = async {
                match reconnect_notify {
                    Some(notify) => notify.notified().await,
                    None => std::future::pending().await,
                }
            } => {
                let now_wall = std::time::SystemTime::now();
                if let Ok(wall_elapsed) = now_wall.duration_since(last_wall_clock) {
                    if wall_elapsed > timeouts.sleep_jump_threshold {
                        eprintln!(
                            "[ntfy] system clock jumped by {}s on wake nudge, reconnecting…",
                            wall_elapsed.as_secs()
                        );
                        return StreamPumpOutcome::Disconnected(
                            "System woke from sleep — refreshing relay connection".to_string(),
                        );
                    }
                }
                last_wall_clock = now_wall;

                match tokio::time::timeout(
                    timeouts.write_timeout,
                    ws.send(Message::Ping(Default::default())),
                )
                .await
                {
                    Ok(Ok(())) => {
                        if probe_deadline.is_none() {
                            probe_deadline =
                                Some(tokio::time::Instant::now() + timeouts.probe_timeout);
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("[ntfy] ws probe ping error: {e}");
                        return StreamPumpOutcome::Disconnected(
                            "Relay socket closed — reconnecting".to_string(),
                        );
                    }
                    Err(_) => {
                        eprintln!("[ntfy] ws probe ping write timed out");
                        return StreamPumpOutcome::Disconnected(
                            "Relay socket stopped responding — reconnecting".to_string(),
                        );
                    }
                }
            }
            _ = async {
                match probe_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                eprintln!("[ntfy] relay did not answer liveness ping in time, reconnecting…");
                return StreamPumpOutcome::Disconnected(
                    "Relay connection stopped responding — reconnecting".to_string(),
                );
            }
            _ = ping_ticker.tick() => {
                match tokio::time::timeout(
                    timeouts.write_timeout,
                    ws.send(Message::Ping(Default::default())),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        eprintln!("[ntfy] ws keepalive ping error: {e}");
                        return StreamPumpOutcome::Disconnected(
                            "Relay keepalive failed — reconnecting".to_string(),
                        );
                    }
                    Err(_) => {
                        eprintln!("[ntfy] ws keepalive ping timed out");
                        return StreamPumpOutcome::Disconnected(
                            "Relay keepalive timed out — reconnecting".to_string(),
                        );
                    }
                }
            }
            _ = watchdog_ticker.tick() => {
                let now_wall = std::time::SystemTime::now();
                if let Ok(wall_elapsed) = now_wall.duration_since(last_wall_clock) {
                    if wall_elapsed > timeouts.sleep_jump_threshold {
                        eprintln!(
                            "[ntfy] system clock jumped by {}s (sleep/wake detected), reconnecting…",
                            wall_elapsed.as_secs()
                        );
                        return StreamPumpOutcome::Disconnected(
                            "System woke from sleep — reconnecting to relay".to_string(),
                        );
                    }
                }
                last_wall_clock = now_wall;

                if last_inbound.elapsed() >= timeouts.idle_timeout {
                    eprintln!(
                        "[ntfy] no inbound traffic or keepalive for {}s, reconnecting…",
                        last_inbound.elapsed().as_secs()
                    );
                    return StreamPumpOutcome::Disconnected(
                        "Relay keepalive timed out — reconnecting".to_string(),
                    );
                }
            }
            msg_result = ws.next() => {
                let Some(msg_result) = msg_result else {
                    return StreamPumpOutcome::Disconnected(
                        "Relay stream closed — reconnecting".to_string(),
                    );
                };
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[ntfy] ws read error: {e}");
                        return StreamPumpOutcome::Disconnected(friendly_ws_error(&e));
                    }
                };

                last_inbound = tokio::time::Instant::now();
                probe_deadline = None;
                last_wall_clock = std::time::SystemTime::now();
                *received_any_frame = true;
                if !reported_healthy {
                    reported_healthy = true;
                    emit_subscriber_status(status_tx, SubscriberStatusEvent::Healthy);
                }

                match msg {
                    Message::Text(text) => {
                        let text_str: &str = &text;
                        let is_idle_event = text_str.contains(r#""event":"open""#)
                            || text_str.contains(r#""event":"keepalive""#);
                        if !is_idle_event {
                            match serde_json::from_str::<NtfyJson>(text_str) {
                                Ok(parsed) => eprintln!(
                                    "[ntfy] received event={} id={} message_bytes={}",
                                    parsed.event.as_deref().unwrap_or("message"),
                                    parsed.id.as_deref().unwrap_or("<none>"),
                                    parsed.message.as_ref().map(|m| m.len()).unwrap_or(0)
                                ),
                                Err(_) => eprintln!(
                                    "[ntfy] received non-json websocket message ({} bytes)",
                                    text_str.len()
                                ),
                            }
                        }
                        if let Some(rm) = decode_ntfy_json(text_str) {
                            eprintln!(
                                "[ntfy] decoded message, {} bytes payload",
                                rm.payload.len()
                            );
                            if !rm.id.is_empty() {
                                *last_id = Some(rm.id.clone());
                            }
                            tokio::select! {
                                _ = &mut *shutdown => {
                                    let _ = tokio::time::timeout(
                                        Duration::from_secs(2),
                                        ws.close(),
                                    )
                                    .await;
                                    eprintln!("[ntfy] subscriber shutting down");
                                    return StreamPumpOutcome::Shutdown;
                                }
                                result = out.send(rm) => {
                                    if result.is_err() {
                                        eprintln!("[ntfy] consumer gone, stopping");
                                        return StreamPumpOutcome::ConsumerGone;
                                    }
                                }
                            }
                        }
                    }
                    Message::Ping(payload) => {
                        match tokio::time::timeout(
                            timeouts.write_timeout,
                            ws.send(Message::Pong(payload)),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                eprintln!("[ntfy] ws pong write error: {e}");
                                return StreamPumpOutcome::Disconnected(
                                    "Relay pong failed — reconnecting".to_string(),
                                );
                            }
                            Err(_) => {
                                eprintln!("[ntfy] ws pong write timed out");
                                return StreamPumpOutcome::Disconnected(
                                    "Relay pong timed out — reconnecting".to_string(),
                                );
                            }
                        }
                    }
                    Message::Close(_) => {
                        return StreamPumpOutcome::Disconnected(
                            "Relay closed connection — reconnecting".to_string(),
                        );
                    }
                    Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
                }
            }
        }
    }
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
                emit_subscriber_status(
                    &cfg.status_tx,
                    SubscriberStatusEvent::Reconnecting(e.to_string()),
                );
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
            emit_subscriber_status(&cfg.status_tx, SubscriberStatusEvent::Connecting);

            let connect_attempt = tokio::select! {
                _ = &mut shutdown => return,
                res = tokio::time::timeout(
                    WS_CONNECT_TIMEOUT,
                    tokio_tungstenite::connect_async(&url),
                ) => res,
            };

            let sleep_for = match connect_attempt {
                Ok(Ok((mut ws, _))) => {
                    eprintln!("[ntfy] WebSocket connected, listening for messages");
                    emit_subscriber_status(&cfg.status_tx, SubscriberStatusEvent::Connected);
                    let mut received_any_frame = false;
                    let outcome = pump_ws_stream(
                        &mut ws,
                        &out,
                        &mut shutdown,
                        &mut last_id,
                        &mut received_any_frame,
                        &cfg.status_tx,
                        &cfg.reconnect_notify,
                        WsHealthTimeouts::default(),
                    )
                    .await;
                    match outcome {
                        StreamPumpOutcome::Shutdown | StreamPumpOutcome::ConsumerGone => return,
                        StreamPumpOutcome::Disconnected(reason) => {
                            eprintln!("[ntfy] stream ended ({reason}), reconnecting…");
                            emit_subscriber_status(
                                &cfg.status_tx,
                                SubscriberStatusEvent::Reconnecting(reason),
                            );
                            if received_any_frame {
                                backoff = Duration::from_secs(1);
                                Duration::from_millis(250)
                            } else {
                                let wait = backoff;
                                backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
                                wait
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("[ntfy] ws connect failed: {e}");
                    if is_bad_request_ws_error(&e) && last_id.is_some() {
                        eprintln!(
                            "[ntfy] relay rejected since cursor with HTTP 400; resetting cursor"
                        );
                        last_id = None;
                    }
                    emit_subscriber_status(
                        &cfg.status_tx,
                        SubscriberStatusEvent::Reconnecting(friendly_ws_error(&e)),
                    );
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
                    wait
                }
                Err(_) => {
                    eprintln!(
                        "[ntfy] ws connect timed out after {}s",
                        WS_CONNECT_TIMEOUT.as_secs()
                    );
                    emit_subscriber_status(
                        &cfg.status_tx,
                        SubscriberStatusEvent::Reconnecting(
                            "Connection to relay timed out — retrying".to_string(),
                        ),
                    );
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
                    wait
                }
            };

            // Reconnect with backoff, unless shutting down or woken early.
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(sleep_for) => {}
                _ = async {
                    match &cfg.reconnect_notify {
                        Some(notify) => notify.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    backoff = Duration::from_secs(1);
                }
            }
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

    async fn duplex_ws_pair() -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_fut = tokio_tungstenite::client_async("ws://localhost/test/ws", client_io);
        let server_fut = tokio_tungstenite::accept_async(server_io);
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        (client_res.unwrap().0, server_res.unwrap())
    }

    #[tokio::test]
    async fn stream_pump_reconnects_when_keepalive_stalls() {
        let (mut client_ws, mut server_ws) = duplex_ws_pair().await;
        // Send initial open frame, then stop reading/responding completely to simulate
        // a half-open zombie socket after NAT idle drop.
        server_ws
            .send(Message::Text(r#"{"event":"open"}"#.into()))
            .await
            .unwrap();

        let (out_tx, _out_rx) = mpsc::channel(8);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let (status_tx, mut status_rx) = mpsc::unbounded_channel();
        let mut last_id = None;
        let mut received_any_frame = false;

        let timeouts = WsHealthTimeouts {
            ping_interval: Duration::from_millis(30),
            idle_timeout: Duration::from_millis(90),
            watchdog_tick: Duration::from_millis(25),
            write_timeout: Duration::from_millis(50),
            probe_timeout: Duration::from_millis(50),
            sleep_jump_threshold: Duration::from_secs(45),
        };

        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            pump_ws_stream(
                &mut client_ws,
                &out_tx,
                &mut shutdown_rx,
                &mut last_id,
                &mut received_any_frame,
                &Some(status_tx),
                &None,
                timeouts,
            ),
        )
        .await
        .expect("watchdog should break stalled stream");

        assert!(received_any_frame);
        assert!(matches!(outcome, StreamPumpOutcome::Disconnected(_)));
        assert_eq!(
            status_rx.try_recv().ok(),
            Some(SubscriberStatusEvent::Healthy)
        );
        drop(server_ws);
    }

    #[tokio::test]
    async fn stream_pump_stays_alive_on_pong_and_delivers_messages() {
        let (mut client_ws, mut server_ws) = duplex_ws_pair().await;
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let (status_tx, mut status_rx) = mpsc::unbounded_channel();
        let mut last_id = None;
        let mut received_any_frame = false;

        let server_task = tokio::spawn(async move {
            server_ws
                .send(Message::Text(r#"{"event":"open"}"#.into()))
                .await
                .unwrap();
            // Answer two client pings with Pong across >2x idle_timeout, then deliver a message.
            let mut pongs = 0;
            while pongs < 2 {
                if let Some(Ok(Message::Ping(payload))) = server_ws.next().await {
                    server_ws.send(Message::Pong(payload)).await.unwrap();
                    pongs += 1;
                }
            }
            server_ws
                .send(Message::Text(
                    r#"{"id":"cursor42","message":"aGVsbG8=","time":99}"#.into(),
                ))
                .await
                .unwrap();
            // Keep socket alive until client shuts down cleanly.
            while let Some(Ok(_)) = server_ws.next().await {}
        });

        let timeouts = WsHealthTimeouts {
            ping_interval: Duration::from_millis(35),
            idle_timeout: Duration::from_millis(90),
            watchdog_tick: Duration::from_millis(25),
            write_timeout: Duration::from_millis(50),
            probe_timeout: Duration::from_millis(50),
            sleep_jump_threshold: Duration::from_secs(45),
        };

        let pump = tokio::spawn(async move {
            pump_ws_stream(
                &mut client_ws,
                &out_tx,
                &mut shutdown_rx,
                &mut last_id,
                &mut received_any_frame,
                &Some(status_tx),
                &None,
                timeouts,
            )
            .await;
            last_id
        });

        let delivered = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("message should arrive")
            .expect("channel open");
        assert_eq!(delivered.id, "cursor42");
        assert_eq!(delivered.payload, b"hello");
        assert_eq!(
            status_rx.try_recv().ok(),
            Some(SubscriberStatusEvent::Healthy)
        );

        let _ = shutdown_tx.send(());
        let final_cursor = pump.await.unwrap();
        assert_eq!(final_cursor.as_deref(), Some("cursor42"));
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn stream_pump_nudge_detects_half_open_socket() {
        let (mut client_ws, _server_ws) = duplex_ws_pair().await;
        let (out_tx, _out_rx) = mpsc::channel(8);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let notify = Arc::new(Notify::new());
        let mut last_id = None;
        let mut received_any_frame = false;

        let timeouts = WsHealthTimeouts {
            ping_interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            watchdog_tick: Duration::from_secs(60),
            write_timeout: Duration::from_millis(50),
            probe_timeout: Duration::from_millis(60),
            sleep_jump_threshold: Duration::from_secs(45),
        };

        let notify_clone = notify.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            notify_clone.notify_waiters();
        });

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            pump_ws_stream(
                &mut client_ws,
                &out_tx,
                &mut shutdown_rx,
                &mut last_id,
                &mut received_any_frame,
                &None,
                &Some(notify),
                timeouts,
            ),
        )
        .await
        .expect("probe deadline should fire promptly on silent half-open peer");

        assert!(matches!(outcome, StreamPumpOutcome::Disconnected(_)));
    }
}
