//! Bounded observation of the official Protect WebSocket subscriptions.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{StatusCode, header};
use tokio::time::{Instant, timeout_at};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Error, Message,
        handshake::{client::generate_key, derive_accept_key},
        protocol::{Role, WebSocketConfig},
    },
};

use super::{ApiError, BoundedMessage, ProtectClient, http};

/// The fixed Protect subscription resources.
#[derive(Debug, Clone, Copy)]
pub enum ProtectSubscriptionSource {
    Devices,
    Events,
}

/// Why one finite observation ended. Limits never imply stream exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectSubscriptionEnd {
    WindowComplete,
    MessageLimit,
    ByteLimit,
    Closed,
    Failed,
}

/// One complete upstream application message, without JSON interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectSubscriptionMessage {
    Text(String),
    Binary(Vec<u8>),
}

/// Collected messages and the complete termination detail available so far.
#[derive(Debug)]
pub struct ProtectSubscriptionBatch {
    pub messages: Vec<ProtectSubscriptionMessage>,
    pub end: ProtectSubscriptionEnd,
    pub received_bytes: usize,
    /// Present when a complete received message did not fit the batch bound.
    pub omitted_message_bytes: Option<usize>,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub error: Option<BoundedMessage>,
}

impl ProtectClient {
    /// Observe device or event updates for a finite window, including connection
    /// setup. Text and binary messages remain complete within the byte bound.
    /// Quiet supported streams differ from unsupported HTTP routes and failures.
    ///
    /// # Errors
    /// Returns the complete bounded upstream HTTP rejection or the connection
    /// diagnostic when a subscription cannot be established. Stream failures
    /// retain already collected messages in the returned batch.
    pub async fn observe_updates(
        &self,
        source: ProtectSubscriptionSource,
        duration: Duration,
        max_messages: u16,
        max_bytes: usize,
    ) -> Result<ProtectSubscriptionBatch, ApiError> {
        if duration.is_zero()
            || duration > Duration::from_secs(20)
            || !(1..=200).contains(&max_messages)
            || !(1..=http::MAXIMUM_RESPONSE_BYTES).contains(&max_bytes)
        {
            return Err(ApiError::Config("subscription duration must be positive and at most 20 seconds, maxMessages 1-200, and maxBytes 1-4194304".to_owned()));
        }
        let deadline = Instant::now() + duration;
        let socket = timeout_at(deadline, self.subscription_socket(source, max_bytes))
            .await
            .map_err(|_| {
                ApiError::Transport(BoundedMessage::new(
                    "subscription connection exceeded the requested observation window",
                ))
            })??;
        let mut socket = socket;
        let mut batch = ProtectSubscriptionBatch {
            messages: Vec::new(),
            end: ProtectSubscriptionEnd::WindowComplete,
            received_bytes: 0,
            omitted_message_bytes: None,
            close_code: None,
            close_reason: None,
            error: None,
        };
        loop {
            let message = match timeout_at(deadline, socket.next()).await {
                Err(_) => break,
                Ok(None) => {
                    batch.end = ProtectSubscriptionEnd::Closed;
                    break;
                }
                Ok(Some(Err(error))) => {
                    batch.end = if matches!(error, Error::Capacity(_)) {
                        ProtectSubscriptionEnd::ByteLimit
                    } else {
                        ProtectSubscriptionEnd::Failed
                    };
                    batch.error = Some(BoundedMessage::new(&error.to_string()));
                    break;
                }
                Ok(Some(Ok(message))) => message,
            };
            let (message, bytes) = match message {
                Message::Text(text) => {
                    let bytes = text.len();
                    (ProtectSubscriptionMessage::Text(text.to_string()), bytes)
                }
                Message::Binary(bytes) => {
                    let length = bytes.len();
                    (ProtectSubscriptionMessage::Binary(bytes.to_vec()), length)
                }
                Message::Close(frame) => {
                    batch.end = ProtectSubscriptionEnd::Closed;
                    if let Some(frame) = frame {
                        batch.close_code = Some(frame.code.into());
                        batch.close_reason = Some(frame.reason.to_string());
                    }
                    break;
                }
                Message::Ping(_) => {
                    // Tungstenite queues the protocol pong; flush it within the
                    // same observation deadline rather than postponing it.
                    match timeout_at(deadline, socket.flush()).await {
                        Err(_) => break,
                        Ok(Err(error)) => {
                            batch.end = ProtectSubscriptionEnd::Failed;
                            batch.error = Some(BoundedMessage::new(&error.to_string()));
                            break;
                        }
                        Ok(Ok(())) => continue,
                    }
                }
                Message::Pong(_) => continue,
                Message::Frame(_) => {
                    unreachable!("tungstenite does not expose raw frames while reading")
                }
            };
            if bytes > max_bytes - batch.received_bytes {
                batch.end = ProtectSubscriptionEnd::ByteLimit;
                batch.omitted_message_bytes = Some(bytes);
                batch.error = Some(BoundedMessage::new(
                    "the next complete upstream message exceeds the remaining subscription byte budget",
                ));
                break;
            }
            batch.received_bytes += bytes;
            batch.messages.push(message);
            if batch.messages.len() == usize::from(max_messages) {
                batch.end = ProtectSubscriptionEnd::MessageLimit;
                break;
            }
            if batch.received_bytes == max_bytes {
                batch.end = ProtectSubscriptionEnd::ByteLimit;
                break;
            }
        }
        Ok(batch)
    }

    async fn subscription_socket(
        &self,
        source: ProtectSubscriptionSource,
        max_bytes: usize,
    ) -> Result<WebSocketStream<reqwest::Upgraded>, ApiError> {
        let route = match source {
            ProtectSubscriptionSource::Devices => "devices",
            ProtectSubscriptionSource::Events => "events",
        };
        let key = generate_key();
        let response = self
            .request(reqwest::Method::GET, &["subscribe", route])?
            .version(reqwest::Version::HTTP_11)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", &key)
            .send()
            .await
            .map_err(|error| {
                ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
            })?;
        let status = response.status();
        if status != StatusCode::SWITCHING_PROTOCOLS {
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(http::rate_limited(response).await?);
            }
            let body = http::read_bounded_body(response).await?;
            return Err(ApiError::Status {
                status: status.as_u16(),
                message: BoundedMessage::from_controller_bytes(&body),
            });
        }
        let valid_token = |name: header::HeaderName, expected: &str| {
            response
                .headers()
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        };
        if !valid_token(header::CONNECTION, "upgrade")
            || !valid_token(header::UPGRADE, "websocket")
            || response
                .headers()
                .get("Sec-WebSocket-Accept")
                .and_then(|value| value.to_str().ok())
                != Some(derive_accept_key(key.as_bytes()).as_str())
        {
            return Err(ApiError::Transport(BoundedMessage::new(
                "upstream WebSocket upgrade headers failed protocol validation",
            )));
        }
        // Upgrade the existing HTTP client's connection so certificate roots,
        // pins, redirects, credentials, and console origin remain identical.
        let stream = response.upgrade().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        let config = WebSocketConfig::default()
            .read_buffer_size(4096)
            .write_buffer_size(0)
            .max_write_buffer_size(4096)
            .max_message_size(Some(max_bytes))
            .max_frame_size(Some(max_bytes.max(125)));
        Ok(WebSocketStream::from_raw_socket(stream, Role::Client, Some(config)).await)
    }
}
