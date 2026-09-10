use std::time::Duration;

use thiserror::Error;

/// Longest upstream-derived detail carried by any error variant.
const MAXIMUM_MESSAGE_BYTES: usize = 512;

/// An upstream-derived message that is bounded and control-character free by
/// construction. Every construction path runs the sanitizer, so no error
/// variant can carry raw upstream detail regardless of who builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedMessage(String);

impl BoundedMessage {
    /// Sanitize one message: drop control characters, then truncate on a
    /// character boundary within the byte budget so a multi-byte message can
    /// never split mid-character.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let mut message = String::new();
        for character in raw.chars().filter(|value| !value.is_control()) {
            if message.len() + character.len_utf8() > MAXIMUM_MESSAGE_BYTES {
                break;
            }
            message.push(character);
        }
        Self(message)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BoundedMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for BoundedMessage {
    fn from(raw: &str) -> Self {
        Self::new(raw)
    }
}

impl From<String> for BoundedMessage {
    fn from(raw: String) -> Self {
        Self::new(&raw)
    }
}

/// A failure talking to a controller. Upstream-derived detail always travels
/// as a [`BoundedMessage`], so it is bounded and stripped of control
/// characters before it can reach a caller; credentials never appear in any
/// variant.
#[derive(Debug, Clone, Error)]
pub enum ApiError {
    /// Locally produced configuration diagnostics; carries no upstream data.
    #[error("invalid controller configuration: {0}")]
    Config(String),
    /// The controller answered with a non-success status. `message` is a
    /// bounded extract of the upstream error body, never the raw payload.
    #[error("controller returned HTTP {status}: {message}")]
    Status {
        status: u16,
        message: BoundedMessage,
    },
    /// The controller rate limited the request and the client did not (or
    /// must not) retry it.
    #[error("controller rate limited the request")]
    RateLimited { retry_after: Option<Duration> },
    /// The legacy controller API accepted the transport but rejected the
    /// operation with one of its `api.err.*` codes. `code` is the upstream
    /// token; `message` is actionable guidance for the caller.
    #[error("controller rejected the request ({code}): {message}")]
    Rejected {
        code: BoundedMessage,
        message: BoundedMessage,
    },
    #[error("transport failure: {0}")]
    Transport(BoundedMessage),
    /// A successful response exceeded the process-wide response body budget.
    #[error("controller response exceeded the {limit}-byte budget")]
    ResponseTooLarge { limit: usize },
    /// A successful response was not syntactically valid JSON. Only its
    /// location is retained; the parser's text can contain controller values.
    #[error("invalid JSON from {endpoint} at line {line}, column {column}")]
    InvalidJson {
        endpoint: &'static str,
        line: usize,
        column: usize,
    },
    /// Valid JSON did not match the endpoint's typed wire contract. The path
    /// names fields only and never retains the rejected value.
    #[error("response from {endpoint} did not match its schema at {path}")]
    SchemaMismatch {
        endpoint: &'static str,
        path: BoundedMessage,
    },
    #[error("response decoding failed: {0}")]
    Decode(BoundedMessage),
}

#[cfg(test)]
mod tests {
    use super::BoundedMessage;

    #[test]
    fn bounding_respects_character_boundaries_under_the_byte_budget() {
        let bounded = BoundedMessage::new(&"é".repeat(600));
        assert!(bounded.as_str().len() <= 512);
        assert_eq!(bounded.as_str().len(), 512);
        assert!(bounded.as_str().chars().all(|character| character == 'é'));
    }

    #[test]
    fn control_characters_are_dropped_before_bounding() {
        assert_eq!(BoundedMessage::new("a\u{7}b\r\nc").as_str(), "abc");
    }

    #[test]
    fn every_construction_path_sanitizes() {
        let oversized = "x".repeat(4096);
        assert!(BoundedMessage::from(oversized.as_str()).as_str().len() <= 512);
        assert!(BoundedMessage::from(oversized).as_str().len() <= 512);
    }
}
