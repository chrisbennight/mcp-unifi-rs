use std::time::Duration;

use thiserror::Error;

/// Longest upstream-derived detail carried by any error variant.
const MAXIMUM_MESSAGE_BYTES: usize = 512;
const TRUNCATION_MARKER: &str = " [truncated]";

/// An upstream-derived message kept within the error string budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedMessage(String);

impl BoundedMessage {
    /// Keep the original characters and signal any byte-budget truncation.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let mut message = String::new();
        let mut truncated = false;
        for character in raw.chars() {
            if message.len() + character.len_utf8() > MAXIMUM_MESSAGE_BYTES {
                truncated = true;
                break;
            }
            message.push(character);
        }
        if truncated {
            while message.len() + TRUNCATION_MARKER.len() > MAXIMUM_MESSAGE_BYTES {
                message.pop();
            }
            message.push_str(TRUNCATION_MARKER);
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

/// Pair a decoder failure with the controller's bounded response body.
pub(crate) fn decode_failure(error: &impl std::fmt::Display, bytes: &[u8]) -> ApiError {
    ApiError::Decode(BoundedMessage::new(&format!(
        "{error}; controller response: {}",
        String::from_utf8_lossy(bytes)
    )))
}

/// A failure talking to a controller. Upstream-derived detail always travels
/// as a [`BoundedMessage`]. Controller-provided values remain present in the
/// selected error detail, with an explicit marker if the budget is reached.
#[derive(Debug, Clone, Error)]
pub enum ApiError {
    /// Locally produced configuration diagnostics; carries no upstream data.
    #[error("invalid controller configuration: {0}")]
    Config(String),
    /// The controller answered with a non-success status. `message` keeps
    /// the original response text within the error string budget.
    #[error("controller returned HTTP {status}: {message}")]
    Status {
        status: u16,
        message: BoundedMessage,
    },
    /// The controller rate limited the request and the client did not (or
    /// must not) retry it.
    #[error("controller rate limited the request: {message}")]
    RateLimited {
        retry_after: Option<Duration>,
        message: BoundedMessage,
    },
    /// The legacy controller API accepted the transport but rejected the
    /// operation with one of its `api.err.*` codes. `code` is the upstream
    /// token when present; `message` is the bounded upstream response body.
    #[error("{message}")]
    Rejected {
        code: BoundedMessage,
        message: BoundedMessage,
    },
    #[error("transport failure: {0}")]
    Transport(BoundedMessage),
    /// A successful response exceeded the process-wide response body budget.
    #[error("controller response exceeded the {limit}-byte budget")]
    ResponseTooLarge { limit: usize },
    /// A successful response was not syntactically valid JSON. The bounded
    /// controller body remains available with its parser location.
    #[error("invalid JSON from {endpoint} at line {line}, column {column}{response_suffix}", response_suffix = controller_response_suffix(response.as_ref()))]
    InvalidJson {
        endpoint: &'static str,
        line: usize,
        column: usize,
        response: Option<BoundedMessage>,
    },
    /// Valid JSON did not match the endpoint's typed wire contract. The path
    /// identifies the mismatch and a bounded controller body accompanies it
    /// when the mismatch happened during wire decoding.
    #[error("response from {endpoint} did not match its schema at {path}{response_suffix}", response_suffix = controller_response_suffix(response.as_ref()))]
    SchemaMismatch {
        endpoint: &'static str,
        path: BoundedMessage,
        response: Option<BoundedMessage>,
    },
    #[error("response decoding failed: {0}")]
    Decode(BoundedMessage),
}

impl ApiError {
    /// Retain the controller body when a decoded value fails a typed
    /// response invariant after JSON parsing has succeeded.
    pub(crate) fn with_controller_response(self, bytes: &[u8]) -> Self {
        match self {
            Self::SchemaMismatch { endpoint, path, .. } => Self::SchemaMismatch {
                endpoint,
                path,
                response: Some(BoundedMessage::new(&String::from_utf8_lossy(bytes))),
            },
            other => other,
        }
    }
}

fn controller_response_suffix(response: Option<&BoundedMessage>) -> String {
    response.map_or_else(String::new, |body| format!("; controller response: {body}"))
}

#[cfg(test)]
mod tests {
    use super::BoundedMessage;

    #[test]
    fn bounding_respects_character_boundaries_under_the_byte_budget() {
        let bounded = BoundedMessage::new(&"é".repeat(600));
        assert!(bounded.as_str().len() <= 512);
        assert_eq!(bounded.as_str().len(), 512);
        assert!(bounded.as_str().ends_with(" [truncated]"));
        assert!(
            bounded
                .as_str()
                .trim_end_matches(" [truncated]")
                .chars()
                .all(|character| character == 'é')
        );
    }

    #[test]
    fn control_characters_are_preserved() {
        assert_eq!(BoundedMessage::new("a\u{7}b\r\nc").as_str(), "a\u{7}b\r\nc");
    }

    #[test]
    fn every_construction_path_respects_the_budget() {
        let oversized = "x".repeat(4096);
        assert!(BoundedMessage::from(oversized.as_str()).as_str().len() <= 512);
        assert!(BoundedMessage::from(oversized).as_str().len() <= 512);
    }
}
