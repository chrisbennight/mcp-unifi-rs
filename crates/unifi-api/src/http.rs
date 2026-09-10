//! Crate-private HTTP plumbing shared by both controller clients: bounded
//! body reads, segment-encoded URL assembly, and `Retry-After` extraction.

use std::time::Duration;

use reqwest::{Response, header::RETRY_AFTER};
use url::Url;

use crate::{ApiError, BoundedMessage};

/// Hard budget for any response body. A payload beyond this is refused
/// mid-stream rather than buffered.
pub(crate) const MAXIMUM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Read a response body in chunks against the hard byte budget so an
/// oversized controller payload is refused mid-stream, never buffered whole.
pub(crate) async fn read_bounded_body(mut response: Response) -> Result<Vec<u8>, ApiError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
    })? {
        if body.len() + chunk.len() > MAXIMUM_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge {
                limit: MAXIMUM_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Assemble a request URL from percent-encoded path segments. A segment that
/// is empty or a dot segment is rejected outright: those are never valid
/// controller identifiers and would otherwise be interpreted structurally by
/// the server. An identifier containing URL syntax stays one literal segment.
pub(crate) fn build_url(
    base: &Url,
    segments: &[&str],
    query: &[(&str, String)],
) -> Result<Url, ApiError> {
    let mut url = base.clone();
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|()| ApiError::Config("base URL cannot carry API paths".to_owned()))?;
        parts.pop_if_empty();
        for segment in segments {
            if segment.is_empty() || *segment == "." || *segment == ".." {
                return Err(ApiError::Config(format!(
                    "invalid path segment {segment:?}"
                )));
            }
            parts.push(segment);
        }
    }
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in query {
            pairs.append_pair(name, value);
        }
        drop(pairs);
    }
    Ok(url)
}

/// `Retry-After` in its delta-seconds form, which is what the controller
/// emits. The HTTP-date form deliberately parses to `None`: the request then
/// surfaces as rate limited to the caller instead of being opportunistically
/// retried.
pub(crate) fn retry_after(response: &Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}
