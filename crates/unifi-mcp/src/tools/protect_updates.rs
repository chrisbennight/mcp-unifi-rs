//! Finite Protect device and event observation with complete payloads.

use super::{
    ApiError, CallToolRequestParams, CallToolResult, ContentBlock, Deserialize, JsonSchema,
    MAXIMUM_RESULT_BYTES, McpError, Serialize, UnifiMcp, parse, structured,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::time::Duration;
use unifi_api::protect::{
    ProtectSubscriptionEnd, ProtectSubscriptionMessage, ProtectSubscriptionSource,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) enum UpdateSource {
    Devices,
    Events,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ProtectUpdatesInput {
    source: UpdateSource,
    /// Observation window including connection setup, 1-20000 milliseconds.
    #[serde(default = "default_duration")]
    duration_ms: u32,
    #[serde(default = "default_count")]
    max_messages: u16,
    /// Total payload byte budget, 1-4194304. An oversized message is reported.
    #[serde(default = "default_bytes")]
    max_bytes: usize,
}
const fn default_duration() -> u32 {
    1000
}
const fn default_count() -> u16 {
    50
}
const fn default_bytes() -> usize {
    65536
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) enum UpdateEnd {
    WindowComplete,
    MessageLimit,
    ByteLimit,
    Closed,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "encoding", content = "payload", rename_all = "camelCase")]
pub(super) enum UpdateMessage {
    Utf8(String),
    Base64(String),
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProtectUpdatesOutput {
    source: UpdateSource,
    connected: bool,
    end: UpdateEnd,
    duration_ms: u32,
    message_count: usize,
    received_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<UpdateMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted_message_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    close_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    close_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_in_content: Option<bool>,
}

impl UnifiMcp {
    pub(super) async fn protect_updates(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectUpdatesInput>(params)?;
        let duration = Duration::from_millis(u64::from(input.duration_ms));
        if !(1..=20000).contains(&input.duration_ms)
            || !(1..=200).contains(&input.max_messages)
            || !(1..=4 * 1024 * 1024).contains(&input.max_bytes)
            || duration + Duration::from_secs(1) > self.request_timeout()
        {
            return Err(McpError::invalid_params(
                "durationMs must be 1-20000 and leave one second in the server request deadline, maxMessages 1-200, and maxBytes 1-4194304",
                None,
            ));
        }
        let source = match input.source {
            UpdateSource::Devices => ProtectSubscriptionSource::Devices,
            UpdateSource::Events => ProtectSubscriptionSource::Events,
        };
        let mut output = ProtectUpdatesOutput {
            source: input.source,
            connected: false,
            end: UpdateEnd::Failed,
            duration_ms: input.duration_ms,
            message_count: 0,
            received_bytes: 0,
            messages: Some(Vec::new()),
            messages_in_content: None,
            omitted_message_bytes: None,
            close_code: None,
            close_reason: None,
            error: None,
            error_in_content: None,
        };
        match self
            .protect()
            .observe_updates(source, duration, input.max_messages, input.max_bytes)
            .await
        {
            Ok(batch) => {
                output.connected = true;
                output.end = match batch.end {
                    ProtectSubscriptionEnd::WindowComplete => UpdateEnd::WindowComplete,
                    ProtectSubscriptionEnd::MessageLimit => UpdateEnd::MessageLimit,
                    ProtectSubscriptionEnd::ByteLimit => UpdateEnd::ByteLimit,
                    ProtectSubscriptionEnd::Closed => UpdateEnd::Closed,
                    ProtectSubscriptionEnd::Failed => UpdateEnd::Failed,
                };
                output.message_count = batch.messages.len();
                output.received_bytes = batch.received_bytes;
                output.messages = Some(
                    batch
                        .messages
                        .into_iter()
                        .map(|message| match message {
                            ProtectSubscriptionMessage::Text(text) => UpdateMessage::Utf8(text),
                            ProtectSubscriptionMessage::Binary(bytes) => {
                                UpdateMessage::Base64(STANDARD.encode(bytes))
                            }
                        })
                        .collect(),
                );
                output.omitted_message_bytes = batch.omitted_message_bytes;
                output.close_code = batch.close_code;
                output.close_reason = batch.close_reason;
                output.error = batch.error.map(|error| error.to_string());
            }
            Err(error) => {
                if matches!(
                    error,
                    ApiError::Status {
                        status: 404 | 405,
                        ..
                    }
                ) {
                    output.end = UpdateEnd::Unsupported;
                }
                output.error = Some(error.to_string());
            }
        }
        subscription_result(output)
    }
}

fn subscription_result(mut output: ProtectUpdatesOutput) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    if serde_json::to_vec(&output)
        .expect("subscription serialization")
        .len()
        > MAXIMUM_RESULT_BYTES
    {
        if let Some(messages) = output.messages.take() {
            content.push(ContentBlock::text(format!(
                "Complete subscription messages\n{}",
                serde_json::to_string(&messages).expect("message serialization")
            )));
            output.messages_in_content = Some(true);
        }
        if serde_json::to_vec(&output)
            .expect("subscription serialization")
            .len()
            > MAXIMUM_RESULT_BYTES
            && let Some(error) = output.error.take()
        {
            content.push(ContentBlock::text(format!(
                "Complete subscription error\n{error}"
            )));
            output.error_in_content = Some(true);
        }
    }
    let failed = matches!(output.end, UpdateEnd::Failed | UpdateEnd::Unsupported);
    let mut result = structured(output)?;
    result.content.extend(content);
    result.is_error = Some(failed);
    Ok(result)
}
