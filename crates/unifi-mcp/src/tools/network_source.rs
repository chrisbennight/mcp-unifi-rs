//! Complete records behind the compact legacy Network diagnostic views.

use super::{
    CallToolRequestParams, CallToolResult, ContentBlock, Deserialize, JsonSchema, Map, McpError,
    STRUCTURED_CONTENT_TARGET_BYTES, Serialize, UnifiMcp, Value, api_error, default_search_limit,
    parse, structured,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) enum NetworkSource {
    ActiveClients,
    SiteHealth,
    NetworkConfiguration,
    NeighborAccessPoints,
    DpiCounters,
}

impl From<NetworkSource> for unifi_api::LegacyDiagnosticSource {
    fn from(source: NetworkSource) -> Self {
        match source {
            NetworkSource::ActiveClients => Self::ActiveClients,
            NetworkSource::SiteHealth => Self::SiteHealth,
            NetworkSource::NetworkConfiguration => Self::NetworkConfiguration,
            NetworkSource::NeighborAccessPoints => Self::NeighborAccessPoints,
            NetworkSource::DpiCounters => Self::DpiCounters,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NetworkSourceReadInput {
    source: NetworkSource,
    /// Offset into the complete response fetched for this call.
    #[serde(default)]
    offset: u64,
    /// Positive complete source rows per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworkSourceReadOutput {
    source: NetworkSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records_in_content: Option<bool>,
    /// All original envelope fields other than data.
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_metadata_in_content: Option<bool>,
    offset: u64,
    limit: usize,
    count: u64,
    /// Number of rows in this call's complete accepted controller response.
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
    pagination_note: &'static str,
}

impl UnifiMcp {
    pub(super) async fn network_source_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkSourceReadInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let envelope = self
            .legacy()
            .diagnostic_records(self.legacy_site(), input.source.into())
            .await
            .map_err(api_error)?;
        // The API reader validates the envelope before returning it.
        let mut metadata = envelope.as_object().expect("validated envelope").clone();
        let data = metadata.remove("data").expect("validated data array");
        let data = data.as_array().expect("validated data array");
        let total_count = data.len() as u64;
        let offset = usize::try_from(input.offset).unwrap_or(data.len());
        let records: Vec<Value> = data
            .iter()
            .skip(offset)
            .take(input.limit)
            .cloned()
            .collect();
        let count = records.len() as u64;
        let next_offset = input
            .offset
            .checked_add(count)
            .filter(|next| *next < total_count);
        source_result(NetworkSourceReadOutput {
            source: input.source,
            records: Some(records),
            records_in_content: None,
            controller_metadata: Some(metadata),
            controller_metadata_in_content: None,
            offset: input.offset,
            limit: input.limit,
            count,
            total_count,
            next_offset,
            pagination_note: "Paging is local to this call's controller response. Each call fetches a new response; rows may change between pages.",
        })
    }
}

fn source_result(mut output: NetworkSourceReadOutput) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &NetworkSourceReadOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(records) = output.records.take()
    {
        output.records_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "records: {}",
            Value::Array(records)
        )));
    }
    if exceeds(&output)?
        && let Some(metadata) = output.controller_metadata.take()
    {
        output.controller_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "controllerMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}
