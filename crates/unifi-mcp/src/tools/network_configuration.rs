//! Official network configuration workflows with complete controller responses.

use super::{
    ApiError, BoundedMessage, CallToolRequestParams, CallToolResult, ContentBlock, Deserialize,
    JsonSchema, MAXIMUM_POLICY_REQUEST_BYTES, MAXIMUM_RESULT_BYTES, MAXIMUM_SEARCH_LIMIT, McpError,
    NETWORK_POLICY_READBACK_BUDGET, NETWORK_POLICY_RESPONSE_RESERVE, NetworkPolicyWriteOperation,
    PageRequest, Serialize, UnifiMcp, Value, api_error, default_search_limit,
    network_request::NetworkRequest, page_validation_error, parse, requested_json_matches,
    structured,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NetworksListInput {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_search_limit")]
    limit: u16,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NetworksStatusInput {
    id: String,
    #[serde(default)]
    include_references: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NetworksConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    network: Option<NetworkRequest>,
    /// The controller's deletion option for networks with references.
    #[serde(default)]
    force: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworksResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    references: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    references_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<NetworkPolicyWriteOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    submitted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

fn validate_network_id(id: &str) -> Result<(), McpError> {
    if id.trim().is_empty() || id.len() > 256 || matches!(id, "." | "..") {
        return Err(McpError::invalid_params(
            "id must be nonempty and at most 256 bytes",
            None,
        ));
    }
    Ok(())
}

impl UnifiMcp {
    pub(super) async fn networks_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworksListInput>(params)?;
        if input.offset > i32::MAX as u32 || !(1..=MAXIMUM_SEARCH_LIMIT).contains(&input.limit) {
            return Err(McpError::invalid_params(
                "offset must be 0-2147483647 and limit must be 1-200",
                None,
            ));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (response, source) = self
            .integration()
            .network_records(
                &site_id,
                PageRequest {
                    offset: u64::from(input.offset),
                    limit: u32::from(input.limit),
                },
                input.filter.as_deref(),
            )
            .await
            .map_err(api_error)?;
        let page: unifi_api::models::Page<Value> = serde_json::from_value(response.clone())
            .map_err(|error| page_validation_error(&source, error.to_string()))?;
        let rows = page.data.len() as u64;
        let next = page
            .offset
            .checked_add(rows)
            .ok_or_else(|| page_validation_error(&source, "network page offset overflow"))?;
        if page.offset != u64::from(input.offset)
            || page.limit == 0
            || page.limit > u64::from(input.limit)
            || rows > page.limit
            || page.count != rows
            || (rows > 0 && next > page.total_count)
            || (rows == 0 && page.offset < page.total_count)
        {
            return Err(page_validation_error(
                &source,
                "network page metadata contradicts the requested page or returned rows",
            ));
        }
        result(NetworksResult {
            response: Some(response),
            next_offset: (next < page.total_count).then_some(next),
            ..Default::default()
        })
    }

    pub(super) async fn networks_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<NetworksStatusInput>(params)?;
        validate_network_id(&input.id)?;
        let site_id = self.site_id().await?;
        let response = self
            .integration()
            .network_record(&site_id, &input.id)
            .await
            .map_err(api_error)?;
        let mut output = NetworksResult {
            response: Some(response),
            ..Default::default()
        };
        if input.include_references {
            let budget = self
                .request_timeout()
                .saturating_sub(started.elapsed())
                .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
                .min(NETWORK_POLICY_READBACK_BUDGET);
            if budget.is_zero() {
                output.readback_error =
                    Some("network reference lookup skipped near request deadline".to_owned());
            } else {
                match tokio::time::timeout(
                    budget,
                    self.integration().network_references(&site_id, &input.id),
                )
                .await
                {
                    Ok(Ok(references)) => output.references = Some(references),
                    Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                    Err(_) => {
                        output.readback_error =
                            Some("network reference lookup timed out".to_owned());
                    }
                }
            }
        }
        result(output)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Each fixed mutation preserves acceptance before its bounded readback"
    )]
    pub(super) async fn networks_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<NetworksConfigureInput>(params)?;
        let requested = input
            .network
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        let valid = match input.operation {
            NetworkPolicyWriteOperation::Create => input.id.is_none() && requested.is_some(),
            NetworkPolicyWriteOperation::Update => input.id.is_some() && requested.is_some(),
            NetworkPolicyWriteOperation::Delete => input.id.is_some() && requested.is_none(),
        };
        if !valid || (input.force && input.operation != NetworkPolicyWriteOperation::Delete) {
            return Err(McpError::invalid_params(
                "create requires network without id; update requires network and id; delete requires id without network; force applies only to delete",
                None,
            ));
        }
        if let Some(id) = &input.id {
            validate_network_id(id)?;
        }
        if requested
            .as_ref()
            .is_some_and(|value| value.to_string().len() > MAXIMUM_POLICY_REQUEST_BYTES)
        {
            return Err(McpError::invalid_params(
                "network request exceeds the 1 MiB request bound",
                None,
            ));
        }
        let mut output = NetworksResult {
            operation: Some(input.operation),
            id: input.id,
            requested,
            force: (input.operation == NetworkPolicyWriteOperation::Delete).then_some(input.force),
            submitted: Some(false),
            ..Default::default()
        };
        if !input.confirm {
            return result(output);
        }
        let site_id = self.site_id().await?;
        let (status, body) = match input.operation {
            NetworkPolicyWriteOperation::Create => {
                self.integration()
                    .create_network(
                        &site_id,
                        output.requested.as_ref().expect("validated network"),
                    )
                    .await
            }
            NetworkPolicyWriteOperation::Update => {
                self.integration()
                    .replace_network(
                        &site_id,
                        output.id.as_deref().expect("validated id"),
                        output.requested.as_ref().expect("validated network"),
                    )
                    .await
            }
            NetworkPolicyWriteOperation::Delete => {
                self.integration()
                    .delete_network(
                        &site_id,
                        output.id.as_deref().expect("validated id"),
                        input.force,
                    )
                    .await
            }
        }
        .map_err(api_error)?;
        output.submitted = Some(true);
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let accepted_id = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned));
        if output.id.is_none() {
            output.id.clone_from(&accepted_id);
        }
        let Some(id) = output.id.as_deref() else {
            output.readback_error =
                Some("accepted network response had no id for readback".to_owned());
            return result(output);
        };
        // An upstream identifier is used only as an encoded path segment.
        if let Err(error) = validate_network_id(id) {
            output.readback_error = Some(error.to_string());
            return result(output);
        }
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
            .min(NETWORK_POLICY_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("network readback skipped near request deadline".to_owned());
            return result(output);
        }
        match tokio::time::timeout(budget, self.integration().network_record(&site_id, id)).await {
            Ok(Ok(after)) => {
                if input.operation == NetworkPolicyWriteOperation::Delete {
                    output.verified_absent = Some(false);
                } else {
                    output.verified = Some(
                        accepted_id.as_deref() == Some(id)
                            && after.get("id").and_then(Value::as_str) == Some(id)
                            && requested_json_matches(
                                output.requested.as_ref().expect("validated network"),
                                &after,
                            ),
                    );
                }
                output.after = Some(after);
            }
            Ok(Err(error @ ApiError::Status { status: 404, .. }))
                if input.operation == NetworkPolicyWriteOperation::Delete =>
            {
                output.verified_absent = Some(true);
                output.readback_error = Some(error.to_string());
            }
            Ok(Err(error)) => output.readback_error = Some(error.to_string()),
            Err(_) => output.readback_error = Some("network readback timed out".to_owned()),
        }
        result(output)
    }
}

fn result(output: NetworksResult) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(output)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let mut content = Vec::new();
    for field in [
        "response",
        "references",
        "requested",
        "responseBody",
        "after",
        "readbackError",
    ] {
        if value.to_string().len() <= MAXIMUM_RESULT_BYTES {
            break;
        }
        if let Some(part) = value.as_object_mut().expect("typed object").remove(field) {
            let text = part
                .as_str()
                .map_or_else(|| part.to_string(), str::to_owned);
            content.push(ContentBlock::text(format!("{field}: {text}")));
            value
                .as_object_mut()
                .expect("typed object")
                .insert(format!("{field}InContent"), Value::Bool(true));
        }
    }
    let mut result = structured(value)?;
    result.content.extend(content);
    Ok(result)
}
