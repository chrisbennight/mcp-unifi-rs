//! Fixed legacy configuration workflows with complete controller envelopes.

use super::{
    ApiError, CallToolRequestParams, CallToolResult, ContentBlock, Deserialize, JsonSchema,
    MAXIMUM_POLICY_REQUEST_BYTES, McpError, NETWORK_POLICY_READBACK_BUDGET,
    NETWORK_POLICY_RESPONSE_RESERVE, NetworkPolicyWriteOperation, STRUCTURED_CONTENT_TARGET_BYTES,
    Serialize, UnifiMcp, Value, api_error, legacy_wlan_request::LegacyWlanConfiguration, parse,
    requested_json_matches, structured,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct LegacyConfigurationListInput {
    #[serde(default)]
    offset: u32,
    #[serde(default = "super::default_search_limit")]
    limit: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct LegacyConfigurationStatusInput {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct LegacyConfigurationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<NetworkPolicyWriteOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
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

/// Controller field names remain unchanged in the submitted configuration.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PortForwardConfiguration {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_hidden: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_hidden_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_no_delete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_no_edit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fwd_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pfwd_interface: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PortForwardConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    configuration: Option<PortForwardConfiguration>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct WlansConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    configuration: Option<LegacyWlanConfiguration>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) enum WlanGroupKind {
    #[serde(rename = "userGroups")]
    Users,
    #[serde(rename = "wlanGroups")]
    Wlans,
    #[serde(rename = "apGroups")]
    AccessPoints,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct WlanGroupsListInput {
    kind: WlanGroupKind,
    #[serde(default)]
    offset: u32,
    #[serde(default = "super::default_search_limit")]
    limit: u16,
}

#[derive(Clone, Copy)]
enum ConfigurationFamily {
    PortForward,
    Wlan,
}

impl ConfigurationFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::PortForward => "port-forward",
            Self::Wlan => "WLAN",
        }
    }
}

struct ConfigurationRequest {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    requested: Option<Value>,
    confirm: bool,
    family: ConfigurationFamily,
}

fn validate_id(id: &str) -> Result<(), McpError> {
    if id.is_empty() || id.len() > 256 || matches!(id, "." | "..") {
        return Err(McpError::invalid_params(
            "id must be nonempty, non-dot, and at most 256 bytes",
            None,
        ));
    }
    Ok(())
}

impl ConfigurationRequest {
    fn validate(&self) -> Result<(), McpError> {
        if let Some(id) = &self.id {
            validate_id(id)?;
        }
        let requested = &self.requested;
        let has_configuration = requested
            .as_ref()
            .is_some_and(|value| value.as_object().is_some_and(|map| !map.is_empty()));
        let valid_shape = match self.operation {
            NetworkPolicyWriteOperation::Create => self.id.is_none() && has_configuration,
            NetworkPolicyWriteOperation::Update => self.id.is_some() && has_configuration,
            NetworkPolicyWriteOperation::Delete => self.id.is_some() && requested.is_none(),
        };
        if !valid_shape {
            return Err(McpError::invalid_params(
                "create requires configuration without id; update requires id and configuration; delete requires id without configuration",
                None,
            ));
        }
        if requested
            .as_ref()
            .is_some_and(|value| value.to_string().len() > MAXIMUM_POLICY_REQUEST_BYTES)
        {
            return Err(McpError::invalid_params(
                "configuration exceeds the 1 MiB request bound",
                None,
            ));
        }
        Ok(())
    }

    async fn submit(
        &self,
        legacy: &unifi_api::LegacyClient,
        site: &str,
        requested: Option<&Value>,
    ) -> Result<(u16, Vec<u8>), ApiError> {
        match (self.family, self.operation) {
            (ConfigurationFamily::PortForward, NetworkPolicyWriteOperation::Create) => {
                legacy
                    .create_port_forward(site, requested.expect("validated configuration"))
                    .await
            }
            (ConfigurationFamily::PortForward, NetworkPolicyWriteOperation::Update) => {
                legacy
                    .configure_port_forward(
                        site,
                        self.id.as_deref().expect("validated id"),
                        requested.expect("validated configuration"),
                    )
                    .await
            }
            (ConfigurationFamily::PortForward, NetworkPolicyWriteOperation::Delete) => {
                legacy
                    .delete_port_forward(site, self.id.as_deref().expect("validated id"))
                    .await
            }
            (ConfigurationFamily::Wlan, NetworkPolicyWriteOperation::Create) => {
                legacy
                    .create_wlan(site, requested.expect("validated configuration"))
                    .await
            }
            (ConfigurationFamily::Wlan, NetworkPolicyWriteOperation::Update) => {
                legacy
                    .configure_wlan(
                        site,
                        self.id.as_deref().expect("validated id"),
                        requested.expect("validated configuration"),
                    )
                    .await
            }
            (ConfigurationFamily::Wlan, NetworkPolicyWriteOperation::Delete) => {
                legacy
                    .delete_wlan(site, self.id.as_deref().expect("validated id"))
                    .await
            }
        }
    }
}

impl UnifiMcp {
    pub(super) async fn port_forward_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<LegacyConfigurationListInput>(params)?;
        if !(1..=super::MAXIMUM_SEARCH_LIMIT).contains(&input.limit) {
            return Err(McpError::invalid_params("limit must be 1-200", None));
        }
        let response = self
            .legacy()
            .port_forward_records(self.legacy_site())
            .await
            .map_err(api_error)?;
        page(response, input.offset, input.limit)
    }

    pub(super) async fn port_forward_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<LegacyConfigurationStatusInput>(params)?;
        validate_id(&input.id)?;
        let response = self
            .legacy()
            .port_forward_record(self.legacy_site(), &input.id)
            .await
            .map_err(api_error)?;
        result(serde_json::json!({"response": response}))
    }

    pub(super) async fn port_forward_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<PortForwardConfigureInput>(params)?;
        let requested = input
            .configuration
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        self.legacy_configuration_write(ConfigurationRequest {
            operation: input.operation,
            id: input.id,
            requested,
            confirm: input.confirm,
            family: ConfigurationFamily::PortForward,
        })
        .await
    }

    pub(super) async fn wlans_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<WlansConfigureInput>(params)?;
        let requested = input
            .configuration
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        self.legacy_configuration_write(ConfigurationRequest {
            operation: input.operation,
            id: input.id,
            requested,
            confirm: input.confirm,
            family: ConfigurationFamily::Wlan,
        })
        .await
    }

    pub(super) async fn wlans_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<LegacyConfigurationListInput>(params)?;
        validate_page(input.limit)?;
        let response = self
            .legacy()
            .wlan_records(self.legacy_site())
            .await
            .map_err(api_error)?;
        page(response, input.offset, input.limit)
    }

    pub(super) async fn wlans_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<LegacyConfigurationStatusInput>(params)?;
        validate_id(&input.id)?;
        let response = self
            .legacy()
            .wlan_record(self.legacy_site(), &input.id)
            .await
            .map_err(api_error)?;
        result(serde_json::json!({"response":response}))
    }

    pub(super) async fn wlan_groups_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<WlanGroupsListInput>(params)?;
        validate_page(input.limit)?;
        let response = match input.kind {
            WlanGroupKind::Users => self.legacy().user_groups(self.legacy_site()).await,
            WlanGroupKind::Wlans => self.legacy().wlan_groups(self.legacy_site()).await,
            WlanGroupKind::AccessPoints => self.legacy().ap_groups(self.legacy_site()).await,
        }
        .map_err(api_error)?;
        page(response, input.offset, input.limit)
    }

    async fn configuration_record(
        &self,
        family: ConfigurationFamily,
        id: &str,
    ) -> Result<Value, ApiError> {
        match family {
            ConfigurationFamily::PortForward => {
                self.legacy()
                    .port_forward_record(self.legacy_site(), id)
                    .await
            }
            ConfigurationFamily::Wlan => self.legacy().wlan_record(self.legacy_site(), id).await,
        }
    }

    async fn legacy_configuration_write(
        &self,
        input: ConfigurationRequest,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        input.validate()?;
        let requested = &input.requested;
        let mut output = serde_json::json!({"operation":input.operation,"id":input.id,"requested":requested,
            "submitted":false});
        if !input.confirm {
            return result(output);
        }
        let (status, body) = input
            .submit(self.legacy(), self.legacy_site(), requested.as_ref())
            .await
            .map_err(api_error)?;
        output["submitted"] = Value::Bool(true);
        output["responseStatus"] = Value::from(status);
        output["responseBody"] = Value::String(String::from_utf8_lossy(&body).into_owned());
        let accepted: Value = serde_json::from_slice(&body).expect("validated legacy envelope");
        let accepted_id = accepted
            .get("data")
            .and_then(Value::as_array)
            .filter(|rows| rows.len() == 1)
            .and_then(|rows| rows[0].get("_id"))
            .and_then(Value::as_str);
        let id = input.id.as_deref().or(accepted_id);
        let Some(id) = id else {
            output["readbackError"] = Value::String(format!(
                "accepted response contains no single {} identifier",
                input.family.label()
            ));
            return result(output);
        };
        output["id"] = Value::String(id.to_owned());
        if let Err(error) = validate_id(id) {
            output["readbackError"] = Value::String(error.to_string());
            return result(output);
        }
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
            .min(NETWORK_POLICY_READBACK_BUDGET);
        if budget.is_zero() {
            output["readbackError"] = Value::String(format!(
                "{} readback skipped near request deadline",
                input.family.label()
            ));
            return result(output);
        }
        match tokio::time::timeout(budget, self.configuration_record(input.family, id)).await {
            Ok(Ok(after)) => {
                let rows = after
                    .get("data")
                    .and_then(Value::as_array)
                    .expect("decoded legacy envelope");
                if input.operation == NetworkPolicyWriteOperation::Delete {
                    output["verifiedAbsent"] = Value::Bool(rows.is_empty());
                } else {
                    output["verified"] = Value::Bool(
                        rows.len() == 1
                            && rows[0].get("_id").and_then(Value::as_str) == Some(id)
                            && accepted_id.is_none_or(|accepted| accepted == id)
                            && requested_json_matches(
                                requested.as_ref().expect("validated configuration"),
                                &rows[0],
                            ),
                    );
                }
                output["after"] = after;
            }
            Ok(Err(error @ ApiError::Status { status: 404, .. }))
                if input.operation == NetworkPolicyWriteOperation::Delete =>
            {
                output["verifiedAbsent"] = Value::Bool(true);
                output["readbackError"] = Value::String(error.to_string());
            }
            Ok(Err(error)) => {
                output["readbackError"] = Value::String(error.to_string());
            }
            Err(_) => {
                output["readbackError"] =
                    Value::String(format!("{} readback timed out", input.family.label()));
            }
        }
        result(output)
    }
}

fn validate_page(limit: u16) -> Result<(), McpError> {
    if !(1..=super::MAXIMUM_SEARCH_LIMIT).contains(&limit) {
        return Err(McpError::invalid_params("limit must be 1-200", None));
    }
    Ok(())
}

fn page(
    mut response: Value,
    requested_offset: u32,
    limit: u16,
) -> Result<CallToolResult, McpError> {
    let rows = if let Value::Array(rows) = &mut response {
        rows
    } else {
        response
            .get_mut("data")
            .and_then(Value::as_array_mut)
            .expect("decoded legacy envelope")
    };
    let total = rows.len();
    let offset = usize::try_from(requested_offset)
        .expect("u32 fits supported platforms")
        .min(total);
    let end = offset.saturating_add(usize::from(limit)).min(total);
    *rows = rows.drain(offset..end).collect();
    result(
        serde_json::json!({"response": response,"offset":requested_offset,"limit":limit,"totalCount":total,"nextOffset":(end<total).then_some(end)}),
    )
}

fn result(mut output: Value) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    for field in [
        "response",
        "requested",
        "responseBody",
        "after",
        "readbackError",
    ] {
        if output.to_string().len() <= STRUCTURED_CONTENT_TARGET_BYTES {
            break;
        }
        if let Some(part) = output.as_object_mut().expect("result object").remove(field) {
            content.push(ContentBlock::text(format!(
                "{field}: {}",
                part.as_str()
                    .map_or_else(|| part.to_string(), str::to_owned)
            )));
            output[format!("{field}InContent")] = Value::Bool(true);
        }
    }
    let output: LegacyConfigurationResult = serde_json::from_value(output)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}
