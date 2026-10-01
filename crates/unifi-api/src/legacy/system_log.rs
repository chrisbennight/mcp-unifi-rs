use reqwest::StatusCode;

use super::{
    CSRF_HEADER, ConsoleKind, LegacyClient, MAXIMUM_RETRY_AFTER, RequestClass, is_login_required,
    translate_failure,
};
use crate::{
    ApiError, BoundedMessage, http,
    system_log::{SystemLogPage, SystemLogQuery},
};

impl LegacyClient {
    /// Read one bounded page from Network 10.6.106's system-log API.
    ///
    /// Shares the local session and CSRF handling with other application
    /// reads. A missing endpoint remains an error; no retired route is tried.
    ///
    /// # Errors
    /// Returns an [`ApiError`] when login, transport, decoding, or the
    /// controller's pagination contract fails.
    pub async fn system_log(
        &self,
        site: &str,
        query: &SystemLogQuery,
    ) -> Result<SystemLogPage, ApiError> {
        let bytes = self.system_log_bytes(site, query).await?;
        serde_json::from_slice(&bytes).map_err(|error| crate::error::decode_failure(&error, &bytes))
    }

    /// Read every original field in one caller-selected system-log page.
    ///
    /// # Errors
    /// Returns complete upstream failures or a pagination diagnostic with
    /// the original response body.
    pub async fn system_log_records(
        &self,
        site: &str,
        query: &SystemLogQuery,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ApiError> {
        let bytes = self.system_log_bytes(site, query).await?;
        serde_json::from_slice(&bytes).map_err(|error| crate::error::decode_failure(&error, &bytes))
    }

    async fn system_log_bytes(
        &self,
        site: &str,
        query: &SystemLogQuery,
    ) -> Result<Vec<u8>, ApiError> {
        let generation = self.ensure_session().await?;
        let result = match self.execute_system_log(site, query).await {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation)
                    .await
                    .map_err(|refresh| error.with_refresh_failure(refresh))?;
                self.execute_system_log(site, query).await
            }
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
                ..
            }) if delay <= MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.execute_system_log(site, query).await
            }
            other => other,
        };
        if let Err(error) = &result {
            let status = match error {
                ApiError::Status { status, .. } => Some(*status),
                _ => None,
            };
            tracing::warn!(
                endpoint = "network.system_log",
                status,
                "Network system-log read failed"
            );
        }
        result
    }

    async fn execute_system_log(
        &self,
        site: &str,
        query: &SystemLogQuery,
    ) -> Result<Vec<u8>, ApiError> {
        let (kind, csrf) = {
            let session = self.session.lock().await;
            (session.kind, session.csrf.clone())
        };
        let mut route = Vec::new();
        if kind == Some(ConsoleKind::UnifiOs) {
            route.extend(["proxy", "network"]);
        }
        route.extend(["v2", "api", "site", site, "system-log", "all"]);
        let url = http::build_url(&self.base, &route, &[])?;
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(query);
        if let Some(token) = csrf {
            request = request.header(CSRF_HEADER, token);
        }
        let response = request.send().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        self.capture_csrf(&response).await;
        let status = response.status();
        if !status.is_success() {
            // The status and controller detail both reach the caller.
            tracing::warn!(
                endpoint = "network.system_log",
                status = status.as_u16(),
                "Network system-log HTTP read failed"
            );
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(http::rate_limited(response).await?);
        }
        let bytes = http::read_bounded_body(response).await?;
        if !status.is_success() {
            return Err(translate_failure(
                status.as_u16(),
                &bytes,
                RequestClass::IdempotentRead,
            ));
        }
        let page: SystemLogPage<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| crate::error::decode_failure(&error, &bytes))?;
        query
            .validate_response(&page)
            .map_err(|error| error.with_controller_response(&bytes))?;
        Ok(bytes)
    }
}
