use reqwest::StatusCode;

use super::{
    CSRF_HEADER, ConsoleKind, LegacyClient, MAXIMUM_RETRY_AFTER, RequestClass, is_login_required,
    login_required_error, translate_failure,
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
        let generation = self.ensure_session().await?;
        let result = match self.execute_system_log(site, query).await {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                self.execute_system_log(site, query).await
            }
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
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
    ) -> Result<SystemLogPage, ApiError> {
        let csrf = {
            let session = self.session.lock().await;
            if session.kind != Some(ConsoleKind::UnifiOs) {
                return Err(ApiError::Config(
                    "Network system logs require a UniFi OS console".to_owned(),
                ));
            }
            session.csrf.clone()
        };
        let url = http::build_url(
            &self.base,
            &[
                "proxy",
                "network",
                "v2",
                "api",
                "site",
                site,
                "system-log",
                "all",
            ],
            &[],
        )?;
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
            // The HTTP status survives even if a legacy error envelope is
            // subsequently translated to a generic controller rejection.
            tracing::warn!(
                endpoint = "network.system_log",
                status = status.as_u16(),
                "Network system-log HTTP read failed"
            );
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(login_required_error());
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::RateLimited {
                retry_after: http::retry_after(&response),
            });
        }
        let bytes = http::read_bounded_body(response).await?;
        if !status.is_success() {
            return Err(translate_failure(
                status.as_u16(),
                &bytes,
                &[self.password.as_str()],
                RequestClass::IdempotentRead,
            ));
        }
        let page: SystemLogPage = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::Decode("unexpected Network system-log response".into()))?;
        query.validate_response(&page)?;
        Ok(page)
    }
}
