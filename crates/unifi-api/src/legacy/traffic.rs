use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;

use super::{
    CSRF_HEADER, ConsoleKind, LegacyClient, RequestClass, is_login_required, translate_failure,
};
use crate::{
    ApiError, BoundedMessage, http,
    traffic::{ActivityBucket, ActivityRead, ActivityReport, ActivityWindow},
};

impl LegacyClient {
    /// Read the same Internet usage totals as the controller's Activity view.
    /// # Errors
    /// Session, transport, permission, and response-size failures remain errors.
    pub async fn activity(
        &self,
        site: &str,
        window: ActivityWindow,
    ) -> Result<ActivityRead<ActivityReport>, ApiError> {
        let result = self.activity_read(site, window, false).await?;
        match result {
            ActivityRead::Reported(report) if !ActivityReport::validate(&report) => {
                Err(ApiError::Decode(
                    "activity report exceeds supported record or string bounds".into(),
                ))
            }
            other => Ok(other),
        }
    }

    /// Read observed graph timestamps without treating rounded rates as counters.
    /// # Errors
    /// Session, transport, permission, and response-size failures remain errors.
    pub async fn activity_buckets(
        &self,
        site: &str,
        window: ActivityWindow,
    ) -> Result<ActivityRead<Vec<ActivityBucket>>, ApiError> {
        let result: ActivityRead<Vec<ActivityBucket>> =
            self.activity_read(site, window, true).await?;
        match result {
            ActivityRead::Reported(rows)
                if rows.len() > 2017
                    || rows.iter().any(|row| {
                        row.interval_seconds == 0
                            || row.interval_seconds > 86_400
                            || row
                                .timestamp
                                .checked_add(u64::from(row.interval_seconds) * 1000)
                                .is_none()
                    }) =>
            {
                Err(ApiError::Decode(
                    "activity graph exceeds supported bounds".into(),
                ))
            }
            other => Ok(other),
        }
    }

    pub(super) async fn activity_read<T: DeserializeOwned>(
        &self,
        site: &str,
        window: ActivityWindow,
        graph: bool,
    ) -> Result<ActivityRead<T>, ApiError> {
        ActivityWindow::new(window.start, window.end)?;
        let generation = self.ensure_session().await?;
        match self.execute_activity(site, window, graph).await {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                self.execute_activity(site, window, graph).await
            }
            other => other,
        }
    }

    async fn execute_activity<T: DeserializeOwned>(
        &self,
        site: &str,
        window: ActivityWindow,
        graph: bool,
    ) -> Result<ActivityRead<T>, ApiError> {
        let csrf = {
            let session = self.session.lock().await;
            if session.kind != Some(ConsoleKind::UnifiOs) {
                return Ok(ActivityRead::Unsupported { response: None });
            }
            session.csrf.clone()
        };
        let endpoint = if graph { "app-traffic-rate" } else { "traffic" };
        let url = http::build_url(
            &self.base,
            &["proxy", "network", "v2", "api", "site", site, endpoint],
            &[
                ("start", window.start.to_string()),
                ("end", window.end.to_string()),
                ("includeUnidentified", "true".to_owned()),
            ],
        )?;
        let mut request = self
            .http
            .request(if graph { Method::POST } else { Method::GET }, url)
            .header(reqwest::header::ACCEPT, "application/json");
        if graph {
            request = request.json(&serde_json::json!({}));
        }
        if let Some(token) = csrf {
            request = request.header(CSRF_HEADER, token);
        }
        let response = request.send().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        self.capture_csrf(&response).await;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(http::rate_limited(response).await?);
        }
        let bytes = http::read_bounded_body(response).await?;
        if matches!(status.as_u16(), 404 | 405) {
            return Ok(ActivityRead::Unsupported {
                response: Some(translate_failure(
                    status.as_u16(),
                    &bytes,
                    RequestClass::IdempotentRead,
                )),
            });
        }
        if !status.is_success() {
            return Err(translate_failure(
                status.as_u16(),
                &bytes,
                RequestClass::IdempotentRead,
            ));
        }
        serde_json::from_slice(&bytes)
            .map(ActivityRead::Reported)
            .map_err(|error| crate::error::decode_failure(&error, &bytes))
    }
}
