use reqwest::Method;
use serde_json::value::RawValue;

use super::{LegacyClient, RequestClass, is_login_required};
use crate::{
    ApiError,
    collection::{SourceReport, SourceStatus, TrafficSnapshot, WanReport},
    traffic::{ActivityBucket, ActivityRead, ActivityReport, ActivityWindow},
};

fn source<T>(
    read: Result<ActivityRead<Box<RawValue>>, ApiError>,
    valid: impl FnOnce(&T) -> bool,
) -> SourceReport
where
    T: serde::de::DeserializeOwned,
{
    match read {
        Ok(ActivityRead::Reported(data)) => {
            let recognized = serde_json::from_str::<T>(data.get()).is_ok_and(|v| valid(&v));
            SourceReport {
                status: if recognized {
                    SourceStatus::Collected
                } else {
                    SourceStatus::Unrecognized
                },
                data: Some(data),
                error: None,
            }
        }
        Ok(ActivityRead::Unsupported) => SourceReport {
            status: SourceStatus::Unsupported,
            data: None,
            error: None,
        },
        Ok(ActivityRead::Unrecognized) => SourceReport {
            status: SourceStatus::Unrecognized,
            data: None,
            error: None,
        },
        Err(error) => SourceReport {
            status: SourceStatus::Failed,
            data: None,
            error: Some(error.to_string()),
        },
    }
}

impl LegacyClient {
    /// Retrieve each fixed report once, preserving every JSON field for retention.
    /// Failures remain source-local so successful reports are not discarded.
    /// # Errors
    /// Rejects invalid interval boundaries before contacting the controller.
    pub async fn collect_traffic(
        &self,
        site: &str,
        window: ActivityWindow,
    ) -> Result<TrafficSnapshot, ApiError> {
        ActivityWindow::new(window.start, window.end)?;
        let activity = source::<ActivityReport>(
            self.activity_read(site, window, false).await,
            ActivityReport::validate,
        );
        let graph =
            source::<Vec<ActivityBucket>>(self.activity_read(site, window, true).await, |rows| {
                rows.len() <= 2017
            });
        let wan = source::<WanReport>(self.collect_wan(site, window).await, |report| {
            report.meta.rc == "ok" && report.data.len() <= 169
        });
        Ok(TrafficSnapshot {
            start_ms: window.start,
            end_ms: window.end,
            activity,
            graph,
            wan,
        })
    }

    async fn collect_wan(
        &self,
        site: &str,
        window: ActivityWindow,
    ) -> Result<ActivityRead<Box<RawValue>>, ApiError> {
        let generation = self.ensure_session().await?;
        let body = serde_json::json!({"attrs":["time","wan-tx_bytes","wan-rx_bytes"], "start":window.start,"end":window.end});
        let read = self.collect_wan_bytes(site, &body).await;
        let bytes = match read {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                self.collect_wan_bytes(site, &body).await?
            }
            other => other?,
        };
        serde_json::from_slice(&bytes)
            .map(ActivityRead::Reported)
            .map_err(|error| crate::error::decode_failure(&error, &bytes))
    }
    async fn collect_wan_bytes(
        &self,
        site: &str,
        body: &serde_json::Value,
    ) -> Result<Vec<u8>, ApiError> {
        let (status, bytes) = self
            .execute_bytes(
                RequestClass::IdempotentRead,
                Method::POST,
                site,
                &["stat", "report", "hourly.site"],
                Some(body),
            )
            .await?;
        if let Some(rejected) = super::envelope_rejection(&bytes) {
            return Err(super::rejection(
                Some(status),
                rejected.code.as_deref(),
                &bytes,
            ));
        }
        Ok(bytes)
    }
}
