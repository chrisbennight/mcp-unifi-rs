//! Optional deterministic collection into operator-owned `InfluxDB` OSS 2.x.
//! Traffic stays in the runtime and destination; status contains no report data.

mod config;
mod sink;

pub use config::CollectionSettings;

use crate::config::RuntimeSettings;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sink::{InfluxSink, Publication, digest};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use unifi_api::{LegacyClient, LegacyConfig, collection::TrafficSnapshot, traffic::ActivityWindow};

const HOUR: u64 = 3_600_000;
const MAX_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;

/// Only operational facts are persisted here; no controller responses or names.
#[derive(Default, Serialize, Deserialize)]
struct Status {
    binding: String,
    last_collected_interval: Option<u64>,
    last_published_interval: Option<u64>,
    updated_ms: u64,
    lag_ms: Option<u64>,
    records: usize,
    error: Option<String>,
    sink_available: Option<bool>,
    /// Start time -> whether all sources were retrieved and published.
    intervals: BTreeMap<u64, bool>,
    /// Cumulative count of unresolved intervals leaving the configured window.
    expired_gaps: u64,
    /// Round-robin cursor prevents an unavailable old interval starving new data.
    cursor: Option<u64>,
}

struct Worker {
    settings: CollectionSettings,
    client: LegacyClient,
    site: String,
    sink: InfluxSink,
    status: Status,
    _lock: File,
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => anyhow::bail!("collection_state_read"),
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("collection_state_read"))?;
    ensure!(bytes.len() <= maximum, "collection_state_bound");
    Ok(Some(bytes))
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    // Names are program constants, never controller-derived path components.
    let temporary = directory.join(format!("{name}.tmp"));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, directory.join(name))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

impl Worker {
    fn new(settings: CollectionSettings, runtime: &RuntimeSettings) -> Result<Self> {
        let RuntimeSettings::Network(controller) = runtime else {
            anyhow::bail!("collection requires Network reports");
        };
        std::fs::create_dir_all(&settings.directory)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(settings.directory.join("collector.lock"))?;
        lock.try_lock()
            .map_err(|_| anyhow::anyhow!("collection state directory already locked"))?;
        let binding = digest(
            serde_json::to_string(&(
                settings.identity.as_str(),
                controller.base_url.as_str(),
                controller.site.as_str(),
                settings.url.as_str(),
                settings.org.as_str(),
                settings.bucket.as_str(),
            ))?
            .as_bytes(),
        );
        let status = if let Some(bytes) =
            read_bounded(&settings.directory.join("status.json"), 128 * 1024)?
        {
            let status: Status = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid collection state"))?;
            ensure!(
                status.binding == binding,
                "collection state belongs to a different source or destination"
            );
            ensure!(
                status.intervals.len() <= 168,
                "collection state exceeds interval bound"
            );
            status
        } else {
            Status {
                binding,
                ..Status::default()
            }
        };
        let client = LegacyClient::new(&LegacyConfig {
            name: controller.name.clone(),
            base_url: controller.base_url.clone(),
            username: controller.username.clone(),
            password: controller.password.clone(),
            tls: controller.tls.clone(),
            timeout: controller.timeout,
        })?;
        let sink = InfluxSink::new(&settings)?;
        let worker = Self {
            settings,
            client,
            site: controller.site.clone(),
            sink,
            status,
            _lock: lock,
        };
        worker.save()?;
        Ok(worker)
    }

    fn save(&self) -> Result<()> {
        atomic_write(
            &self.settings.directory,
            "status.json",
            &serde_json::to_vec(&self.status)?,
        )
    }

    fn schedule(&mut self, now: u64) -> Vec<u64> {
        let end = now.saturating_sub(self.settings.delay_ms) / HOUR * HOUR;
        let start = end.saturating_sub(self.settings.history_hours * HOUR);
        // A stopped worker can miss entire hours beyond its last scheduled
        // window. Those hours never entered the map, but remain missing when
        // they are already too old for the current recovery window.
        if let Some((last, _)) = self.status.intervals.last_key_value() {
            self.status.expired_gaps += start.saturating_sub(last.saturating_add(HOUR)) / HOUR;
        }
        self.status.expired_gaps += self
            .status
            .intervals
            .iter()
            .filter(|(time, complete)| **time < start && !**complete)
            .count() as u64;
        self.status
            .intervals
            .retain(|time, _| *time >= start && *time < end);
        for time in (start..end).step_by(usize::try_from(HOUR).expect("hour fits usize")) {
            self.status.intervals.entry(time).or_insert(false);
        }
        let correction_start = end.saturating_sub(self.settings.correction_hours * HOUR);
        let mut candidates: Vec<_> = self
            .status
            .intervals
            .iter()
            .filter(|(time, complete)| !**complete || **time >= correction_start)
            .map(|(time, _)| *time)
            .collect();
        if let Some(cursor) = self.status.cursor {
            let split = candidates.partition_point(|time| *time <= cursor);
            candidates.rotate_left(split);
        }
        candidates.truncate(self.settings.intervals_per_cycle);
        candidates
    }

    async fn publish_pending(&mut self) -> Result<()> {
        let path = self.settings.directory.join("pending.json");
        let Some(bytes) = read_bounded(&path, MAX_ARCHIVE_BYTES)? else {
            return Ok(());
        };
        let snapshot: TrafficSnapshot = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid pending collection"))?;
        ensure!(
            snapshot.start_ms.checked_add(HOUR) == Some(snapshot.end_ms)
                && snapshot.start_ms.is_multiple_of(HOUR),
            "invalid pending interval"
        );
        let publication = Publication::build(&snapshot, &self.settings.identity)?;
        // Replaying identical content and selector is idempotent, including when
        // the previous response was lost. Do not fetch a new revision until this
        // durable pending revision has a successful acknowledgement.
        if self.sink.publish(&publication).await.is_err() {
            self.status.sink_available = Some(false);
            anyhow::bail!("publication_failed");
        }
        self.status.sink_available = Some(true);
        self.status.last_published_interval = Some(
            self.status
                .last_published_interval
                .unwrap_or(0)
                .max(snapshot.start_ms),
        );
        self.status.records = publication.records;
        self.status
            .intervals
            .insert(snapshot.start_ms, snapshot.collected());
        if snapshot.collected() {
            self.status.last_collected_interval = Some(
                self.status
                    .last_collected_interval
                    .unwrap_or(0)
                    .max(snapshot.start_ms),
            );
        }
        while self.status.intervals.len() > 168 {
            if let Some((_, false)) = self.status.intervals.pop_first() {
                self.status.expired_gaps += 1;
            }
        }
        self.status.cursor = Some(snapshot.start_ms);
        self.status.error = if snapshot.collected() {
            None
        } else {
            Some("source_incomplete".to_owned())
        };
        self.save()?;
        std::fs::remove_file(path)?;
        File::open(&self.settings.directory)?.sync_all()?;
        Ok(())
    }

    async fn cycle(&mut self) -> Result<()> {
        self.publish_pending().await?;
        let now = now_ms()?;
        let candidates = self.schedule(now);
        self.save()?;
        for start in candidates {
            let snapshot = self
                .client
                .collect_traffic(&self.site, ActivityWindow::new(start, start + HOUR)?)
                .await?;
            // Validate serialization and the complete publication before any
            // sink mutation or durable pending state is committed.
            Publication::build(&snapshot, &self.settings.identity)?;
            atomic_write(
                &self.settings.directory,
                "pending.json",
                &serde_json::to_vec(&snapshot)?,
            )?;
            if snapshot.collected() {
                self.status.last_collected_interval =
                    Some(self.status.last_collected_interval.unwrap_or(0).max(start));
            }
            self.save()?;
            self.publish_pending().await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }

    async fn run(mut self, cancellation: CancellationToken) {
        loop {
            let cycle = tokio::select! {
                () = cancellation.cancelled() => return,
                result = tokio::time::timeout(Duration::from_mins(30), self.cycle()) => result,
            };
            match cycle {
                Ok(Ok(())) => (),
                Ok(Err(_)) => {
                    self.status.error = Some("collection_or_publication_failed".to_owned());
                }
                Err(_) => self.status.error = Some("cycle_timeout".to_owned()),
            }
            self.status.updated_ms = now_ms().unwrap_or(self.status.updated_ms);
            self.status.lag_ms = self
                .status
                .last_published_interval
                .map(|time| self.status.updated_ms.saturating_sub(time + HOUR));
            if self.save().is_err() {
                tracing::error!(
                    error_kind = "collection_state_write",
                    "Collection status could not be saved"
                );
            }
            if let Some(category) = &self.status.error {
                tracing::warn!(
                    error_kind = category.as_str(),
                    "Traffic collection requires attention"
                );
            }
            tokio::select! {
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(self.settings.cadence) => (),
            }
        }
    }
}

/// Start a bounded worker for a long-running service. Disabled means no client,
/// destination request, state directory, or background task is created.
/// # Errors
/// Rejects invalid configuration, state binding, and concurrent state ownership.
pub fn start(
    settings: Option<CollectionSettings>,
    runtime: &RuntimeSettings,
    cancellation: &CancellationToken,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    settings
        .map(|settings| {
            Worker::new(settings, runtime)
                .map(|worker| tokio::spawn(worker.run(cancellation.child_token())))
        })
        .transpose()
}

#[cfg(test)]
mod tests;
