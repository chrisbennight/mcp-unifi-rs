use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use unifi_api::collection::{SourceReport, SourceStatus};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const START: u64 = 1_789_200_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "unifi-collection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "test helper accepts inline JSON fixtures"
)]
fn source(value: Value) -> SourceReport {
    SourceReport {
        status: SourceStatus::Collected,
        data: Some(serde_json::value::to_raw_value(&value).unwrap()),
        error: None,
    }
}

fn snapshot() -> TrafficSnapshot {
    TrafficSnapshot {
        start_ms: START,
        end_ms: START + HOUR,
        activity: source(
            serde_json::from_str(include_str!(
                "../../../unifi-mcp/tests/fixtures/network_10_6_106_activity.json"
            ))
            .unwrap(),
        ),
        graph: source(
            json!([{"timestamp":START,"interval_seconds":3600,"rx_byte-r":1.23,"extra":{"original":true}}]),
        ),
        wan: source(
            json!({"meta":{"rc":"ok","extra":"retained"},"data":[{"time":START,"wan-rx_bytes":901.0,"wan-tx_bytes":50.0}]}),
        ),
    }
}

fn settings(server: &MockServer, directory: &Directory) -> CollectionSettings {
    CollectionSettings {
        url: url::Url::parse(&server.uri()).unwrap(),
        org: "org".into(),
        bucket: "traffic".into(),
        token: zeroize::Zeroizing::new("test-token".into()),
        directory: directory.0.clone(),
        identity: "test-site".into(),
        cadence: Duration::from_secs(60),
        delay_ms: 0,
        history_hours: 24,
        correction_hours: 3,
        intervals_per_cycle: 4,
    }
}

#[test]
fn archive_preserves_unknown_fields_names_and_numeric_spelling() {
    let mut report = snapshot();
    let original = report
        .activity
        .data
        .as_ref()
        .unwrap()
        .get()
        .replace("Synthetic server", &"name ".repeat(700));
    report.activity.data = Some(serde_json::value::RawValue::from_string(original).unwrap());
    let publication = Publication::build(&report, "test").unwrap();
    let body = publication.batches.concat();
    let mut restored = Vec::new();
    for line in body
        .lines()
        .filter(|line| line.starts_with("unifi_archive,"))
    {
        let data = line
            .split(" data=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        restored.extend(STANDARD.decode(data).unwrap());
    }
    assert_eq!(restored, serde_json::to_vec(&report).unwrap());
    assert!(String::from_utf8(restored).unwrap().contains("fingerprint"));
    assert!(body.contains("unmatched_tx_bytes=-10"));
    assert!(body.contains("collected=true"));
    assert!(body.contains("client_rx_bytes=700u"));
    let long_name = "name ".repeat(14_000);
    let original = report
        .activity
        .data
        .as_ref()
        .unwrap()
        .get()
        .replace(&"name ".repeat(700), &long_name);
    report.activity.data = Some(serde_json::value::RawValue::from_string(original).unwrap());
    let publication = Publication::build(&report, "test").unwrap();
    let body = publication.batches.concat();
    assert!(body.contains("name_in_archive=true"));
    assert!(body.contains("collected=true"));
    assert!(body.contains("client_rx_bytes=700u"));
    let restored: Vec<u8> = body
        .lines()
        .filter(|line| line.starts_with("unifi_archive,"))
        .flat_map(|line| {
            STANDARD
                .decode(
                    line.split(" data=\"")
                        .nth(1)
                        .unwrap()
                        .split('"')
                        .next()
                        .unwrap(),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(restored, serde_json::to_vec(&report).unwrap());
    assert!(String::from_utf8(restored).unwrap().contains(&long_name));
}

#[test]
fn revisions_replace_removed_clients_and_fields_without_double_counting() {
    let first = snapshot();
    let one = Publication::build(&first, "test").unwrap();
    let replay = Publication::build(&first, "test").unwrap();
    assert_eq!(one.batches, replay.batches);
    assert_eq!(one.marker, replay.marker);
    let mut changed = snapshot();
    let mut activity: Value =
        serde_json::from_str(changed.activity.data.as_ref().unwrap().get()).unwrap();
    activity["client_usage_by_app"]
        .as_array_mut()
        .unwrap()
        .pop();
    changed.activity = source(activity);
    changed.wan = source(json!({"meta":{"rc":"ok"},"data":[]}));
    let two = Publication::build(&changed, "test").unwrap();
    assert_ne!(one.marker, two.marker);
    assert!(!two.batches.concat().contains("client=02:00:00:00:00:02"));
    assert!(!two.batches.concat().contains("site_rx_bytes="));
    assert_eq!(one.marker.split(' ').next(), two.marker.split(' ').next());
}

#[test]
fn empty_is_success_missing_is_not_zero_and_accounting_does_not_gate_collection() {
    let mut report = snapshot();
    report.activity = source(json!({"client_usage_by_app":[],"total_usage_by_app":[]}));
    report.wan = source(json!({"meta":{"rc":"ok"},"data":[]}));
    let body = Publication::build(&report, "test")
        .unwrap()
        .batches
        .concat();
    assert!(report.collected());
    assert!(body.contains("client_rx_bytes=0u"));
    assert!(!body.contains("site_rx_bytes="));
    report.graph.status = SourceStatus::Unsupported;
    assert!(!report.collected());
    let body = Publication::build(&report, "test")
        .unwrap()
        .batches
        .concat();
    assert!(body.contains("graph_status=\"unsupported\""));
    assert!(body.contains("collected=false"));
}

#[tokio::test]
async fn partial_sink_failure_never_publishes_selector_and_restart_replays_exact_revision() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    let report = snapshot();
    atomic_write(
        &directory.0,
        "pending.json",
        &serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v2/write"))
        .respond_with(ResponseTemplate::new(422).set_body_string("do not log rejected record"))
        .mount(&server)
        .await;
    assert!(worker.publish_pending().await.is_err());
    assert!(directory.0.join("pending.json").exists());
    assert!(worker.status.last_published_interval.is_none());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!String::from_utf8_lossy(&requests[0].body).contains("unifi_publication"));
    drop(worker);
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut restarted = Worker::new(settings(&server, &directory), &runtime).unwrap();
    restarted.publish_pending().await.unwrap();
    assert_eq!(restarted.status.last_published_interval, Some(START));
    assert!(!directory.0.join("pending.json").exists());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        String::from_utf8(requests.last().unwrap().body.clone()).unwrap(),
        Publication::build(&report, "test-site").unwrap().marker
    );
    assert!(requests.iter().all(|r| {
        r.url
            .query_pairs()
            .any(|(k, v)| k == "precision" && v == "ms")
    }));
}

#[tokio::test]
async fn lost_marker_response_replays_identical_data_before_advancing_checkpoint() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    let report = snapshot();
    atomic_write(
        &directory.0,
        "pending.json",
        &serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let markers = Arc::new(Mutex::new(Vec::new()));
    let observed = markers.clone();
    Mock::given(method("POST"))
        .respond_with(move |request: &wiremock::Request| {
            let body = String::from_utf8(request.body.clone()).unwrap();
            if body.starts_with("unifi_publication") {
                observed.lock().unwrap().push(body);
                // A failure after the server receives the marker models an unknown
                // write outcome. The client cannot infer whether it persisted.
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(204)
            }
        })
        .mount(&server)
        .await;
    assert!(worker.publish_pending().await.is_err());
    assert!(worker.publish_pending().await.is_err());
    let markers = markers.lock().unwrap();
    assert_eq!(markers.len(), 2);
    assert_eq!(markers[0], markers[1]);
    assert!(worker.status.last_published_interval.is_none());
}

#[tokio::test]
async fn scheduling_bounds_backfill_and_does_not_starve_new_intervals() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    let now = START + HOUR * 24;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        let times = worker.schedule(now);
        assert_eq!(times.len(), 4);
        worker.status.cursor = times.last().copied();
        seen.extend(times);
    }
    assert_eq!(seen.len(), 24);
    assert_eq!(seen.first(), Some(&START));
    assert_eq!(seen.last(), Some(&(now - HOUR)));
    worker.schedule(now + HOUR * 24);
    assert_eq!(worker.status.expired_gaps, 24);
    assert!(worker.status.intervals.values().all(|complete| !complete));
}

#[tokio::test]
async fn disabled_collection_has_no_effect_and_state_lock_prevents_two_workers() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let cancellation = CancellationToken::new();
    assert!(start(None, &runtime, &cancellation).unwrap().is_none());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    let worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    assert!(Worker::new(settings(&server, &directory), &runtime).is_err());
    let task = tokio::spawn(worker.run(cancellation.clone()));
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(Worker::new(settings(&server, &directory), &runtime).is_ok());
}

#[test]
fn disabled_configuration_does_not_require_or_parse_sink_settings() {
    assert!(CollectionSettings::read(|_| None).unwrap().is_none());
    assert!(
        CollectionSettings::read(
            |key| (key == "UNIFI_MCP_COLLECTION_INFLUX_URL").then(|| "invalid".into())
        )
        .unwrap()
        .is_none()
    );
    assert!(
        CollectionSettings::read(
            |key| (key == "UNIFI_MCP_COLLECTION_ENABLED").then(|| "true".into())
        )
        .is_err()
    );
}

#[tokio::test]
async fn later_batch_failure_keeps_previous_publication_and_cancellation_is_prompt() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let controller = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&controller)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/stat/report/hourly.site"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"meta":{"rc":"ok"},"data":[]})),
        )
        .mount(&controller)
        .await;
    let mut config = crate::config::test_support::controller();
    config.base_url = controller.uri().parse().unwrap();
    let runtime = RuntimeSettings::Network(config);
    let mut report = snapshot();
    let mut graph: Value = serde_json::from_str(report.graph.data.as_ref().unwrap().get()).unwrap();
    graph[0]["detail"] = json!("x".repeat(400_000));
    report.graph = source(graph);
    let publication = Publication::build(&report, "test-site").unwrap();
    assert!(publication.batches.len() > 1);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    Mock::given(method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::Relaxed) == 0 {
                ResponseTemplate::new(204)
            } else {
                ResponseTemplate::new(422)
            }
        })
        .mount(&server)
        .await;
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    atomic_write(
        &directory.0,
        "pending.json",
        &serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    assert!(worker.publish_pending().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(worker.status.last_published_interval.is_none());
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(worker.run(cancellation.clone()));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !server.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // An ordinary MCP report request stays usable while export is waiting.
    let handler = crate::server::build_handler(&runtime).unwrap();
    let mut request = rmcp::model::CallToolRequestParams::default();
    request.name = "stats.query".into();
    request.arguments =
        Some(serde_json::from_value(json!({"report":"wanHourly","hours":1})).unwrap());
    let response = tokio::time::timeout(Duration::from_secs(1), handler.call(&request, None))
        .await
        .unwrap();
    assert!(response.is_ok());
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(directory.0.join("pending.json").exists());
}

#[tokio::test]
async fn restart_rejects_changed_destination_before_export() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    drop(Worker::new(settings(&server, &directory), &runtime).unwrap());
    let mut changed = settings(&server, &directory);
    changed.bucket = "different".into();
    assert!(Worker::new(changed, &runtime).is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn restart_counts_hours_that_expired_before_they_could_be_scheduled() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    let old_end = START + 24 * HOUR;
    worker.schedule(old_end);
    worker
        .status
        .intervals
        .values_mut()
        .for_each(|complete| *complete = true);
    worker.save().unwrap();
    drop(worker);
    let mut restarted = Worker::new(settings(&server, &directory), &runtime).unwrap();
    restarted.schedule(old_end + 48 * HOUR);
    assert_eq!(restarted.status.expired_gaps, 24);
    assert_eq!(restarted.status.intervals.len(), 24);
    assert!(
        restarted
            .status
            .intervals
            .values()
            .all(|complete| !complete)
    );
    restarted.save().unwrap();
    drop(restarted);
    let mut restarted = Worker::new(settings(&server, &directory), &runtime).unwrap();
    restarted.schedule(old_end + 48 * HOUR);
    assert_eq!(
        restarted.status.expired_gaps, 24,
        "the same outage is not counted twice"
    );
}

#[tokio::test]
async fn pending_publication_recovery_preserves_unscheduled_outage_gaps() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
    let mut worker = Worker::new(settings(&server, &directory), &runtime).unwrap();
    let old_end = START + 24 * HOUR;
    worker.schedule(old_end);
    worker
        .status
        .intervals
        .values_mut()
        .for_each(|complete| *complete = true);
    worker.status.intervals.insert(START, false);
    worker.save().unwrap();
    atomic_write(
        &directory.0,
        "pending.json",
        &serde_json::to_vec(&snapshot()).unwrap(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(worker.publish_pending().await.is_err());
    drop(worker);
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut restarted = Worker::new(settings(&server, &directory), &runtime).unwrap();
    restarted.publish_pending().await.unwrap();
    restarted.schedule(old_end + 48 * HOUR);
    assert_eq!(restarted.status.expired_gaps, 24);
    assert_eq!(restarted.status.last_published_interval, Some(START));
}

#[tokio::test]
async fn unrecognized_wan_envelope_still_publishes_other_sources_and_advances() {
    let server = MockServer::start().await;
    let directory = Directory::new();
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/v2/api/site/default/traffic"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(snapshot().activity.data.unwrap().get()),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/v2/api/site/default/app-traffic-rate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/stat/report/hourly.site"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"meta":{"rc":"ok"}})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v2/write"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut controller = crate::config::test_support::controller();
    controller.base_url = server.uri().parse().unwrap();
    let runtime = RuntimeSettings::Network(controller);
    let mut config = settings(&server, &directory);
    config.history_hours = 1;
    config.correction_hours = 1;
    config.intervals_per_cycle = 1;
    let mut worker = Worker::new(config, &runtime).unwrap();
    worker.cycle().await.unwrap();
    assert!(worker.status.last_published_interval.is_some());
    assert_eq!(worker.status.cursor, worker.status.last_published_interval);
    assert!(worker.status.last_collected_interval.is_none());
    assert_eq!(worker.status.error.as_deref(), Some("source_incomplete"));
    assert!(!directory.0.join("pending.json").exists());
    let requests = server.received_requests().await.unwrap();
    let writes: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == "/api/v2/write")
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .collect();
    let body = writes.concat();
    assert!(body.contains("activity_status=\"collected\""));
    assert!(body.contains("graph_status=\"collected\""));
    assert!(body.contains("wan_status=\"unrecognized\""));
    assert!(body.contains("client_rx_bytes=700u"));
    assert!(writes.last().unwrap().starts_with("unifi_publication,"));
}
