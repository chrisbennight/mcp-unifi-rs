//! Wire-level tests for the legacy controller client against loopback fakes.

#![recursion_limit = "256"]

use std::time::Duration;

use unifi_api::{ApiError, LegacyClient, LegacyConfig, TlsMode, models::WlanPatch};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};
use zeroize::Zeroizing;

const USERNAME: &str = "automation";
const PASSWORD: &str = "test-legacy-password";

#[test]
fn present_empty_protect_storage_distribution_remains_known_empty() {
    let distribution = serde_json::from_value::<unifi_api::protect::ProtectStorageDistribution>(
        serde_json::json!({"resolutionDistributions": []}),
    )
    .expect("storage distribution");

    assert!(
        distribution
            .resolution_distributions
            .as_ref()
            .is_some_and(Vec::is_empty)
    );
    assert!(distribution.recording_type_distributions.is_none());
}

fn client_for(server: &MockServer) -> LegacyClient {
    let config = LegacyConfig {
        name: "test".to_owned(),
        base_url: Url::parse(&server.uri()).expect("mock server uri"),
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    };
    LegacyClient::new(&config).expect("client")
}

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
}

fn login_body() -> serde_json::Value {
    serde_json::json!({"username": USERNAME, "password": PASSWORD})
}

#[tokio::test]
async fn unifi_os_sessions_carry_the_cookie_and_echo_csrf_on_mutations() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(login_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .insert_header("x-csrf-token", "csrf-1")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .and(header("cookie", "TOKEN=session-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "wlan", "status": "ok", "unmodelled": 3}]),
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/cmd/stamgr"))
        .and(header("cookie", "TOKEN=session-1"))
        .and(header("x-csrf-token", "csrf-1"))
        .and(body_json(
            serde_json::json!({"cmd": "kick-sta", "mac": "aa:bb:cc:dd:ee:ff"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let health = client.site_health("default").await.expect("health");
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].subsystem.as_deref(), Some("wlan"));
    assert_eq!(health[0].status.as_deref(), Some("ok"));

    // The MAC is normalized to the lowercase form the controller stores.
    client
        .kick_client("default", "AA:BB:CC:DD:EE:FF")
        .await
        .expect("kick");
}

#[tokio::test]
async fn standalone_controllers_fall_back_to_the_legacy_login_route() {
    let server = MockServer::start().await;
    // No /api/auth/login mock: the probe receives the mock server's default
    // 404, which is exactly the standalone detection signal.
    Mock::given(method("POST"))
        .and(path("/api/login"))
        .and(body_json(login_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "unifises=abc; Path=/")
                .set_body_json(ok_envelope(&serde_json::json!([]))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/s/default/stat/health"))
        .and(header("cookie", "unifises=abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "www", "status": "ok"}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let health = client_for(&server)
        .site_health("default")
        .await
        .expect("health");
    assert_eq!(health[0].subsystem.as_deref(), Some("www"));
}

#[tokio::test]
async fn expired_sessions_reauthenticate_once_and_replay_the_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "wan", "status": "ok"}]),
        )))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(401).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.LoginRequired"}}),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "wan", "status": "ok"}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.site_health("default").await.expect("first read");
    let replayed = client.site_health("default").await.expect("replayed read");
    assert_eq!(replayed[0].subsystem.as_deref(), Some("wan"));
}

#[tokio::test]
async fn concurrent_expiry_observers_share_one_refresh_instead_of_stampeding() {
    let server = MockServer::start().await;
    // Two logins total: the initial session plus exactly one refresh, no
    // matter how many in-flight requests observe the same expiry.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(2)
        .mount(&server)
        .await;
    // The delay holds both concurrent requests in flight until each has
    // received the same-generation expiry, forcing the stampede window.
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_delay(Duration::from_millis(200))
                .set_body_json(
                    serde_json::json!({"meta": {"rc": "error", "msg": "api.err.LoginRequired"}}),
                ),
        )
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "wan", "status": "ok"}]),
        )))
        .expect(2)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let (first, second) =
        tokio::join!(client.site_health("default"), client.site_health("default"));
    first.expect("first concurrent read");
    second.expect("second concurrent read");
}

#[tokio::test]
async fn a_failed_initial_login_is_shared_with_immediate_followers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "600"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let first = client
        .site_health("default")
        .await
        .expect_err("rate limited login");
    assert!(matches!(first, ApiError::RateLimited { .. }));
    // Inside the backoff window the follower shares the outcome; the login
    // mock's expectation of one call is the stampede guard.
    let second = client
        .site_health("default")
        .await
        .expect_err("shared login failure");
    assert!(matches!(second, ApiError::RateLimited { .. }));
}

#[tokio::test]
async fn a_reflected_password_is_scrubbed_from_login_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": format!("bad credentials: {PASSWORD}")},
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("login rejected");
    let rendered = format!("{error} / {error:?}");
    assert!(
        !rendered.contains(PASSWORD),
        "password must never survive into the error surface"
    );
    assert!(rendered.contains("<redacted>"));
}

#[tokio::test]
async fn bodies_without_an_envelope_forward_no_upstream_content() {
    // Literal scrubbing cannot match a credential hidden behind
    // serialization escapes, so an unrecognized body must never be echoed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "detail": format!("submitted \"{PASSWORD}\" was rejected"),
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("login rejected");
    let rendered = format!("{error} / {error:?}");
    assert!(!rendered.contains(PASSWORD));
    assert!(
        !rendered.contains("submitted"),
        "no upstream content at all"
    );
    assert!(rendered.contains("no recognizable error envelope"));

    let plain = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(format!("gateway error while proxying {PASSWORD}")),
        )
        .expect(1)
        .mount(&plain)
        .await;

    let error = client_for(&plain)
        .site_health("default")
        .await
        .expect_err("login failed");
    let rendered = format!("{error} / {error:?}");
    assert!(!rendered.contains(PASSWORD));
    assert!(!rendered.contains("proxying"), "no upstream content at all");
}

#[tokio::test]
async fn a_failed_refresh_is_shared_across_concurrent_expiry_observers() {
    let server = MockServer::start().await;
    // Exactly two logins: the initial session and the one failed refresh;
    // the second observer receives the shared failure without logging in.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "600"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_delay(Duration::from_millis(200))
                .set_body_json(
                    serde_json::json!({"meta": {"rc": "error", "msg": "api.err.LoginRequired"}}),
                ),
        )
        .up_to_n_times(2)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let (first, second) =
        tokio::join!(client.site_health("default"), client.site_health("default"));
    assert!(matches!(
        first.expect_err("shared refresh failure"),
        ApiError::RateLimited { .. }
    ));
    assert!(matches!(
        second.expect_err("shared refresh failure"),
        ApiError::RateLimited { .. }
    ));
}

#[tokio::test]
async fn a_reflected_password_in_a_2xx_rejection_envelope_is_scrubbed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": format!("denied for {PASSWORD}")},
            "data": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("rejected");
    let rendered = format!("{error} / {error:?}");
    assert!(!rendered.contains(PASSWORD));
    assert!(rendered.contains("<redacted>"));
}

#[tokio::test]
async fn a_2xx_login_carrying_a_rejection_envelope_is_not_a_session() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("rejected login");
    let ApiError::Rejected { code, .. } = error else {
        panic!("expected Rejected, got {error:?}");
    };
    assert_eq!(code.as_str(), "api.err.Invalid");
}

#[tokio::test]
async fn a_2xx_login_rejection_without_a_code_is_still_not_a_session() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"meta": {"rc": "error"}, "data": []})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("rejected login");
    assert!(matches!(error, ApiError::Rejected { .. }));
}

#[tokio::test]
async fn a_rate_limited_login_surfaces_immediately_and_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("rate limited login");
    assert!(matches!(error, ApiError::RateLimited { .. }));
}

#[tokio::test]
async fn a_transient_probe_failure_does_not_latch_console_detection() {
    let server = MockServer::start().await;
    // The first detection probe hits a transient 503; once it clears, the
    // unmatched probe route answers the mock server's default 404 and the
    // client must still detect the standalone console.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "unifises=abc; Path=/")
                .set_body_json(ok_envelope(&serde_json::json!([]))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"subsystem": "www", "status": "ok"}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .site_health("default")
        .await
        .expect_err("transient probe failure surfaces");
    // Outlast the transient failure's shared backoff window.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let health = client
        .site_health("default")
        .await
        .expect("standalone detection after the transient clears");
    assert_eq!(health[0].subsystem.as_deref(), Some("www"));
}

#[tokio::test]
async fn mfa_accounts_fail_with_actionable_guidance() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.Ubic2faTokenRequired"}}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("mfa rejected");
    let ApiError::Rejected { code, message } = error else {
        panic!("expected Rejected, got {error:?}");
    };
    assert_eq!(code.as_str(), "api.err.Ubic2faTokenRequired");
    assert!(message.as_str().contains("local administrator without MFA"));
}

#[tokio::test]
async fn envelope_rejections_translate_the_documented_codes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.NoPermission"}, "data": []}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .site_health("default")
        .await
        .expect_err("permission rejected");
    let ApiError::Rejected { code, message } = error else {
        panic!("expected Rejected, got {error:?}");
    };
    assert_eq!(code.as_str(), "api.err.NoPermission");
    assert!(message.as_str().contains("permission"));
}

#[test]
fn debug_output_never_contains_the_password() {
    let config = LegacyConfig {
        name: "home".to_owned(),
        base_url: Url::parse("https://192.0.2.1").expect("url"),
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    };
    let formatted = format!("{config:?}");
    assert!(!formatted.contains(PASSWORD));
    assert!(formatted.contains("<redacted>"));
    assert!(formatted.contains(USERNAME));
}

async fn logged_in_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .insert_header("x-csrf-token", "csrf-1")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn resource_reads_decode_their_allowlisted_projections() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/portforward")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([{
                "_id": "pf1",
                "name": "web",
                "enabled": true,
                "fwd": "192.0.2.20",
                "fwd_port": "8080",
                "dst_port": "443",
                "proto": "tcp",
            }]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/trafficrule")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"_id": "tr1", "description": "block tiktok", "enabled": true, "action": "BLOCK"}]),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/trafficroute")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"_id": "tro1", "description": "vpn egress", "enabled": false}]),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/stat/rogueap")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"bssid": "aa:aa:aa:aa:aa:aa", "essid": "neighbor", "channel": 6, "rssi": -70}]),
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/sitedpi")))
        .and(body_json(serde_json::json!({"type": "by_app"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"app": 133, "cat": 4, "rx_bytes": 1000, "tx_bytes": 2000}]),
        )))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let forwards = client.port_forwards("default").await.expect("forwards");
    assert_eq!(forwards[0].fwd.as_deref(), Some("192.0.2.20"));
    let rules = client
        .traffic_rules("default")
        .await
        .expect("traffic rules");
    assert_eq!(rules[0].action.as_deref(), Some("BLOCK"));
    let routes = client
        .traffic_routes("default")
        .await
        .expect("traffic routes");
    assert_eq!(routes[0].enabled, Some(false));
    let rogues = client.rogue_aps("default").await.expect("rogues");
    assert_eq!(rogues[0].rssi, Some(-70));
    let dpi = client.dpi_by_application("default").await.expect("dpi");
    assert_eq!(dpi[0].rx_bytes, Some(1000));
}

#[tokio::test]
async fn active_clients_decode_association_and_addressing_fields() {
    let server = logged_in_server().await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/sta"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "laptop",
                    "ip": "192.168.1.50",
                    "essid": "HomeNet",
                    "vlan": 10,
                    "ap_mac": "11:22:33:44:55:66",
                    "signal": -52,
                    "tx_bytes": 1024,
                    "rx_bytes": 2048,
                    "uptime": 3600,
                    "is_wired": false,
                    "use_fixedip": true,
                    "fixed_ip": "192.168.1.50",
                    "unmodelled_field": {"nested": true}
                },
            ]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let clients = client_for(&server)
        .active_clients("default")
        .await
        .expect("clients");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].hostname.as_deref(), Some("laptop"));
    assert_eq!(clients[0].essid.as_deref(), Some("HomeNet"));
    assert_eq!(clients[0].vlan, Some(10));
    assert_eq!(clients[0].signal, Some(-52));
    assert_eq!(clients[0].is_wired, Some(false));
    assert_eq!(clients[0].fixed_ip.as_deref(), Some("192.168.1.50"));
}

#[tokio::test]
async fn network_and_wlan_configuration_reads_decode_allowlisted_fields() {
    let server = logged_in_server().await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/networkconf"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"_id": "net-1", "name": "LAN", "purpose": "corporate", "vlan": 10,
                 "ip_subnet": "192.168.10.1/24", "enabled": true, "dhcpd_enabled": true,
                 "dhcpd_start": "192.168.10.100", "dhcpd_stop": "192.168.10.200"},
            ]))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/wlanconf"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"_id": "wlan-1", "name": "HomeNet", "enabled": true, "security": "wpapsk",
                 "x_passphrase": "wifi-secret-passphrase", "networkconf_id": "net-1",
                 "hide_ssid": false},
            ]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let networks = client.networks("default").await.expect("networks");
    assert_eq!(networks[0].vlan, Some(10));
    assert_eq!(networks[0].dhcpd_start.as_deref(), Some("192.168.10.100"));
    let wlans = client.wlans("default").await.expect("wlans");
    assert_eq!(wlans[0].name.as_deref(), Some("HomeNet"));
    assert_eq!(
        wlans[0].x_passphrase.as_deref(),
        Some("wifi-secret-passphrase")
    );
}

#[tokio::test]
async fn event_and_alarm_reads_clamp_their_limits() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/event")))
        .and(body_json(serde_json::json!({"_limit": 1000})))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"key": "EVT_WU_Connected", "msg": "client connected", "time": 1_755_300_000_000_u64, "subsystem": "wlan"}]),
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/alarm")))
        .and(body_json(serde_json::json!({"_limit": 25, "archived": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"_id": "al1", "key": "EVT_GW_WANTransition", "msg": "wan down", "time": 1_755_300_000_000_u64, "archived": false}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    // An over-large request is clamped to the bounded page.
    let events = client.events("default", 5000).await.expect("events");
    assert_eq!(events[0].key.as_deref(), Some("EVT_WU_Connected"));
    let alarms = client.alarms("default", 25).await.expect("alarms");
    assert_eq!(alarms[0].archived, Some(false));
}

#[tokio::test]
async fn report_windows_are_validated_before_any_request() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/report/hourly.site")))
        .and(body_json(serde_json::json!({
            "attrs": ["time", "wan-tx_bytes", "wan-rx_bytes"],
            "start": 1_755_200_000_000_u64,
            "end": 1_755_286_400_000_u64,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"time": 1_755_200_000_000_u64, "wan-tx_bytes": 1.5e9, "wan-rx_bytes": 2.5e9}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let samples = client
        .hourly_wan_report("default", 1_755_200_000_000, 1_755_286_400_000)
        .await
        .expect("report");
    assert_eq!(samples[0].wan_rx_bytes, Some(2.5e9));

    let inverted = client
        .hourly_wan_report("default", 2, 1)
        .await
        .expect_err("inverted window");
    assert!(matches!(inverted, ApiError::Config(_)));
    let too_wide = client
        .hourly_wan_report("default", 0, 8 * 24 * 60 * 60 * 1000)
        .await
        .expect_err("over-wide window");
    assert!(matches!(too_wide, ApiError::Config(_)));
}

#[tokio::test]
async fn device_commands_post_their_envelopes_with_csrf() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/cmd/devmgr")))
        .and(header("x-csrf-token", "csrf-1"))
        .and(body_json(
            serde_json::json!({"cmd": "restart", "mac": "aa:bb:cc:dd:ee:ff"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/cmd/devmgr")))
        .and(body_json(
            serde_json::json!({"cmd": "set-locate", "mac": "aa:bb:cc:dd:ee:ff"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/cmd/devmgr")))
        .and(body_json(
            serde_json::json!({"cmd": "unset-locate", "mac": "aa:bb:cc:dd:ee:ff"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .restart_device("default", "AA:BB:CC:DD:EE:FF")
        .await
        .expect("restart");
    client
        .locate_device("default", "aa:bb:cc:dd:ee:ff", true)
        .await
        .expect("locate on");
    client
        .locate_device("default", "aa:bb:cc:dd:ee:ff", false)
        .await
        .expect("locate off");
}

#[tokio::test]
async fn rate_limited_post_bodied_reads_retry_once_like_any_idempotent_read() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/event")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/stat/event")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(
            &serde_json::json!([{"key": "EVT_WU_Connected", "msg": "ok", "time": 1_755_300_000_000_u64}]),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let events = client_for(&server)
        .events("default", 10)
        .await
        .expect("retried idempotent read");
    assert_eq!(events[0].key.as_deref(), Some("EVT_WU_Connected"));
}

#[tokio::test]
async fn a_wireless_update_sends_only_the_fields_it_was_given() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    // The body carries exactly the two set fields: an absent field means
    // "leave alone", so serializing it as null would clear configuration the
    // caller never mentioned.
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .and(header("x-csrf-token", "csrf-1"))
        .and(body_json(
            serde_json::json!({"enabled": false, "hide_ssid": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        enabled: Some(false),
        hide_ssid: Some(true),
        ..WlanPatch::default()
    };
    client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect("update");
}

#[tokio::test]
async fn a_wireless_update_carrying_a_passphrase_puts_it_on_the_wire_but_never_in_debug() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .and(body_json(serde_json::json!({
            "security": "wpapsk",
            "x_passphrase": "new-wifi-secret",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        security: Some("wpapsk".to_owned()),
        x_passphrase: Some(Zeroizing::new("new-wifi-secret".to_owned())),
        ..WlanPatch::default()
    };
    // The value reaches the controller, because that is the write's purpose.
    client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect("update");
    // It never reaches diagnostic output, which is where it would leak.
    let rendered = format!("{patch:?}");
    assert!(!rendered.contains("new-wifi-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[tokio::test]
async fn an_empty_wireless_update_is_refused_before_any_upstream_call() {
    // No mock is mounted: reaching the controller at all would fail the test,
    // which is the point. A write that cannot change anything must not count
    // as a mutation against the controller.
    let server = logged_in_server().await;
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &WlanPatch::default())
        .await
        .expect_err("empty patch");
    assert!(matches!(error, ApiError::Config(_)), "{error:?}");
}

#[tokio::test]
async fn a_rejected_wireless_update_surfaces_the_controller_refusal() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.NoPermission"}, "data": []}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        enabled: Some(true),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rejection");
    assert!(matches!(error, ApiError::Rejected { .. }), "{error:?}");
}

#[tokio::test]
async fn a_rate_limited_wireless_update_is_never_resent() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    // A resent write could apply twice, so a mutation gets no retry even
    // when the controller offers an immediate Retry-After.
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        enabled: Some(true),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rate limited");
    assert!(matches!(error, ApiError::RateLimited { .. }), "{error:?}");
}

#[tokio::test]
async fn a_single_wireless_read_returns_the_row_and_names_a_missing_id() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([{
                "_id": "wlan-1",
                "name": "Home",
                "enabled": true,
                "security": "wpapsk",
                "x_passphrase": "current-secret",
                "hide_ssid": false,
            }]))),
        )
        .mount(&server)
        .await;
    // An `ok` envelope with no rows is how the controller reports an id that
    // matched nothing; it must not decode into a phantom resource.
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/wlanconf/absent")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let wlan = client.wlan("default", "wlan-1").await.expect("wlan");
    assert_eq!(wlan.id, "wlan-1");
    assert_eq!(wlan.name.as_deref(), Some("Home"));
    assert_eq!(wlan.x_passphrase.as_deref(), Some("current-secret"));

    let missing = client
        .wlan("default", "absent")
        .await
        .expect_err("absent id");
    assert!(matches!(missing, ApiError::Rejected { .. }), "{missing:?}");
}

#[tokio::test]
async fn a_passphrase_reflected_in_a_rejection_never_survives_in_the_error() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    let secret = "reflected-wifi-secret";
    // A controller that quotes the submitted value back in its rejection is
    // the leak path: the error is what reaches logs and diagnostic output.
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": format!("invalid passphrase {secret}")},
            "data": [],
        })))
        .mount(&server)
        .await;

    let patch = WlanPatch {
        x_passphrase: Some(Zeroizing::new(secret.to_owned())),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rejection");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(secret), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[tokio::test]
async fn a_reflected_passphrase_is_scrubbed_from_a_non_2xx_rejection_too() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    let secret = "another-wifi-secret";
    // The same reflection can arrive on the error-status path, which builds
    // its rejection through a different branch.
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": format!("api.err.Invalid {secret}")},
            "data": [],
        })))
        .mount(&server)
        .await;

    let patch = WlanPatch {
        x_passphrase: Some(Zeroizing::new(secret.to_owned())),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rejection");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(secret), "{rendered}");
}

#[tokio::test]
async fn a_secret_containing_the_login_password_is_redacted_whole() {
    let server = logged_in_server().await;
    let prefix = "/proxy/network/api/s/default";
    // The passphrase contains the login password. Replacing secrets one after
    // another would consume the password first and leave the surrounding
    // characters of the passphrase behind.
    let secret = format!("wifi-{PASSWORD}-suffix");
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": format!("rejected {secret}")},
            "data": [],
        })))
        .mount(&server)
        .await;

    let patch = WlanPatch {
        x_passphrase: Some(Zeroizing::new(secret.clone())),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rejection");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("wifi-"), "{rendered}");
    assert!(!rendered.contains("-suffix"), "{rendered}");
    assert!(!rendered.contains(PASSWORD), "{rendered}");
}

#[tokio::test]
async fn a_mutation_never_resends_on_an_expiry_token_carried_in_message_text() {
    let server = MockServer::start().await;
    // One login only: the write must not earn a refresh-and-resend from text
    // the controller echoed back.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let prefix = "/proxy/network/api/s/default";
    // Exactly one PUT is allowed. A passphrase set to the expiry token and
    // echoed back as the whole message must not be read as session expiry.
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"meta": {"rc": "error", "msg": "api.err.LoginRequired"}, "data": []}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        x_passphrase: Some(Zeroizing::new("api.err.LoginRequired".to_owned())),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("rejection, not a replay");
    assert!(matches!(error, ApiError::Rejected { .. }), "{error:?}");
}

#[tokio::test]
async fn a_mutation_is_not_resent_even_when_the_status_reports_the_session_gone() {
    let server = MockServer::start().await;
    // The session is still refreshed, so the caller's next attempt starts
    // clean; what must not happen is this write going out a second time.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("PUT"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let patch = WlanPatch {
        enabled: Some(true),
        ..WlanPatch::default()
    };
    let error = client_for(&server)
        .update_wlan("default", "wlan-1", &patch)
        .await
        .expect_err("surfaced rather than resent");
    assert!(matches!(error, ApiError::Rejected { .. }), "{error:?}");
}

#[tokio::test]
async fn a_read_still_reauthenticates_and_replays_after_the_same_signal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let prefix = "/proxy/network/api/s/default";
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/rest/wlanconf/wlan-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([{
                "_id": "wlan-1",
                "name": "Home",
            }]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let wlan = client_for(&server)
        .wlan("default", "wlan-1")
        .await
        .expect("replayed read");
    assert_eq!(wlan.id, "wlan-1");
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one full-shape fixture proves both the allowlist and the operational projection"
)]
async fn protect_bootstrap_decodes_only_the_bounded_inventory_projection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(login_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .and(header("cookie", "TOKEN=protect-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authUser": {"email": "must-not-enter-the-model@example.invalid"},
            "cameras": [{
                "id": "cam-front", "modelKey": "camera", "guid": "camera-guid",
                "mac": "aa:bb:cc:dd:ee:ff", "name": "Front Door", "type": "UVC G5 Bullet",
                "marketName": "G5 Bullet", "state": "CONNECTED",
                "firmwareVersion": "4.72.44", "latestFirmwareVersion": "4.73.10",
                "hardwareRevision": "12", "connectedSince": 1000, "lastSeen": 2000,
                "lastDisconnect": 900, "uptime": 100_000, "isUpdating": false,
                "isDownloadingFW": true, "isRebooting": false, "isRestoring": false,
                "isAttemptingToConnect": false, "isRecording": true,
                "isMicEnabled": true, "micVolume": 80, "hasRecordings": true,
                "isPoorNetwork": false, "videoMode": "default", "is2K": true,
                "is4K": false, "isThirdPartyCamera": false, "isPairedWithAiPort": true,
                "recordingSettings": {"mode": "always"},
                "featureFlags": {
                    "isDoorbell": false, "hasMic": true, "hasSpeaker": true,
                    "hasWifi": true, "hasHdr": true, "hasPackageCamera": false,
                    "hasSmartDetect": true, "hasLedStatus": true,
                    "canOpticalZoom": false, "hasAutoICROnly": true, "isPtz": false,
                    "smartDetectTypes": ["person", "vehicle"],
                    "smartDetectAudioTypes": ["smoke"]
                },
                "wifiConnectionState": {
                    "signalQuality": 91, "signalStrength": -48, "phyRate": 866.7,
                    "txRate": 400.5, "channel": 44, "frequency": 5220,
                    "experience": "excellent", "connectivity": "full",
                    "ssid": "must-not-enter-the-model-ssid",
                    "bssid": "11:22:33:44:55:66", "apName": "private-ap"
                },
                "channels": [{"rtspAlias": "must-not-enter-the-model-stream"}]
            }],
            "nvr": {
                "id": "nvr-1", "modelKey": "nvr", "guid": "nvr-guid",
                "mac": "00:11:22:33:44:55", "name": "Recorder", "type": "UNVR",
                "marketName": "Network Video Recorder", "version": "7.1.87",
                "ucoreVersion": "4.1.13", "isDbAvailable": true,
                "isRecordingDisabled": false, "isRecordingMotionOnly": false,
                "disableAudio": false, "isRecycling": true, "corruptionState": "normal",
                "hardDriveState": "normal", "lastDriveSlowEvent": 1234,
                "cameraUtilization": 37,
                "maxCameraCapacity": {"4K": 15, "2K": 25, "HD": 50},
                "storageStats": {
                    "capacity": 7_776_000_000_u64, "remainingCapacity": 2_592_000_000_u64,
                    "utilization": 0.66,
                    "recordingSpace": {"total": 1_000_000, "used": 660_000, "available": 340_000},
                    "storageDistribution": {
                        "recordingTypeDistributions": [
                            {"recordingType": "detections", "size": 100, "percentage": 0.1},
                            {"recordingType": "continuous"}
                        ]
                    }
                },
                "hosts": ["private-host"],
                "systemInfo": {"ustorage": {"disks": [{"serial": "private-disk-serial"}]}}
            },
            "users": [{"email": "another-user@example.invalid"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let bootstrap = client_for(&server)
        .protect_bootstrap()
        .await
        .expect("bounded bootstrap");
    assert_eq!(bootstrap.cameras.len(), 1);
    let camera = &bootstrap.cameras[0];
    assert_eq!(camera.market_name.as_deref(), Some("G5 Bullet"));
    assert_eq!(camera.is_recording, Some(true));
    assert_eq!(
        camera
            .feature_flags
            .as_ref()
            .expect("features")
            .smart_detect_types,
        ["person", "vehicle"]
    );
    assert_eq!(
        bootstrap
            .nvr
            .max_camera_capacity
            .as_ref()
            .expect("capacity")
            .four_k,
        Some(15)
    );
    assert_eq!(
        bootstrap
            .nvr
            .storage_stats
            .as_ref()
            .expect("storage")
            .recording_space
            .as_ref()
            .expect("recording space")
            .available,
        Some(340_000)
    );
    let distributions = bootstrap
        .nvr
        .storage_stats
        .as_ref()
        .and_then(|storage| storage.storage_distribution.as_ref())
        .expect("storage distributions");
    let recording_types = distributions
        .recording_type_distributions
        .as_ref()
        .expect("recording type distributions");
    assert_eq!(
        recording_types[1].recording_type.as_deref(),
        Some("continuous")
    );
    assert_eq!(recording_types[1].size, None);
    assert!(distributions.resolution_distributions.is_none());

    let debug = format!("{bootstrap:?}");
    for excluded in [
        "must-not-enter-the-model@example.invalid",
        "another-user@example.invalid",
        "must-not-enter-the-model-stream",
        "must-not-enter-the-model-ssid",
        "11:22:33:44:55:66",
        "private-ap",
        "private-host",
        "private-disk-serial",
    ] {
        assert!(
            !debug.contains(excluded),
            "private value entered wire model"
        );
    }
}

#[tokio::test]
async fn protect_bootstrap_rejects_wrong_resource_discriminators() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "cameras": [{"id": "cam-a", "modelKey": "nvr"}],
            "nvr": {"id": "nvr-a", "modelKey": "nvr"}
        })))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .protect_bootstrap()
        .await
        .expect_err("wrong camera discriminator");
    assert!(matches!(error, ApiError::SchemaMismatch { .. }));
    assert!(error.to_string().contains("cameras.modelKey"));
}

#[tokio::test]
async fn protect_camera_inventory_does_not_depend_on_the_recorder_projection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "cameras": [{"id": "cam-a", "modelKey": "camera", "name": "Front"}],
            "nvr": "an unrelated recorder shape"
        })))
        .mount(&server)
        .await;

    let cameras = client_for(&server)
        .protect_camera_inventory()
        .await
        .expect("camera-only bootstrap projection");
    assert_eq!(cameras.len(), 1);
    assert_eq!(cameras[0].id, "cam-a");
}

#[tokio::test]
async fn protect_bootstrap_distinguishes_a_missing_camera_member_from_an_empty_inventory() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "nvr": {"id": "nvr-a", "modelKey": "nvr"}
        })))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .protect_bootstrap()
        .await
        .expect_err("missing cameras member");
    assert!(matches!(error, ApiError::SchemaMismatch { .. }));
}

#[tokio::test]
async fn protect_bootstrap_rejects_inventory_above_the_camera_ceiling() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    let cameras: Vec<serde_json::Value> = (0..=1000)
        .map(|index| serde_json::json!({"id": format!("cam-{index}"), "modelKey": "camera"}))
        .collect();
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "cameras": cameras,
            "nvr": {"id": "nvr-a", "modelKey": "nvr"}
        })))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .protect_bootstrap()
        .await
        .expect_err("inventory ceiling");
    assert!(matches!(error, ApiError::SchemaMismatch { .. }));
    assert!(error.to_string().contains("cameras"));
}

#[tokio::test]
async fn protect_events_page_without_a_scan_ceiling_uses_a_time_keyset() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(login_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(header("cookie", "TOKEN=protect-session"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "2000"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .and(query_param("orderDirection", "DESC"))
        .and(query_param("types", "motion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": "event-3",
                "type": "smartDetectZone",
                "start": 1900,
                "end": 1950,
                "score": 91,
                "camera": "cam-front",
                "smartDetectTypes": ["person"],
                "metadata": {"detectedThumbnails": ["must-not-leave-the-client"]},
                "thumbnail": "base64-must-not-leave-the-client"
            },
            {"id": "event-2", "type": "motion", "start": 1800,
             "camera": "cam-front"},
            {"id": "event-1", "type": "ring", "start": 1100,
             "camera": "cam-front"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(header("cookie", "TOKEN=protect-session"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "1799"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .and(query_param("orderDirection", "DESC"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-1", "type": "ring", "start": 1100,
             "camera": "cam-front"},
            {"id": "event-before-window", "type": "motion", "start": 999}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let first = client
        .protect_events(1000, 2000, 2, None)
        .await
        .expect("first page");
    assert_eq!(first.scanned_rows, 2);
    assert_eq!(first.events.len(), 2);
    assert_eq!(first.events[0].id, "event-3");
    assert_eq!(first.events[0].kind, "smartDetectZone");
    assert_eq!(first.events[0].camera.as_deref(), Some("cam-front"));
    assert_eq!(first.events[0].smart_detect_types, ["person"]);
    let continuation = first.next.expect("continuation");
    assert_eq!(continuation.next_end, 1799);

    let second = client
        .protect_events(1000, 2000, 2, Some(&continuation))
        .await
        .expect("second page");
    assert_eq!(second.scanned_rows, 2);
    assert_eq!(second.events.len(), 1);
    assert_eq!(second.events[0].id, "event-1");
    assert!(second.next.is_none(), "the page crossed the window start");
}

#[tokio::test]
async fn an_inverted_protect_event_window_is_rejected_before_login() {
    let server = MockServer::start().await;
    let error = client_for(&server)
        .protect_events(2000, 1000, 10, None)
        .await
        .expect_err("inverted window");
    assert!(matches!(error, ApiError::Config(_)), "{error:?}");
    assert!(error.to_string().contains("start is after end"), "{error}");
}

#[tokio::test]
async fn protect_event_time_keyset_is_immune_to_newer_balanced_churn() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(login_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("end", "2000"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-2", "type": "motion", "start": 1900},
            {"id": "event-1", "type": "motion", "start": 1800},
            {"id": "event-0", "type": "motion", "start": 1700}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("end", "1799"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-0", "type": "motion", "start": 1700}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let first = client
        .protect_events(1000, 2000, 2, None)
        .await
        .expect("first page");
    // Removing event-2 and inserting an event at 1850 cannot shift the next
    // request: its upper time key is already below both of them.
    let second = client
        .protect_events(1000, 2000, 2, first.next.as_ref())
        .await
        .expect("older page");
    assert_eq!(second.events.len(), 1);
    assert_eq!(second.events[0].id, "event-0");
    assert!(second.next.is_none());
}

#[tokio::test]
async fn protect_event_page_fails_loud_instead_of_splitting_one_timestamp() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("limit", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-3", "type": "motion", "start": 1900},
            {"id": "event-2", "type": "motion", "start": 1900},
            {"id": "event-1", "type": "motion", "start": 1900}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .protect_events(1000, 2000, 2, None)
        .await
        .expect_err("equal timestamp boundary must not be split");
    assert!(
        error.to_string().contains("retry with a higher limit"),
        "{error}"
    );
}
