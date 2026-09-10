use std::net::IpAddr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::{net::TcpListener, signal};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;
use unifi_server::{
    config::Settings,
    gateway_manifest,
    server::{build_handler, build_router},
};

#[derive(Debug, Parser)]
#[command(version, about = "Curated UniFi MCP server")]
struct Args {
    /// Check only the local liveness endpoint and exit.
    #[arg(long)]
    healthcheck: bool,
    /// Print the annotation-native gateway manifest scaffold and exit.
    #[arg(long)]
    emit_gateway_manifest: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.healthcheck {
        return healthcheck().await;
    }
    let surface = Settings::surface_from_env().context("invalid runtime surface")?;
    if args.emit_gateway_manifest {
        print!("{}", gateway_manifest(surface));
        return Ok(());
    }

    let settings = Settings::from_env().context("invalid server configuration")?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_new(&settings.log_level).context("invalid log filter")?)
        .init();

    let handler = build_handler(&settings.runtime).context("build console clients")?;
    let cancellation = CancellationToken::new();
    let router = build_router(&settings, handler, &cancellation).context("compose HTTP router")?;
    let listener = TcpListener::bind((settings.host.as_str(), settings.port))
        .await
        .context("bind listener")?;
    let address = listener.local_addr().context("read bound address")?;
    info!(%address, "UniFi MCP listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown(cancellation))
        .await
        .context("serve HTTP")
}

async fn shutdown(cancellation: CancellationToken) {
    let _ = signal::ctrl_c().await;
    // Ending in-flight MCP streams lets graceful shutdown finish promptly.
    cancellation.cancel();
}

/// Map the configured bind address to the address the liveness probe dials.
///
/// A wildcard bind is reachable on loopback; a specific address or hostname
/// is only reachable on itself, so the probe must dial it directly.
fn probe_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) if address.is_unspecified() => "127.0.0.1".to_owned(),
        Ok(IpAddr::V6(address)) if address.is_unspecified() => "[::1]".to_owned(),
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        Ok(IpAddr::V4(address)) => address.to_string(),
        Err(_) => host.to_owned(),
    }
}

async fn healthcheck() -> Result<()> {
    let settings = Settings::listener_from_env().context("invalid listener configuration")?;
    let url = format!(
        "http://{}:{}/healthz",
        probe_host(&settings.host),
        settings.port
    );
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("build health client")?
        .get(url)
        .send()
        .await
        .context("health request")?;
    anyhow::ensure!(
        response.status().is_success(),
        "health endpoint is not ready"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::probe_host;

    #[test]
    fn wildcard_binds_probe_loopback() {
        assert_eq!(probe_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(probe_host("::"), "[::1]");
    }

    #[test]
    fn specific_addresses_are_probed_directly() {
        assert_eq!(probe_host("192.0.2.7"), "192.0.2.7");
        assert_eq!(probe_host("2001:db8::7"), "[2001:db8::7]");
        assert_eq!(probe_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn hostname_binds_are_probed_by_name() {
        assert_eq!(probe_host("unifi-mcp"), "unifi-mcp");
    }
}
