use fridgep0t::config::Config;
use fridgep0t::fields;
use fridgep0t::server::{accept_loop, App, Service};
use fridgep0t::tls;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fridgep0t: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    let app = App::new(cfg.clone())?;

    let mut handles = Vec::new();

    let http_addr = SocketAddr::new(cfg.bind, cfg.http_port);
    let http = TcpListener::bind(http_addr)
        .await
        .map_err(|e| format!("bind {http_addr}: {e}"))?;
    {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            accept_loop(app, http, Service::Http).await
        }));
    }

    if cfg.https_port != 0 {
        let cert = tls::load_or_generate(&cfg, &app.id)?;
        let tls_cfg = tls::server_config(cert)?;
        let addr = SocketAddr::new(cfg.bind, cfg.https_port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            accept_loop(app, listener, Service::Https(tls_cfg)).await
        }));
    }

    if cfg.modbus_port != 0 {
        let addr = SocketAddr::new(cfg.bind, cfg.modbus_port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            accept_loop(app, listener, Service::Modbus).await
        }));
    }

    app.log.log(
        "system",
        SocketAddr::new(cfg.bind, 0),
        "start",
        fields! {
            "http_port" => cfg.http_port,
            "https_port" => cfg.https_port,
            "modbus_port" => cfg.modbus_port,
            "store_name" => app.id.store_name,
            "hostname" => app.id.hostname,
            "mac" => app.id.mac,
            "firmware" => app.id.firmware,
            "device_tz" => cfg.device_tz.to_string(),
        },
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm() => {}
    }
    app.log.close(); // write out whatever is still queued
    Ok(())
}

#[cfg(unix)]
async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    if let Ok(mut s) = signal(SignalKind::terminate()) {
        s.recv().await;
    }
}

#[cfg(not(unix))]
async fn sigterm() {
    std::future::pending::<()>().await;
}
