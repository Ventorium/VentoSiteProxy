//! TCP 透传中继：把监听端口原样转发到上游地址。
//! 通过后台服务按配置同步监听器；配置变化（启用/停用/改端口）在下一轮 tick 生效。

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::config::AppState;

pub struct TcpRelaySupervisor {
    pub state: std::sync::Arc<AppState>,
}

#[async_trait]
impl BackgroundService for TcpRelaySupervisor {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut active: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    for (addr, h) in &active {
                        log::info!("tcp relay stopping: {addr}");
                        h.abort();
                    }
                    log::info!("tcp relay supervisor exited");
                    return;
                }
                _ = tick.tick() => {
                    let cfg = self.state.load_config();
                    let want: Vec<(String, String)> = cfg
                        .streams
                        .iter()
                        .filter(|s| s.enabled)
                        .map(|s| (s.listen.trim().to_string(), s.upstream.trim().to_string()))
                        .collect();
                    let want_addrs: std::collections::HashSet<&str> =
                        want.iter().map(|(a, _)| a.as_str()).collect();

                    for (addr, h) in active.iter() {
                        if !want_addrs.contains(addr.as_str()) {
                            log::info!("tcp relay stopped: {addr}");
                            h.abort();
                        }
                    }
                    active.retain(|addr, _| want_addrs.contains(addr.as_str()));

                    for (addr, upstream) in &want {
                        if !active.contains_key(addr) {
                            match tokio::net::TcpListener::bind(addr).await {
                                Ok(listener) => {
                                    log::info!("tcp relay started: {addr} -> {upstream}");
                                    let handle = tokio::spawn(relay_listener(
                                        listener,
                                        addr.clone(),
                                        upstream.clone(),
                                    ));
                                    active.insert(addr.clone(), handle);
                                }
                                Err(err) => {
                                    log::warn!(
                                        "tcp relay bind {addr} failed: {err} (will retry next tick)"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn relay_listener(listener: tokio::net::TcpListener, addr: String, upstream: String) {
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                tokio::spawn(relay_pair(client, peer, upstream.clone()));
            }
            Err(err) => {
                log::warn!("tcp accept on {addr}: {err}");
            }
        }
    }
}

async fn relay_pair(client: tokio::net::TcpStream, peer: std::net::SocketAddr, upstream: String) {
    let upstream_stream = match tokio::net::TcpStream::connect(&upstream).await {
        Ok(s) => s,
        Err(err) => {
            log::warn!("tcp relay: connect {upstream} from {peer} failed: {err}");
            return;
        }
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream_stream.into_split();
    let a = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
    });
    let b = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
    });
    let _ = tokio::select! {
        r = a => r,
        r = b => r,
    };
    log::debug!("tcp relay connection closed: {peer} -> {upstream}");
}
