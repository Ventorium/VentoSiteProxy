//! 主反代服务（Pingora ProxyHttp 实现）。
//!
//! 热路径原则：只做 ArcSwap 读 + 无锁匹配 + 非阻塞日志投递，不阻塞、不分配大对象。
//!
//! 请求流程：
//! 1. `request_filter`：Host → 站点（精确 > 通配，仅 enabled）；无站点 404。
//!    按序匹配 URL 黑白名单规则（首个命中生效，默认值可配 allow/deny）；deny → 403。
//!    按序匹配 locations（path 命中 → 覆盖上游）。
//! 2. `upstream_peer`：按站点配置构造上游（含 TLS/SNI/超时；0 = 不限）。
//! 3. `logging`：站点开启访问日志时，非阻塞投递一行。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora_error::Result;

use crate::config::{AppState, UrlAction};
use crate::glob::{glob_match, slugify};
use crate::routes::find_site;

pub struct ProxyHandler {
    pub state: Arc<AppState>,
}

/// 每请求上下文
#[derive(Default)]
pub struct ProxyCtx {
    target: Option<RouteTarget>,
    start: Option<Instant>,
}

/// request_filter 解析出的目标（避免 upstream_peer 阶段再查表）
#[derive(Clone)]
struct RouteTarget {
    site_name: String,
    slug: String,
    access_log: bool,
    upstream: String,
    upstream_scheme: String,
    upstream_sni: Option<String>,
    verify_cert: bool,
    connect_timeout: u64,
    read_timeout: u64,
    write_timeout: u64,
}

impl ProxyCtx {
    fn resolve(
        site: &crate::config::Site,
        path: &str,
    ) -> RouteTarget {
        let base = RouteTarget {
            site_name: site.name.clone(),
            slug: format!("site-{}-{}", site.id, slugify(&site.name)),
            access_log: site.access_log,
            upstream: site.upstream.trim().to_string(),
            upstream_scheme: site.upstream_scheme.trim().to_lowercase(),
            upstream_sni: site.upstream_sni.clone(),
            verify_cert: site.verify_cert,
            connect_timeout: site.connect_timeout,
            read_timeout: site.read_timeout,
            write_timeout: site.write_timeout,
        };
        // locations：按序，首个 path 命中者覆盖上游（对应 NPM locations）
        for loc in &site.locations {
            if !loc.path.is_empty() && glob_match(&loc.path, path) {
                let mut t = base;
                if !loc.upstream.trim().is_empty() {
                    t.upstream = loc.upstream.trim().to_string();
                }
                if !loc.upstream_scheme.trim().is_empty() {
                    t.upstream_scheme = loc.upstream_scheme.trim().to_lowercase();
                }
                if loc.connect_timeout > 0 {
                    t.connect_timeout = loc.connect_timeout;
                }
                if loc.read_timeout > 0 {
                    t.read_timeout = loc.read_timeout;
                }
                return t;
            }
        }
        base
    }
}

async fn respond_plain(session: &mut Session, status: u16, body: &str) {
    let mut resp = match ResponseHeader::build(status, Some(body.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", "text/plain; charset=utf-8");
    let _ = resp.insert_header("Connection", "close");
    let end = body.is_empty();
    let _ = session.write_response_header(Box::new(resp), end).await;
    if !end {
        let _ = session.write_response_body(Some(Bytes::from(body.to_string())), true).await;
    }
}

/// 取请求 Host 头（pingora-http 的 RequestHeader 没有 host 字段，从 header 里取）。
fn req_host_str(req: &pingora::http::RequestHeader) -> &str {
    req.headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("")
}

fn pick_sni(target: &RouteTarget, req_host: &str) -> String {
    if let Some(sni) = &target.upstream_sni {
        if !sni.trim().is_empty() {
            return sni.trim().to_string();
        }
    }
    // 上游是域名 → 用上游名；是 IP → 退回请求 Host（若为域名），否则不发 SNI
    let up_host = target.upstream.split(':').next().unwrap_or(&target.upstream);
    if up_host.parse::<IpAddr>().is_err() && !up_host.is_empty() {
        return up_host.to_string();
    }
    let req_host = req_host.trim();
    if !req_host.is_empty() && req_host.parse::<IpAddr>().is_err() && !req_host.contains(':') {
        return req_host.to_string();
    }
    String::new()
}

#[async_trait]
impl ProxyHttp for ProxyHandler {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx {
            target: None,
            start: Some(Instant::now()),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<bool> {
        let req = session.req_header();
        let host = req_host_str(req).to_string();
        let path = req.uri.path().to_string();

        let cfg = self.state.config.load();
        let site = match find_site(&cfg.sites, &host) {
            Some(s) => s,
            None => {
                // 未匹配站点：按配置的默认 404 模式响应（status / page / custom）
                crate::defaultpage::respond_default_404(session, &*cfg, &path).await;
                return Ok(true);
            }
        };

        // 按序 URL 规则，首个命中生效
        let decision = site
            .url_rules
            .iter()
            .find(|r| !r.pattern.trim().is_empty() && glob_match(r.pattern.trim(), &path))
            .map(|r| r.action)
            .unwrap_or(site.url_default);
        if decision == UrlAction::Deny {
            let _ = respond_plain(session, 403, &format!("403 - Forbidden by URL rule (Host: {host}, Path: {path})\n")).await;
            // 仍记录目标，便于访问日志审计拦截
            ctx.target = Some(ProxyCtx::resolve(site, &path));
            return Ok(true);
        }

        ctx.target = Some(ProxyCtx::resolve(site, &path));
        Ok(false)
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut ProxyCtx) -> Result<Box<HttpPeer>> {
        let req = session.req_header();
        let target = ctx
            .target
            .as_ref()
            .ok_or_else(|| pingora_error::Error::new_str("no route resolved"))?
            .clone();
        let tls = target.upstream_scheme == "https";
        let sni = pick_sni(&target, req_host_str(req));
        let mut peer = HttpPeer::new(target.upstream.as_str(), tls, sni);
        peer.options.connection_timeout = (target.connect_timeout > 0).then(|| Duration::from_secs(target.connect_timeout));
        peer.options.read_timeout = (target.read_timeout > 0).then(|| Duration::from_secs(target.read_timeout));
        peer.options.write_timeout = (target.write_timeout > 0).then(|| Duration::from_secs(target.write_timeout));
        if tls {
            peer.options.verify_cert = target.verify_cert;
            peer.options.verify_hostname = target.verify_cert;
        }
        Ok(Box::new(peer))
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_error::Error>, ctx: &mut ProxyCtx) {
        let target = match &ctx.target {
            Some(t) => t.clone(),
            None => return,
        };
        if !target.access_log {
            return;
        }
        let req = session.req_header();
        let (status, bytes) = match session.response_written() {
            Some(r) => {
                let len = r
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                (r.status.as_u16(), len)
            }
            None => (500, 0),
        };
        let client = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "-".into());
        let vstr = match req.version {
            pingora::http::Version::HTTP_09 => "HTTP/0.9",
            pingora::http::Version::HTTP_10 => "HTTP/1.0",
            pingora::http::Version::HTTP_11 => "HTTP/1.1",
            pingora::http::Version::HTTP_2 => "HTTP/2.0",
            pingora::http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        };
        let rt_ms = ctx
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let line = crate::accesslog::format_line(
            &client,
            req.method.as_str(),
            req.uri.path(),
            vstr,
            status,
            bytes,
            &target.site_name,
            rt_ms,
        );
        let _ = self
            .state
            .log_tx
            .try_send(crate::config::LogLine { slug: target.slug, line });
    }
}
