//! 管理端 HTTP API（网关模式：request_filter 内直接响应）。
//!
//! 路由：
//!   GET  /                      内嵌 Web UI
//!   GET  /api/health            健康检查（免认证）
//!   POST /api/login             登录，返回 JWT
//!   GET  /api/me                当前用户
//!   GET  /api/sites             站点列表
//!   POST /api/sites             新建站点
//!   GET  /api/sites/{id}        站点详情
//!   PUT  /api/sites/{id}        整体更新站点
//!   DELETE /api/sites/{id}      删除站点
//!   POST /api/sites/{id}/enable|disable
//!   GET  /api/streams           数据流列表
//!   POST /api/streams
//!   GET|PUT|DELETE /api/streams/{id}
//!   POST /api/streams/{id}/enable|disable
//!   GET  /api/audit?limit=N     操作日志
//!   GET  /api/settings          全局设置（默认 404 页面模式 + 日志自动清理）
//!   PUT  /api/settings          更新全局设置

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::Session;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::{is_valid_default_404, AppState, Location, Site, TcpStream, UrlAction, UrlRule};

// ---------------------------------------------------------------------------
// 载荷
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct LoginPayload {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Deserialize, Default)]
pub struct SitePayload {
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub enabled: Option<bool>,
    pub access_log: Option<bool>,
    pub domains: Option<Vec<String>>,
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstream_scheme: Option<String>,
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default)]
    pub verify_cert: Option<bool>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
    #[serde(default)]
    pub write_timeout: Option<u64>,
    #[serde(default)]
    pub locations: Option<Vec<Location>>,
    #[serde(default)]
    pub url_rules: Option<Vec<UrlRule>>,
    #[serde(default)]
    pub url_default: Option<UrlAction>,
}

#[derive(Deserialize, Default)]
pub struct StreamPayload {
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub enabled: Option<bool>,
    pub listen: Option<String>,
    pub upstream: Option<String>,
}

// ---------------------------------------------------------------------------
// 响应助手
// ---------------------------------------------------------------------------

async fn respond(session: &mut Session, status: u16, content_type: &str, body: Bytes) {
    let mut resp = match ResponseHeader::build(status, Some(body.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", content_type);
    let _ = resp.insert_header("X-Content-Type-Options", "nosniff");
    let end = body.is_empty();
    let _ = session.write_response_header(Box::new(resp), end).await;
    if !end {
        let _ = session.write_response_body(Some(body), true).await;
    }
}

async fn json(session: &mut Session, status: u16, v: &Value) {
    let body = Bytes::from(serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
    respond(session, status, "application/json; charset=utf-8", body).await;
}

async fn fail(session: &mut Session, status: u16, msg: &str) {
    json(session, status, &json!({"ok": false, "error": msg})).await;
}

async fn ok(session: &mut Session, data: Value) {
    json(session, 200, &json!({"ok": true, "data": data})).await;
}

async fn parse_body(session: &mut Session) -> Option<Value> {
    match session.read_request_body().await {
        Ok(Some(b)) if !b.is_empty() => serde_json::from_slice(&b).ok(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

pub async fn handle(session: &mut Session, state: &AppState) {
    let req = session.req_header();
    let method = req.method.as_str().to_string();
    let path = req.uri.path().to_string();
    let ip = session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "-".into());

    // 静态 UI
    if method == "GET" && (path == "/" || path == "/index.html") {
        let body = Bytes::from(crate::admin::web::INDEX_HTML.to_string());
        return respond(session, 200, "text/html; charset=utf-8", body).await;
    }
    // 内嵌图标（favicon / 品牌 logo / iOS 主屏图标）
    if method == "GET" {
        let icon = match path.as_str() {
            "/favicon.png" => Some(crate::admin::web::FAVICON_PNG),
            "/logo.png" => Some(crate::admin::web::LOGO_PNG),
            "/apple-touch-icon.png" => Some(crate::admin::web::APPLE_TOUCH_ICON_PNG),
            _ => None,
        };
        if let Some(bytes) = icon {
            return respond(session, 200, "image/png", Bytes::from_static(bytes)).await;
        }
    }
    if !path.starts_with("/api/") {
        return fail(session, 404, "not found").await;
    }

    if path == "/api/health" && method == "GET" {
        return json(session, 200, &json!({"ok": true, "service": "ventositeproxy"})).await;
    }

    // 登录
    if path == "/api/login" && method == "POST" {
        let v = parse_body(session).await.unwrap_or(Value::Null);
        let p: LoginPayload = serde_json::from_value(v).unwrap_or_default();
        match crate::admin::auth::verify_password(&p.password, &state.admin.password_hash) {
            Ok(true) if p.username == state.admin.username => {
                let token = crate::admin::auth::issue_token(
                    &state.admin.jwt_secret,
                    &p.username,
                    state.admin.jwt_ttl_hours,
                )
                .unwrap_or_default();
                state.audit.record(&p.username, "login", &p.username, "登录成功", &ip);
                return json(
                    session,
                    200,
                    &json!({"ok": true, "data": {"token": token, "username": p.username}}),
                )
                .await;
            }
            _ => {
                state.audit.record(&p.username, "login_failed", "-", "用户名或密码错误", &ip);
                return fail(session, 401, "用户名或密码错误").await;
            }
        }
    }

    // 其余接口需要 Bearer 令牌
    let token = req
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .strip_prefix("Bearer ")
        .unwrap_or("")
        .to_string();
    let user = match crate::admin::auth::verify_token(&state.admin.jwt_secret, &token) {
        Ok(u) => u,
        Err(_) => return fail(session, 401, "未登录或会话已过期").await,
    };

    // 路由分发
    let rest = path.trim_start_matches("/api/");
    let mut parts = rest.split('/');
    let head = parts.next().unwrap_or("");
    let id_part = parts.next();
    let third = parts.next();

    match head {
        "me" if method == "GET" => {
            json(session, 200, &json!({"ok": true, "data": {"username": user}})).await
        }
        "sites" => routes_sites(session, state, &user, &ip, &method, id_part, third).await,
        "streams" => {
            routes_streams(session, state, &user, &ip, &method, id_part, third).await
        }
        "audit" if method == "GET" => {
            let limit = req
                .uri
                .query()
                .and_then(|q| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix("limit="))
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(200)
                .min(2000);
            let rows = state.audit.tail(limit);
            json(session, 200, &json!({"ok": true, "data": rows})).await
        }
        "settings" => routes_settings(session, state, &user, &ip, &method).await,
        _ => fail(session, 404, "not found").await,
    }
}

// ---------------------------------------------------------------------------
// 全局设置（默认 404 页面模式）
// ---------------------------------------------------------------------------

async fn routes_settings(
    session: &mut Session,
    state: &AppState,
    user: &str,
    ip: &str,
    method: &str,
) {
    match method {
        "GET" => {
            let cfg = state.load_config();
            ok(
                session,
                json!({
                    "default_404": cfg.default_404,
                    "custom_404_dir": cfg.custom_404_dir,
                    "log_cleanup": {
                        "enabled": cfg.log_cleanup.enabled,
                        "retention_days": cfg.log_cleanup.retention_days,
                    },
                }),
            )
            .await
        }
        "PUT" => {
            let Some(v) = parse_body(session).await else {
                return fail(session, 400, "缺少请求体").await;
            };
            let mode = v
                .get("default_404")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let dir = v
                .get("custom_404_dir")
                .and_then(|x| x.as_str())
                .map(|s| s.trim().to_string());
            if !is_valid_default_404(&mode) {
                return fail(session, 400, "default_404 必须为 status / page / custom").await;
            }
            if matches!(dir.as_deref(), Some(d) if d.is_empty()) {
                return fail(session, 400, "custom_404_dir 不能为空").await;
            }
            let cleanup = v.get("log_cleanup");
            if let Some(c) = cleanup {
                if !c.is_object() {
                    return fail(session, 400, "log_cleanup 必须为对象").await;
                }
                if let Some(e) = c.get("enabled") {
                    if !e.is_boolean() {
                        return fail(session, 400, "log_cleanup.enabled 必须为布尔值").await;
                    }
                }
                if let Some(r) = c.get("retention_days") {
                    let Some(days) = r.as_u64() else {
                        return fail(session, 400, "log_cleanup.retention_days 必须为整数").await;
                    };
                    if !(1..=3650).contains(&days) {
                        return fail(session, 400, "log_cleanup.retention_days 需在 1~3650 之间").await;
                    }
                }
            }
            let cleanup_enabled = cleanup
                .and_then(|c| c.get("enabled"))
                .and_then(|x| x.as_bool());
            let cleanup_days = cleanup
                .and_then(|c| c.get("retention_days"))
                .and_then(|x| x.as_u64());
            let res = state.with_mutated_config(|cfg| {
                cfg.default_404 = mode.clone();
                if let Some(d) = &dir {
                    cfg.custom_404_dir = d.clone();
                }
                if let Some(e) = cleanup_enabled {
                    cfg.log_cleanup.enabled = e;
                }
                if let Some(days) = cleanup_days {
                    cfg.log_cleanup.retention_days = days as u32;
                }
                Ok(())
            });
            let next = match res {
                Ok(c) => c,
                Err(e) => return fail(session, 500, &format!("保存失败: {e}")).await,
            };
            state.audit.record(
                user,
                "update_settings",
                "-",
                &format!(
                    "默认404页面: {} (目录: {}); 日志清理: {} 保留{}天",
                    next.default_404,
                    next.custom_404_dir,
                    if next.log_cleanup.enabled { "开启" } else { "关闭" },
                    next.log_cleanup.retention_days
                ),
                ip,
            );
            ok(
                session,
                json!({
                    "default_404": next.default_404,
                    "custom_404_dir": next.custom_404_dir,
                    "log_cleanup": {
                        "enabled": next.log_cleanup.enabled,
                        "retention_days": next.log_cleanup.retention_days,
                    },
                }),
            )
            .await
        }
        _ => fail(session, 405, "method not allowed").await,
    }
}

// ---------------------------------------------------------------------------
// 站点
// ---------------------------------------------------------------------------

async fn routes_sites(
    session: &mut Session,
    state: &AppState,
    user: &str,
    ip: &str,
    method: &str,
    id_part: Option<&str>,
    third: Option<&str>,
) {
    match id_part {
        None => match method {
            "GET" => {
                let cfg = state.load_config();
                json(session, 200, &json!({"ok": true, "data": cfg.sites})).await
            }
            "POST" => {
                let Some(v) = parse_body(session).await else {
                    return fail(session, 400, "缺少请求体").await;
                };
                let p: SitePayload = match serde_json::from_value(v) {
                    Ok(p) => p,
                    Err(e) => return fail(session, 400, &format!("参数错误: {e}")).await,
                };
                let name = p.name.as_deref().unwrap_or("").trim().to_string();
                let upstream = p.upstream.as_deref().unwrap_or("").trim().to_string();
                let domains: Vec<String> = p
                    .domains
                    .unwrap_or_default()
                    .into_iter()
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect();
                if name.is_empty() || upstream.is_empty() || domains.is_empty() {
                    return fail(session, 400, "名称 / 上游 / 域名 为必填项").await;
                }
                let scheme = p
                    .upstream_scheme
                    .unwrap_or_default()
                    .trim()
                    .to_lowercase();
                let site = Site {
                    id: 0,
                    name: name.clone(),
                    notes: p.notes.unwrap_or_default(),
                    enabled: p.enabled.unwrap_or(true),
                    access_log: p.access_log.unwrap_or(true),
                    domains,
                    upstream,
                    upstream_scheme: if scheme.is_empty() { "http".into() } else { scheme },
                    upstream_sni: {
                        let sni = p.upstream_sni.clone().unwrap_or_default();
                        let s = sni.trim();
                        if s.is_empty() { None } else { Some(s.to_string()) }
                    },
                    verify_cert: p.verify_cert.unwrap_or(false),
                    connect_timeout: p.connect_timeout.unwrap_or(10),
                    read_timeout: p.read_timeout.unwrap_or(0),
                    write_timeout: p.write_timeout.unwrap_or(0),
                    locations: p.locations.unwrap_or_default(),
                    url_rules: p.url_rules.unwrap_or_default(),
                    url_default: p.url_default.unwrap_or(UrlAction::Allow),
                };
                let id = {
                    let next = match state.with_mutated_config(|cfg| {
                        let id = cfg.next_site_id();
                        let mut s = site.clone();
                        s.id = id;
                        cfg.sites.push(s);
                        Ok(())
                    }) {
                        Ok(c) => c,
                        Err(e) => return fail(session, 500, &format!("保存失败: {e}")).await,
                    };
                    next.sites.iter().map(|s| s.id).max().unwrap_or(1)
                };
                state
                    .audit
                    .record(user, "create_site", &format!("site#{id} {name}"), "新建站点", ip);
                json(session, 200, &json!({"ok": true, "data": {"id": id}})).await
            }
            _ => fail(session, 405, "method not allowed").await,
        },
        Some(id_str) => {
            let Ok(id) = id_str.parse::<u64>() else {
                return fail(session, 400, "非法 id").await;
            };
            match third {
                Some("enable") | Some("disable") if method == "POST" => {
                    let enable = third == Some("enable");
                    let mut detail = String::new();
                    let res = state.with_mutated_config(|cfg| {
                        let Some(s) = cfg.sites.iter_mut().find(|s| s.id == id) else {
                            return Err(format!("站点 #{id} 不存在"));
                        };
                        s.enabled = enable;
                        detail = s.name.clone();
                        Ok(())
                    });
                    if let Err(e) = res {
                        return fail(session, 404, &e).await;
                    }
                    let action = if enable { "enable_site" } else { "disable_site" };
                    state
                        .audit
                        .record(user, action, &format!("site#{id} {detail}"), if enable { "启用站点" } else { "停用站点" }, ip);
                    ok(session, json!({"id": id, "enabled": enable})).await
                }
                Some("log") if method == "GET" => {
                    let limit = session
                        .req_header()
                        .uri
                        .query()
                        .and_then(|q| {
                            q.split('&')
                                .find_map(|kv| kv.strip_prefix("lines="))
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap_or(200)
                        .min(1000);
                    let cfg = state.load_config();
                    let site = match cfg.sites.iter().find(|s| s.id == id) {
                        Some(s) => s,
                        None => return fail(session, 404, "站点不存在").await,
                    };
                    let access_dir = state.log_dir.join("access");
                    let prefix = format!("site-{id}-");
                    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&access_dir)
                        .map(|d| d.into_iter().flatten().map(|e| e.path()).collect::<Vec<_>>())
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| n.starts_with(&prefix) && n.ends_with(".log"))
                                .unwrap_or(false)
                        })
                        .collect();
                    if paths.is_empty() {
                        return ok(
                            session,
                            json!({
                                "file": null,
                                "access_log": site.access_log,
                                "total": 0,
                                "shown": 0,
                                "lines": []
                            }),
                        )
                        .await;
                    }
                    // 按天归档后同一站点可能有多个文件：
                    // 无日期旧文件最旧（排最前），有日期文件按日期升序；
                    // archive_date 会用 mtime 交叉校验文件名日期，避免 slug 以 8 位
                    // 数字结尾的旧格式文件被误排到其"日期"位置
                    paths.sort_by(|a, b| {
                        let ka = crate::logcleanup::archive_date(a);
                        let kb = crate::logcleanup::archive_date(b);
                        ka.cmp(&kb) // None < Some：旧格式/无法确认日期的文件在前
                    });
                    // 先读全部归档文件并统计真实总行数（total 不再因提前 break 而少报），
                    // 再从最新的一天往前累积，直到凑满最近 N 行
                    let mut files: Vec<(String, Vec<String>)> = Vec::with_capacity(paths.len());
                    let mut total: usize = 0;
                    for path in &paths {
                        let content = std::fs::read_to_string(path).unwrap_or_default();
                        let lines: Vec<String> = content.lines().map(ToString::to_string).collect();
                        total += lines.len();
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
                        files.push((name, lines));
                    }
                    let mut tail: Vec<String> = Vec::new();
                    let mut names: Vec<String> = Vec::new();
                    for (name, lines) in files.iter().rev() {
                        if tail.len() < limit {
                            let start = lines.len().saturating_sub(limit - tail.len());
                            tail.splice(0..0, lines[start..].iter().cloned());
                        }
                        names.push(name.clone());
                        if tail.len() >= limit {
                            break;
                        }
                    }
                    names.reverse(); // 旧 → 新，用于 file_display 的 "oldest … newest" 展示
                    let file_display = match names.len() {
                        0 => String::new(),
                        1 => names[0].clone(),
                        n => format!("{} … {}（{} 个归档文件）", names[0], names[n - 1], n),
                    };
                    ok(
                        session,
                        json!({
                            "file": file_display,
                            "access_log": site.access_log,
                            "total": total,
                            "shown": tail.len(),
                            "lines": tail
                        }),
                    )
                    .await
                }
                _ => match method {
                    "GET" => {
                        let cfg = state.load_config();
                        match cfg.sites.iter().find(|s| s.id == id) {
                            Some(s) => ok(session, json!(s)).await,
                            None => fail(session, 404, "站点不存在").await,
                        }
                    }
                    "PUT" => {
                        let Some(v) = parse_body(session).await else {
                            return fail(session, 400, "缺少请求体").await;
                        };
                        let p: SitePayload = match serde_json::from_value(v) {
                            Ok(p) => p,
                            Err(e) => return fail(session, 400, &format!("参数错误: {e}")).await,
                        };
                        let mut name = String::new();
                        let res = state.with_mutated_config(|cfg| {
                            let Some(s) = cfg.sites.iter_mut().find(|s| s.id == id) else {
                                return Err(format!("站点 #{id} 不存在"));
                            };
                            if let Some(n) = &p.name {
                                s.name = n.trim().to_string();
                                name = s.name.clone();
                            }
                            if let Some(n) = &p.notes {
                                s.notes = n.clone();
                            }
                            if let Some(e) = p.enabled {
                                s.enabled = e;
                            }
                            if let Some(a) = p.access_log {
                                s.access_log = a;
                            }
                            if let Some(d) = &p.domains {
                                s.domains = d
                                    .iter()
                                    .map(|x| x.trim().to_string())
                                    .filter(|x| !x.is_empty())
                                    .collect();
                            }
                            if let Some(u) = &p.upstream {
                                s.upstream = u.trim().to_string();
                            }
                            if let Some(sc) = &p.upstream_scheme {
                                if !sc.trim().is_empty() {
                                    s.upstream_scheme = sc.trim().to_lowercase();
                                }
                            }
                            if let Some(sni) = &p.upstream_sni {
                                let t = sni.trim();
                                s.upstream_sni = if t.is_empty() { None } else { Some(t.to_string()) };
                            }
                            if let Some(v) = p.verify_cert {
                                s.verify_cert = v;
                            }
                            if let Some(v) = p.connect_timeout {
                                s.connect_timeout = v;
                            }
                            if let Some(v) = p.read_timeout {
                                s.read_timeout = v;
                            }
                            if let Some(v) = p.write_timeout {
                                s.write_timeout = v;
                            }
                            if let Some(l) = &p.locations {
                                s.locations = l.clone();
                            }
                            if let Some(r) = &p.url_rules {
                                s.url_rules = r.clone();
                            }
                            if let Some(d) = p.url_default {
                                s.url_default = d;
                            }
                            Ok(())
                        });
                        if let Err(e) = res {
                            return fail(session, 404, &e).await;
                        }
                        state
                            .audit
                            .record(user, "update_site", &format!("site#{id} {name}"), "更新站点", ip);
                        ok(session, json!({"id": id})).await
                    }
                    "DELETE" => {
                        let mut name = String::new();
                        let res = state.with_mutated_config(|cfg| {
                            let before = cfg.sites.len();
                            cfg.sites.retain(|s| {
                                if s.id == id {
                                    name = s.name.clone();
                                    false
                                } else {
                                    true
                                }
                            });
                            if cfg.sites.len() == before {
                                Err(format!("站点 #{id} 不存在"))
                            } else {
                                Ok(())
                            }
                        });
                        if let Err(e) = res {
                            return fail(session, 404, &e).await;
                        }
                        state
                            .audit
                            .record(user, "delete_site", &format!("site#{id} {name}"), "删除站点", ip);
                        ok(session, json!({"id": id})).await
                    }
                    _ => fail(session, 405, "method not allowed").await,
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 数据流
// ---------------------------------------------------------------------------

async fn routes_streams(
    session: &mut Session,
    state: &AppState,
    user: &str,
    ip: &str,
    method: &str,
    id_part: Option<&str>,
    third: Option<&str>,
) {
    match id_part {
        None => match method {
            "GET" => {
                let cfg = state.load_config();
                json(session, 200, &json!({"ok": true, "data": cfg.streams})).await
            }
            "POST" => {
                let Some(v) = parse_body(session).await else {
                    return fail(session, 400, "缺少请求体").await;
                };
                let p: StreamPayload = match serde_json::from_value(v) {
                    Ok(p) => p,
                    Err(e) => return fail(session, 400, &format!("参数错误: {e}")).await,
                };
                let name = p.name.as_deref().unwrap_or("").trim().to_string();
                let listen = p.listen.as_deref().unwrap_or("").trim().to_string();
                let upstream = p.upstream.as_deref().unwrap_or("").trim().to_string();
                if name.is_empty() || listen.is_empty() || upstream.is_empty() {
                    return fail(session, 400, "名称 / 监听 / 上游 为必填项").await;
                }
                let stream = TcpStream {
                    id: 0,
                    name: name.clone(),
                    notes: p.notes.unwrap_or_default(),
                    enabled: p.enabled.unwrap_or(true),
                    listen,
                    upstream,
                };
                let id = {
                    let next = match state.with_mutated_config(|cfg| {
                        let id = cfg.next_stream_id();
                        let mut s = stream.clone();
                        s.id = id;
                        cfg.streams.push(s);
                        Ok(())
                    }) {
                        Ok(c) => c,
                        Err(e) => return fail(session, 500, &format!("保存失败: {e}")).await,
                    };
                    next.streams.iter().map(|s| s.id).max().unwrap_or(1)
                };
                state
                    .audit
                    .record(user, "create_stream", &format!("stream#{id} {name}"), "新建数据流", ip);
                json(session, 200, &json!({"ok": true, "data": {"id": id}})).await
            }
            _ => fail(session, 405, "method not allowed").await,
        },
        Some(id_str) => {
            let Ok(id) = id_str.parse::<u64>() else {
                return fail(session, 400, "非法 id").await;
            };
            match third {
                Some("enable") | Some("disable") if method == "POST" => {
                    let enable = third == Some("enable");
                    let mut detail = String::new();
                    let res = state.with_mutated_config(|cfg| {
                        let Some(s) = cfg.streams.iter_mut().find(|s| s.id == id) else {
                            return Err(format!("数据流 #{id} 不存在"));
                        };
                        s.enabled = enable;
                        detail = s.name.clone();
                        Ok(())
                    });
                    if let Err(e) = res {
                        return fail(session, 404, &e).await;
                    }
                    let action = if enable { "enable_stream" } else { "disable_stream" };
                    state
                        .audit
                        .record(user, action, &format!("stream#{id} {detail}"), if enable { "启用数据流" } else { "停用数据流" }, ip);
                    ok(session, json!({"id": id, "enabled": enable})).await
                }
                _ => match method {
                    "GET" => {
                        let cfg = state.load_config();
                        match cfg.streams.iter().find(|s| s.id == id) {
                            Some(s) => ok(session, json!(s)).await,
                            None => fail(session, 404, "数据流不存在").await,
                        }
                    }
                    "PUT" => {
                        let Some(v) = parse_body(session).await else {
                            return fail(session, 400, "缺少请求体").await;
                        };
                        let p: StreamPayload = match serde_json::from_value(v) {
                            Ok(p) => p,
                            Err(e) => return fail(session, 400, &format!("参数错误: {e}")).await,
                        };
                        let mut name = String::new();
                        let res = state.with_mutated_config(|cfg| {
                            let Some(s) = cfg.streams.iter_mut().find(|s| s.id == id) else {
                                return Err(format!("数据流 #{id} 不存在"));
                            };
                            if let Some(n) = &p.name {
                                s.name = n.trim().to_string();
                                name = s.name.clone();
                            }
                            if let Some(n) = &p.notes {
                                s.notes = n.clone();
                            }
                            if let Some(e) = p.enabled {
                                s.enabled = e;
                            }
                            if let Some(l) = &p.listen {
                                s.listen = l.trim().to_string();
                            }
                            if let Some(u) = &p.upstream {
                                s.upstream = u.trim().to_string();
                            }
                            Ok(())
                        });
                        if let Err(e) = res {
                            return fail(session, 404, &e).await;
                        }
                        state
                            .audit
                            .record(user, "update_stream", &format!("stream#{id} {name}"), "更新数据流", ip);
                        ok(session, json!({"id": id})).await
                    }
                    "DELETE" => {
                        let mut name = String::new();
                        let res = state.with_mutated_config(|cfg| {
                            let before = cfg.streams.len();
                            cfg.streams.retain(|s| {
                                if s.id == id {
                                    name = s.name.clone();
                                    false
                                } else {
                                    true
                                }
                            });
                            if cfg.streams.len() == before {
                                Err(format!("数据流 #{id} 不存在"))
                            } else {
                                Ok(())
                            }
                        });
                        if let Err(e) = res {
                            return fail(session, 404, &e).await;
                        }
                        state
                            .audit
                            .record(user, "delete_stream", &format!("stream#{id} {name}"), "删除数据流", ip);
                        ok(session, json!({"id": id})).await
                    }
                    _ => fail(session, 405, "method not allowed").await,
                },
            }
        }
    }
}
