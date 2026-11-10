//! 终端用户 `/__auth/*` 接口（挂在代理端口，request_filter 直接处理，不走上游）
//!
//! - `GET  /__auth/login`     登录页（`?next=` 为登录后跳转的同源路径）
//! - `POST /__auth/login`     `{username,password}` → 会话 Cookie + `{redirect}`
//! - `GET  /__auth/me`        当前会话信息（401 = 未登录/过期）
//! - `POST /__auth/logout`    注销（会话删除 + Cookie 清除）
//!
//! 安全：登录按 IP 限流；next 强制同源（`/` 开头且非 `//`）；
//! 用户不存在与密码错误统一提示，避免用户名枚举。

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::Session;

use super::identity;
use super::page;
use super::session::hash_token;
use crate::config::AppState;

const BODY_CAP: usize = 1 << 20; // 1MB

/// 处理 `/__auth/*` 请求；总是消费请求并返回 `Ok(true)`
pub async fn handle(state: &AppState, session: &mut Session, path: &str, ip: &str) -> bool {
    let method = session.req_header().method.clone();
    let _ = match (method.as_str(), path.trim_end_matches('/').trim_start_matches("/__auth")) {
        ("GET", "/login" | "") => handle_login_page(session, ip).await,
        ("POST", "/login") => handle_login(state, session, ip).await,
        ("GET", "/me") => handle_me(state, session, ip).await,
        ("POST", "/logout") => handle_logout(state, session, ip).await,
        _ => {
            respond_json(session, 404, &serde_json::json!({ "ok": false, "error": "not found" }), None).await;
            404
        }
    };
    true
}

// ---------------------------------------------------------------------------
// 登录
// ---------------------------------------------------------------------------

async fn handle_login_page(session: &mut Session, _ip: &str) -> i64 {
    // 登录页自己读取 URL 上的 ?next=（gate 302 已带上）
    respond_html(session, 200, page::LOGIN_HTML).await;
    200
}

async fn handle_login(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();

    // 限流：锁定期内直接 429
    if let Some(secs) = auth.ratelimit.is_locked(ip) {
        state.audit.record("-", "login_rate_limited", "auth", &format!("ip={ip} remaining={secs}s"), ip);
        respond_json(
            session,
            429,
            &serde_json::json!({ "ok": false, "error": "尝试过于频繁，请稍后再试", "retry_after_secs": secs }),
            None,
        )
        .await;
        return 429;
    }

    // 认证总开关关闭时仍允许登录（站点级单独启用场景）
    let mut username = String::new();
    let mut password = String::new();
    if let Ok(body) = read_body(session).await {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
            username = v.get("username").and_then(|x| x.as_str()).unwrap_or("").to_string();
            password = v.get("password").and_then(|x| x.as_str()).unwrap_or("").to_string();
        }
    }

    // 用户名格式校验（同时限制登录枚举面）
    let valid_username = (2..=64).contains(&username.chars().count())
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid_username || password.is_empty() {
        auth.ratelimit.record_failure(ip);
        state.audit.record(&username, "login_failed", "auth", "用户名或密码错误", ip);
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
        return 401;
    }

    match identity::authenticate(&auth.store, &auth.ldap_cache, &s, &username, &password).await {
        Ok(Some(user)) => {
            auth.ratelimit.record_success(ip);
            // next 校验：同源路径（/ 开头且非 //）
            let next = session
                .req_header()
                .uri
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("next=").map(|s| s.to_string())))
                .map(|n| next_redirect_url(&n))
                .filter(|n| n.starts_with('/') && !n.starts_with("//"))
                .unwrap_or_else(|| "/".to_string());

            // P1 仅密码通过 → auth_level = 1（P3 引入 MFA 后升为 2）
            let token = auth.sessions.issue(
                &user.username,
                &user.subject,
                &user.display_name,
                &user.source,
                &user.groups,
                ip,
                1,
                s.session.max_sessions_per_user,
            );
            let secure = if s.session.cookie_secure { "; Secure" } else { "" };
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax{secure}",
                s.session.cookie_name, token
            );
            state.audit.record(
                &user.username,
                "login",
                "auth",
                &format!("source={} display={}", user.source, user.display_name),
                ip,
            );
            log::info!("零信任登录成功: {} (来源 {}, IP {ip})", user.username, user.source);
            respond_json(
                session,
                200,
                &serde_json::json!({
                    "ok": true,
                    "data": {
                        "username": user.username,
                        "display_name": user.display_name,
                        "source": user.source,
                        "groups": user.groups,
                        "redirect": next,
                    }
                }),
                Some(&cookie),
            )
            .await;
            200
        }
        Ok(None) => {
            auth.ratelimit.record_failure(ip);
            state.audit.record(&username, "login_failed", "auth", "用户名或密码错误", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
            401
        }
        Err(identity::AuthFail::Disabled) => {
            state.audit.record(&username, "login_failed_disabled", "auth", "账号已禁用", ip);
            respond_json(session, 403, &serde_json::json!({ "ok": false, "error": "账号已被禁用，请联系管理员" }), None).await;
            403
        }
        Err(identity::AuthFail::BadCredentials) => {
            auth.ratelimit.record_failure(ip);
            state.audit.record(&username, "login_failed", "auth", "用户名或密码错误", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
            401
        }
    }
}

// ---------------------------------------------------------------------------
// me / logout
// ---------------------------------------------------------------------------

async fn handle_me(state: &AppState, session: &mut Session, _ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let req = session.req_header();
    let token = match super::gate::extract_token(req, &s.session.cookie_name) {
        Some(t) => t,
        None => {
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "未登录" }), None).await;
            return 401;
        }
    };
    let idle = s.session.idle_timeout_secs as i64;
    let absolute = s.session.absolute_timeout_secs as i64;
    let Some(info) = auth.sessions.lookup(&token, idle, absolute) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "登录已过期" }), None).await;
        return 401;
    };
    // 重新解析账号（拿最新 mfa / passkey 状态；ldap 来源走缓存+在线复核）
    let user =
        super::identity::resolve(&auth.store, &auth.ldap_cache, &s, &info.username, &info.source).await;
    let body = serde_json::json!({
        "ok": true,
        "data": {
            "username": info.username,
            "display_name": info.display_name,
            "source": info.source,
            "groups": info.groups,
            "auth_level": info.auth_level,
            "ip": info.ip,
            "mfa_required": user.as_ref().map(|u| u.mfa_required).unwrap_or(false),
            "totp_bound": user.as_ref().map(|u| u.totp_bound).unwrap_or(false),
            "passkey_count": user.as_ref().map(|u| u.passkey_count).unwrap_or(0),
        }
    });
    respond_json(session, 200, &body, None).await;
    200
}

async fn handle_logout(state: &AppState, session: &mut Session, _ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let req = session.req_header();
    if let Some(token) = super::gate::extract_token(req, &s.session.cookie_name) {
        let h = hash_token(&token);
        if auth.sessions.remove_if_present(&h) {
            state.audit.record("-", "logout", "auth", &format!("ip={_ip}"), _ip);
        }
    }
    let clear = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", s.session.cookie_name);
    respond_json(session, 200, &serde_json::json!({ "ok": true }), Some(&clear)).await;
    200
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

async fn respond_json(session: &mut Session, status: u16, body: &serde_json::Value, cookie: Option<&str>) {
    let text = body.to_string();
    let mut resp = match ResponseHeader::build(status, Some(text.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", "application/json; charset=utf-8");
    let _ = resp.insert_header("Cache-Control", "no-store");
    if let Some(c) = cookie {
        let _ = resp.insert_header("Set-Cookie", c);
    }
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session
        .write_response_body(Some(Bytes::from(text.into_bytes())), true)
        .await;
}

async fn respond_html(session: &mut Session, status: u16, body: &str) {
    let mut resp = match ResponseHeader::build(status, Some(body.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", "text/html; charset=utf-8");
    let _ = resp.insert_header("Cache-Control", "no-store");
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session
        .write_response_body(Some(Bytes::from(body.to_string())), true)
        .await;
}

/// 读取请求体（上限 1MB，防滥用）
async fn read_body(session: &mut Session) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let chunk = session
            .read_request_body()
            .await
            .map_err(|e| format!("读取请求体失败: {e}"))?;
        if let Some(b) = chunk {
            body.extend_from_slice(&b);
            if body.len() > BODY_CAP {
                return Err("请求体过大".into());
            }
        } else {
            break;
        }
    }
    Ok(body)
}

/// 把登录页拿到的 `?next=` 值解码并还原（防开放重定向：只保留 `/` 开头的同源路径）
fn next_redirect_url(raw: &str) -> String {
    let decoded = percent_decode(raw);
    if decoded.starts_with('/') && !decoded.starts_with("//") {
        decoded
    } else {
        String::new()
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
