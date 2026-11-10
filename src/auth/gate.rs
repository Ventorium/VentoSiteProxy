//! 零信任决策点（gate）。
//!
//! 由代理 request_filter 调用（站点匹配之后、URL 规则之后、上游之前）：
//! 1. 生效开关：`site.auth.enabled`（None = 跟随全局 `auth.enabled`）→ 关闭则 Continue
//! 2. 剥离客户端伪造的 X-VSP-* 身份头（生效时才做）
//! 3. 豁免路径（glob）→ Continue
//! 4. 会话校验（空闲 / 绝对超时）→ 未登录：浏览器 302 登录页 / API 401 JSON
//! 5. 持续评估：账号仍存在且启用，否则撤销会话并按未登录处理
//! 6. 站点 ACL：allowed_users ∪ allowed_groups 命中，否则 403（两份名单皆空 = 任何人都不允许）
//!
//! P1 仅本地用户 + 密码；`mfa_required` 已存储但本阶段不强制（P3 强制并强制首绑）。

use bytes::Bytes;
use pingora::http::RequestHeader;
use pingora::http::ResponseHeader;
use pingora::prelude::Session;

use super::identity;
use super::AuthState;
use crate::config::Site;
use crate::glob::glob_match;

/// 会话摘要（供 upstream_peer 注入 X-VSP-* 与访问日志）
#[derive(Debug, Clone, Default)]
pub struct SessionSummary {
    pub username: String,
    /// 主体（`local:<u>` / `ldap:<u>`）；P3 起用于 MFA/passkey 标识
    #[allow(dead_code)]
    pub subject: String,
    pub source: String,
    pub groups: Vec<String>,
    pub auth_level: u8,
}

pub enum GateResult {
    /// 无需认证（开关关闭 / 豁免路径），按普通请求代理
    Continue,
    /// 已通过认证，继续代理，并向 ctx 记录身份（供上游头注入）
    Authorized(SessionSummary),
    /// 已返回终止响应（302 / 401 / 403）
    Terminated,
}

pub const IDENTITY_HEADERS: &[&str] = &[
    "x-vsp-user",
    "x-vsp-source",
    "x-vsp-groups",
    "x-vsp-auth-level",
];

/// 浏览器导航请求：Accept 含 text/html 且不含 application/json
pub fn is_browser(accept: &str) -> bool {
    let a = accept.to_ascii_lowercase();
    a.contains("text/html") && !a.contains("application/json")
}

/// 会话 token：Cookie 优先，Bearer 兜底（curl / 脚本场景）
pub fn extract_token(req: &RequestHeader, cookie_name: &str) -> Option<String> {
    let cookie = req
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.split(';')
                .map(|kv| kv.trim())
                .find_map(|kv| {
                    kv.split_once('=').and_then(|(k, v)| (k == cookie_name).then(|| v.to_string()))
                })
        });
    cookie.or_else(|| {
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

pub fn strip_identity_headers(req: &mut RequestHeader) {
    for h in IDENTITY_HEADERS.iter().copied() {
        let _ = req.remove_header(h);
    }
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b'?' | b'=' | b'&' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn respond(session: &mut Session, status: u16, content_type: &str, extra: &[(&str, &str)], body: &str) {
    let mut resp = match ResponseHeader::build(status, Some(body.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", content_type);
    let _ = resp.insert_header("Cache-Control", "no-store");
    for (k, v) in extra {
        let _ = resp.insert_header(k.to_string(), v.to_string());
    }
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session.write_response_body(Some(Bytes::from(body.to_string())), true).await;
}

/// 未登录 / 登录失效：浏览器 302 登录页，API 401 JSON（含 login_url）
async fn deny(session: &mut Session, browser: bool, next: &str, msg: &str) {
    let loc = format!("/__auth/login?next={}", urlenc(next));
    if browser {
        let body = format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>正在跳转登录…</title></head><body style=\"margin:0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:system-ui,-apple-system,sans-serif;background:#fafafa;color:#52525b\"><p>{msg}，正在跳转登录页…</p></body></html>"
        );
        respond(session, 302, "text/html; charset=utf-8", &[("Location", &loc)], &body).await;
    } else {
        let body = serde_json::json!({ "ok": false, "error": msg, "login_url": loc }).to_string();
        respond(session, 401, "application/json; charset=utf-8", &[], &body).await;
    }
}

async fn forbidden(session: &mut Session, browser: bool, username: &str) {
    if browser {
        let body = format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>无访问权限</title></head><body style=\"margin:0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:system-ui,-apple-system,sans-serif;background:#fafafa;color:#52525b\"><div style=\"text-align:center\"><h1 style=\"font-size:48px;margin:0\">403</h1><p>您（{username}）没有权限访问此站点</p><p style=\"color:#a1a1aa;font-size:13px\">如需权限请联系管理员</p></div></body></html>"
        );
        respond(session, 403, "text/html; charset=utf-8", &[], &body).await;
    } else {
        let body = serde_json::json!({ "ok": false, "error": "无权访问此站点" }).to_string();
        respond(session, 403, "application/json; charset=utf-8", &[], &body).await;
    }
}

pub async fn evaluate(auth: &AuthState, session: &mut Session, site: &Site, path: &str, ip: &str) -> GateResult {
    let s = auth.settings();
    let site_auth = site.auth.as_ref();
    let effective = site_auth.and_then(|a| a.enabled).unwrap_or(s.enabled);
    if !effective {
        return GateResult::Continue;
    }

    // 剥离客户端伪造的 X-VSP-* 头（生效时才做）
    {
        let req = session.req_header_mut();
        strip_identity_headers(req);
    }

    if let Some(a) = site_auth {
        if a.exempt_paths.iter().any(|p| !p.trim().is_empty() && glob_match(p.trim(), path)) {
            return GateResult::Continue;
        }
    }

    let req = session.req_header();
    let accept = req
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let browser = is_browser(&accept);
    let next = req
        .uri
        .path()
        .to_string()
        + req.uri.query().map(|q| format!("?{q}")).as_deref().unwrap_or("");

    let Some(token) = extract_token(req, &s.session.cookie_name) else {
        deny(session, browser, &next, "尚未登录").await;
        return GateResult::Terminated;
    };

    let idle = s.session.idle_timeout_secs as i64;
    let absolute = s.session.absolute_timeout_secs as i64;
    let Some(info) = auth.sessions.lookup(&token, idle, absolute) else {
        deny(session, browser, &next, "登录已过期").await;
        return GateResult::Terminated;
    };

    // 持续评估：账号必须仍存在且启用（ldap 来源：TTL 缓存 + 在线复核）
    let Some(user) = identity::resolve(&auth.store, &auth.ldap_cache, &s, &info.username, &info.source).await else {
        auth.sessions.remove_if_present(&info.token_hash);
        auth.audit.record(
            &info.username,
            "session_revoked_deleted",
            &site.name,
            "账号已删除，会话被撤销",
            ip,
        );
        deny(session, browser, &next, "用户不存在").await;
        return GateResult::Terminated;
    };
    if !user.enabled {
        auth.sessions.remove_if_present(&info.token_hash);
        auth.audit.record(
            &info.username,
            "session_revoked_disabled",
            &site.name,
            "账号已禁用，会话被撤销",
            ip,
        );
        deny(session, browser, &next, "账号已禁用").await;
        return GateResult::Terminated;
    }

    // 站点 ACL：命中 allowed_users ∪ allowed_groups 才放行。
    // 语义（产品定义）：认证开启后两份名单皆空 = 任何已登录用户都不允许访问。
    if let Some(a) = site_auth {
        let user_ok = a.allowed_users.iter().any(|u| *u == info.username);
        let group_ok = info
            .groups
            .iter()
            .any(|g| a.allowed_groups.iter().any(|ag| ag == g));
        if !user_ok && !group_ok {
            forbidden(session, browser, &info.username).await;
            auth.audit.record(
                &info.username,
                "access_denied_acl",
                &site.name,
                &format!(
                    "path={path} groups={} list_empty={}",
                    info.groups.join(","),
                    a.allowed_users.is_empty() && a.allowed_groups.is_empty()
                ),
                ip,
            );
            return GateResult::Terminated;
        }
    }

    // P3 重认证：用户要求 MFA 且本会话仍是「仅密码」级别 → 必须先过 MFA。
    // 通过后 auth.rs 的 MFA 完成路径将就地升级该会话到 level 2，此后不再拦截。
    if user.mfa_required && info.auth_level < 2 {
        let mfa_url = format!("/__auth/mfa?next={}", urlenc(&next));
        auth.audit.record(
            &info.username,
            "reauth_required",
            &site.name,
            &format!("path={path}"),
            ip,
        );
        if browser {
            let body = format!(
                r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>需要多因素验证</title><meta http-equiv="refresh" content="0; url={mfa_url}"></head><body style="margin:0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:system-ui,-apple-system,sans-serif;background:#fafafa;color:#52525b"><p>需要多因素验证，正在跳转…</p></body></html>"#
            );
            respond(session, 302, "text/html; charset=utf-8", &[("Location", &mfa_url)], &body).await;
        } else {
            let body = serde_json::json!({
                "ok": false,
                "error": "需要多因素验证",
                "reauth_required": true,
                "mfa_url": mfa_url,
            })
            .to_string();
            respond(session, 401, "application/json; charset=utf-8", &[], &body).await;
        }
        return GateResult::Terminated;
    }

    GateResult::Authorized(SessionSummary {
        username: info.username,
        subject: info.subject,
        source: info.source,
        groups: info.groups,
        auth_level: info.auth_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_detection() {
        assert!(is_browser("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        assert!(!is_browser("*/*")); // 含不到 text/html → false
        assert!(!is_browser("application/json"));
        assert!(!is_browser("text/html, application/json"));
        assert!(!is_browser(""));
    }

    #[test]
    fn urlenc_keeps_path_and_unreserved() {
        assert_eq!(urlenc("/a/b?x=1 中文"), "/a/b?x=1%20%E4%B8%AD%E6%96%87");
        assert_eq!(urlenc("/"), "/");
    }
}
