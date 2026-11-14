//! 终端用户 `/__auth/*` API（挂在代理端口，request_filter 直接处理，不走上游）
//!
//! - `GET  /__auth/login`              登录页（`?next=` 登录成功后跳回的站内路径）
//! - `POST /__auth/login`              `{username,password}` → P3 三分支（无 MFA → Cookie；
//!                                     需 MFA 有凭据 → pending 凭据；需 MFA 无凭据 → 首次绑定）
//! - `GET  /__auth/me`                 当前会话信息（401 = 未登录/过期）
//! - `POST /__auth/logout`             登出（删会话 + 清 Cookie）
//! - `GET  /__auth/mfa`                MFA 页（验证 / 再验证 / 管理）
//! - `GET  /__auth/enroll`             首次绑定页（开强制 MFA 但尚无凭据）
//! - `GET  /__auth/mfa/state`          MFA 页状态（pending token 或会话 Cookie）
//! - `POST /__auth/mfa/totp`           TOTP 验证（登录 MFA / 再验证）
//! - `GET  /__auth/totp/setup`         TOTP 绑定：签发 secret + 二维码（不落库）
//! - `POST /__auth/totp/setup/finish`  TOTP 绑定：校验动态码并持久化
//! - `POST /__auth/passkey/register/begin|finish`   通行密钥注册
//! - `POST /__auth/passkey/auth/begin|finish`       通行密钥验证
//! - `POST /__auth/passkey/login/begin|finish`      通行密钥免密直接登录（首因素）
//! - `DELETE /__auth/passkey/{credential_id}`       解绑通行密钥
//!
//! 安全：登录与 MFA 均按 IP 限流；next 强制同源；用户不存在与密码错误统一措辞
//! 防用户名枚举；pending / challenge 均一次性、TTL 5 分钟、仅存内存。

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::Session;

use super::identity::{self, AuthUser};
use super::mfa::{self, MfaCtx};
use super::page;
use super::session::{hash_token, SessionInfo};
use super::store::UserStore;
use super::{totp, webauthn};
use crate::config::AppState;

const BODY_CAP: usize = 1 << 20; // 1MB

pub async fn handle(state: &AppState, session: &mut Session, path: &str, ip: &str) -> bool {
    let method = session.req_header().method.clone();
    let _ = match (
        method.as_str(),
        path.trim_end_matches('/').trim_start_matches("/__auth"),
    ) {
        ("GET", "/login" | "") => handle_login_page(session, ip).await,
        ("POST", "/login") => handle_login(state, session, ip).await,
        ("GET", "/me") => handle_me(state, session, ip).await,
        ("POST", "/logout") => handle_logout(state, session, ip).await,
        ("GET", "/mfa") => handle_mfa_page(session).await,
        ("GET", "/enroll") => handle_enroll_page(session).await,
        ("GET", "/mfa/state") => handle_mfa_state(state, session).await,
        ("POST", "/mfa/totp") => handle_mfa_totp(state, session, ip).await,
        ("GET", "/totp/setup") => handle_totp_setup(state, session).await,
        ("POST", "/totp/setup/finish") => handle_totp_setup_finish(state, session, ip).await,
        ("GET", "/passkeys") => handle_passkeys_list(state, session).await,
        ("POST", "/passkey/register/begin") => handle_passkey_register_begin(state, session).await,
        ("POST", "/passkey/register/finish") => handle_passkey_register_finish(state, session, ip).await,
        ("POST", "/passkey/auth/begin") => handle_passkey_auth_begin(state, session).await,
        ("POST", "/passkey/auth/finish") => handle_passkey_auth_finish(state, session, ip).await,
        ("POST", "/passkey/login/begin") => handle_passkey_login_begin(state, session, ip).await,
        ("POST", "/passkey/login/finish") => handle_passkey_login_finish(state, session, ip).await,
        ("DELETE", p) if p.starts_with("/passkey/") => {
            handle_passkey_delete(state, session, &p["/passkey/".len()..], ip).await
        }
        _ => {
            respond_json(session, 404, &serde_json::json!({ "ok": false, "error": "not found" }), None).await;
            404
        }
    };
    true
}

// ---------------------------------------------------------------------------
// 登录 / 登出
// ---------------------------------------------------------------------------

async fn handle_login_page(session: &mut Session, _ip: &str) -> i64 {
    respond_html(session, 200, page::LOGIN_HTML).await;
    200
}

async fn handle_login(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();

    // 登录限流（按 IP）：锁定中直接 429，不碰后端
    if let Some(secs) = auth.ratelimit.is_locked(ip) {
        respond_json(
            session,
            429,
            &serde_json::json!({ "ok": false, "error": "尝试过于频繁，请稍后再试", "retry_after_secs": secs }),
            None,
        )
        .await;
        return 429;
    }

    let body = match read_body(session).await {
        Ok(b) => b,
        Err(e) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 400;
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "请求体格式无效" }), None).await;
            return 400;
        }
    };
    let username = v.get("username").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("").to_string();

    // 用户名格式校验（先过滤，防 LDAP 注入面；统一错误措辞防用户名枚举）
    if username.len() < 2
        || username.len() > 64
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
        return 401;
    }

    match super::identity::authenticate(&auth.store, &auth.ldap_cache, &s, &username, &password).await {
        Ok(Some(user)) => {
            auth.ratelimit.record_success(ip);
            // next 校验：仅允许同源站内路径（/ 开头且非 //，防开放重定向/JS 协议）
            let next = session
                .req_header()
                .uri
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("next=").map(|s| s.to_string())))
                .map(|raw| next_redirect_url(&raw))
                .filter(|n| n.starts_with('/') && !n.starts_with("//"))
                .unwrap_or_else(|| "/".to_string());

            if !user.mfa_required {
                // 分支 a：无需 MFA → 直接签发 level-1 会话
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
                state.audit.record(&user.username, "login", "auth", &format!("source={} next={next}", user.source), ip);
                log::info!("用户登录成功: {} (source={}, IP={ip})", user.username, user.source);
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
            } else {
                // 分支 b/c：需 MFA。有凭据 → 进入 MFA 验证；无凭据 → 首次绑定
                let has_factors = user.totp_bound || user.passkey_count > 0;
                let kind = if has_factors {
                    mfa::PendingKind::Mfa
                } else {
                    mfa::PendingKind::Enroll
                };
                let mfa_token = auth.mfa.issue_pending(mfa::PendingEntry {
                    username: user.username.clone(),
                    subject: user.subject.clone(),
                    display_name: user.display_name.clone(),
                    source: user.source.clone(),
                    groups: user.groups.clone(),
                    ip: ip.to_string(),
                    next: next.clone(),
                    kind,
                    created_at: mfa::now_secs(),
                });
                state.audit.record(
                    &user.username,
                    if kind == mfa::PendingKind::Enroll { "enroll_start" } else { "mfa_start" },
                    "auth",
                    &format!("source={} next={next}", user.source),
                    ip,
                );
                // 注意：此分支不写 Cookie（MFA 通过后才签发）
                respond_json(
                    session,
                    200,
                    &serde_json::json!({
                        "ok": true,
                        "data": {
                            "username": user.username,
                            "display_name": user.display_name,
                            "need_mfa": kind == mfa::PendingKind::Mfa,
                            "enroll_required": kind == mfa::PendingKind::Enroll,
                            "mfa_token": mfa_token,
                            "next": next,
                        }
                    }),
                    None,
                )
                .await;
                200
            }
        }
        Ok(None) => {
            auth.ratelimit.record_failure(ip);
            state.audit.record(&username, "login_fail", "auth", "reason=bad_credentials", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
            401
        }
        Err(super::identity::AuthFail::Disabled) => {
            state.audit.record(&username, "login_fail", "auth", "reason=disabled", ip);
            respond_json(session, 403, &serde_json::json!({ "ok": false, "error": "账号已被禁用，请联系管理员" }), None).await;
            403
        }
        Err(super::identity::AuthFail::BadCredentials) => {
            auth.ratelimit.record_failure(ip);
            state.audit.record(&username, "login_fail", "auth", "reason=bad_credentials", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户名或密码错误" }), None).await;
            401
        }
    }
}

async fn handle_me(state: &AppState, session: &mut Session, _ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let req = session.req_header();
    let Some(token) = super::gate::extract_token(req, &s.session.cookie_name) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "未登录" }), None).await;
        return 401;
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
// MFA 通用：当前操作者（pending 凭据 或 会话 Cookie）
// ---------------------------------------------------------------------------

/// MFA 流程中的当前操作者：登录阶段的 pending 凭据（尚无会话），或已有会话
enum MfaActor {
    /// (pending 快照, 一次性 token)
    Pending(mfa::PendingEntry, String),
    Session(MfaSessionActor),
}

/// 已有会话的 MFA 上下文
struct MfaSessionActor {
    info: SessionInfo,
    /// 通过后要回到的路径（已 sanitize，默认 "/"）
    next: String,
    /// 本次重验证是否由「空闲超时」触发（level-2 会话同样需要，成功后 touch 刷新计时）
    idle_expired: bool,
}

impl MfaActor {
    fn username(&self) -> &str {
        match self {
            MfaActor::Pending(e, _) => &e.username,
            MfaActor::Session(a) => &a.info.username,
        }
    }

    fn source(&self) -> &str {
        match self {
            MfaActor::Pending(e, _) => &e.source,
            MfaActor::Session(a) => &a.info.source,
        }
    }

    fn display_name(&self) -> &str {
        match self {
            MfaActor::Pending(e, _) => &e.display_name,
            MfaActor::Session(a) => &a.info.display_name,
        }
    }

    /// 回跳目标（pending 来自登录请求；会话来自 MFA 页 URL 的 next 参数）
    fn next(&self) -> &str {
        match self {
            MfaActor::Pending(e, _) => &e.next,
            MfaActor::Session(a) => &a.next,
        }
    }

    /// 嵌入 passkey 挑战的上下文：
    /// pending → Pending（成功后消费签发 level-2 会话）；
    /// level-1 会话 → Reauth（成功后就地升级）；
    /// level-2 会话且因空闲超时被拦截 → Reauth（成功后 touch 刷新空闲计时）；
    /// 其余 level-2 会话 → SelfManaged
    fn ctx(&self) -> MfaCtx {
        match self {
            MfaActor::Pending(_, token) => MfaCtx::Pending { pending_token: token.clone() },
            MfaActor::Session(a) => {
                if a.info.auth_level >= 2 && !a.idle_expired {
                    MfaCtx::SelfManaged
                } else {
                    MfaCtx::Reauth { token_hash: a.info.token_hash.clone() }
                }
            }
        }
    }
}

/// 解析当前操作者：优先 pending token，其次会话 Cookie
async fn resolve_actor(
    state: &AppState,
    session: &Session,
    token: Option<&str>,
) -> Result<MfaActor, (u16, String)> {
    let auth = &state.auth;
    let s = auth.settings();
    if let Some(t) = token.filter(|t| !t.trim().is_empty()) {
        return match auth.mfa.peek_pending(t) {
            Some(entry) => Ok(MfaActor::Pending(entry, t.to_string())),
            None => Err((401, "登录已过期，请重新登录".into())),
        };
    }
    let req = session.req_header();
    let Some(cookie) = super::gate::extract_token(req, &s.session.cookie_name) else {
        return Err((401, "未登录".into()));
    };
    // peek 不刷新 last_active：/mfa 页本身是「检测空闲」的一环，刷新后计时就失真了
    let info = auth
        .sessions
        .peek(
            &cookie,
            s.session.idle_timeout_secs as i64,
            s.session.absolute_timeout_secs as i64,
        )
        .ok_or_else(|| (401, "登录已过期，请重新登录".to_string()))?;
    let reauth_secs = crate::config::effective_reauth_secs(&s.session);
    let idle_expired =
        reauth_secs > 0 && (chrono::Utc::now().timestamp() - info.last_active) > reauth_secs;
    let next = query_param(session, "next")
        .map(|n| next_redirect_url(&n))
        .filter(|n| n.starts_with('/') && !n.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());
    Ok(MfaActor::Session(MfaSessionActor {
        info,
        next,
        idle_expired,
    }))
}

/// MFA 成功落地：
/// - Pending → 消费凭据，签发新的 level-2 会话（返回要写入的 Cookie）
/// - Reauth / 低级别会话 → 就地升级为 level 2
/// - SelfManaged（已是 level 2）→ 无操作
fn apply_mfa_success(
    state: &AppState,
    actor: &MfaActor,
    method: &str,
    ip: &str,
) -> Result<Option<String>, (u16, String)> {
    let auth = &state.auth;
    let s = auth.settings();
    match actor {
        MfaActor::Session(a) => {
            let upgraded = a.info.auth_level < 2;
            if upgraded {
                auth.sessions.upgrade_auth_level(&a.info.token_hash, 2);
            }
            // MFA 通过即活跃：刷新空闲计时（升级与空闲重验证共用此路径）
            auth.sessions.touch(&a.info.token_hash);
            state.audit.record(
                &a.info.username,
                "mfa_ok",
                "auth",
                &format!("method={method} upgraded={} idle_expired={}", upgraded, a.idle_expired),
                ip,
            );
            Ok(None)
        }
        MfaActor::Pending(_, token) => {
            let consumed = auth
                .mfa
                .consume_pending(token)
                .ok_or_else(|| (401, "登录已过期，请重新登录".to_string()))?;
            let token2 = auth.sessions.issue(
                &consumed.username,
                &consumed.subject,
                &consumed.display_name,
                &consumed.source,
                &consumed.groups,
                ip,
                2,
                s.session.max_sessions_per_user,
            );
            let secure = if s.session.cookie_secure { "; Secure" } else { "" };
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax{secure}",
                s.session.cookie_name, token2
            );
            state.audit.record(
                &consumed.username,
                "mfa_ok",
                "auth",
                &format!("method={method} kind={:?}", consumed.kind),
                ip,
            );
            log::info!("MFA 验证通过: {} (method={}, IP={ip})", consumed.username, method);
            Ok(Some(cookie))
        }
    }
}

/// 用户的 TOTP secret（本地或 LDAP 覆盖）
fn totp_secret(store: &UserStore, user: &AuthUser) -> Option<String> {
    if user.source == "ldap" {
        store.ldap_override(&user.username).and_then(|o| o.totp_secret)
    } else {
        store.local_user(&user.username).and_then(|u| u.totp_secret)
    }
}

// ---------------------------------------------------------------------------
// MFA 页
// ---------------------------------------------------------------------------

async fn handle_mfa_page(session: &mut Session) -> i64 {
    respond_html(session, 200, page::MFA_HTML).await;
    200
}

async fn handle_enroll_page(session: &mut Session) -> i64 {
    respond_html(session, 200, page::ENROLL_HTML).await;
    200
}

/// MFA 页状态：token → pending 模式（verify / enroll）；Cookie → 会话模式（reauth / manage）
async fn handle_mfa_state(state: &AppState, session: &mut Session) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let token = query_param(session, "token");

    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let user =
        identity::resolve(&auth.store, &auth.ldap_cache, &s, actor.username(), actor.source()).await;

    match &actor {
        MfaActor::Pending(entry, _) => {
            let body = serde_json::json!({
                "ok": true,
                "data": {
                    "mode": if entry.kind == mfa::PendingKind::Enroll { "enroll" } else { "verify" },
                    "next": entry.next,
                    "username": entry.username,
                    "display_name": entry.display_name,
                    "totp_bound": user.as_ref().map(|u| u.totp_bound).unwrap_or(false),
                    "passkey_count": user.as_ref().map(|u| u.passkey_count).unwrap_or(0),
                }
            });
            respond_json(session, 200, &body, None).await;
        }
        MfaActor::Session(a) => {
            let totp_bound = user.as_ref().map(|u| u.totp_bound).unwrap_or(false);
            let passkey_count = user.as_ref().map(|u| u.passkey_count).unwrap_or(0);
            let mfa_required = user.as_ref().map(|u| u.mfa_required).unwrap_or(false);
            // 模式判定与门禁一致：MFA 级别不足，或空闲超时且有二次验证凭据 → reauth
            let needs_verify = (a.info.auth_level < 2 && mfa_required)
                || (a.idle_expired && (totp_bound || passkey_count > 0));
            let mode = if needs_verify { "reauth" } else { "manage" };
            let body = serde_json::json!({
                "ok": true,
                "data": {
                    "mode": mode,
                    "next": a.next,
                    "username": a.info.username,
                    "display_name": a.info.display_name,
                    "auth_level": a.info.auth_level,
                    "mfa_required": mfa_required,
                    "totp_bound": totp_bound,
                    "passkey_count": passkey_count,
                }
            });
            respond_json(session, 200, &body, None).await;
        }
    }
    200
}

/// TOTP 动态码验证（登录 MFA / 再验证）
async fn handle_mfa_totp(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    if let Some(secs) = auth.mfa.guard.is_locked(ip) {
        respond_json(
            session,
            429,
            &serde_json::json!({ "ok": false, "error": "尝试过于频繁，请稍后再试", "retry_after_secs": secs }),
            None,
        )
        .await;
        return 429;
    }
    let v = match read_json_body(session).await {
        Ok(v) => v,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "请输入 6 位数字动态码" }), None).await;
        return 400;
    }
    let token = v.get("token").and_then(|x| x.as_str()).map(|s| s.to_string());
    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let s = auth.settings();
    let user = match identity::resolve(&auth.store, &auth.ldap_cache, &s, actor.username(), actor.source()).await {
        Some(u) => u,
        None => {
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户已不存在，请重新登录" }), None).await;
            return 401;
        }
    };
    let secret = match totp_secret(&auth.store, &user) {
        Some(sec) => sec,
        None => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "尚未绑定动态口令，请先绑定" }), None).await;
            return 400;
        }
    };
    if !totp::verify(&secret, &code) {
        auth.mfa.guard.record_failure(ip);
        state.audit.record(actor.username(), "mfa_fail", "auth", "method=totp", ip);
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "动态码无效，请检查设备时间后重试" }), None).await;
        return 401;
    }
    auth.mfa.guard.record_success(ip);
    match apply_mfa_success(state, &actor, "totp", ip) {
        Ok(cookie) => {
            let next = actor.next().to_string();
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "next": next } }),
                cookie.as_deref(),
            )
            .await;
            200
        }
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            st as i64
        }
    }
}

// ---------------------------------------------------------------------------
// TOTP 绑定
// ---------------------------------------------------------------------------

/// 签发 TOTP secret + 二维码（不落库；客户端确认后可重复获取，确认前作废）
async fn handle_totp_setup(state: &AppState, session: &mut Session) -> i64 {
    let token = query_param(session, "token");
    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let secret = totp::generate_secret();
    let otpauth_uri = totp::otpauth_uri(actor.username(), &secret);
    let qr_png = totp::qr_png_base64(actor.username(), &secret);
    let mut data = serde_json::json!({
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_png": qr_png, // base64 PNG（无 data: 前缀）；生成失败为 null
    });
    // 登录阶段客户端需把 token 带回 finish；会话阶段由 Cookie 识别
    if let MfaActor::Pending(_, token) = &actor {
        data["token"] = serde_json::json!(token);
    }
    respond_json(session, 200, &serde_json::json!({ "ok": true, "data": data }), None).await;
    200
}

/// 校验动态码并持久化 TOTP secret；随后按 ctx 落地（签发/升级会话）
async fn handle_totp_setup_finish(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let v = match read_json_body(session).await {
        Ok(v) => v,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let secret = v.get("secret").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let token = v.get("token").and_then(|x| x.as_str()).map(|s| s.to_string());
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "请输入 6 位数字动态码" }), None).await;
        return 400;
    }
    if secret.is_empty() {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "缺少 secret 参数" }), None).await;
        return 400;
    }
    if !totp::verify(&secret, &code) {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "动态码无效，请重新输入或重新扫码" }), None).await;
        return 400;
    }
    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let s = auth.settings();
    let user = match identity::resolve(&auth.store, &auth.ldap_cache, &s, actor.username(), actor.source()).await {
        Some(u) => u,
        None => {
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户已不存在，请重新登录" }), None).await;
            return 401;
        }
    };
    // 按来源持久化（本地用户 → auth_users；LDAP 用户 → 覆盖表）
    let err = if user.source == "ldap" {
        auth.store.set_ldap_totp(&user.username, Some(&secret)).err()
    } else {
        auth.store.set_local_totp(&user.username, Some(&secret)).err()
    };
    if let Some(e) = err {
        respond_json(session, 500, &serde_json::json!({ "ok": false, "error": e }), None).await;
        return 500;
    }
    let first_factor = !user.totp_bound && user.passkey_count == 0;
    state.audit.record(
        &user.username,
        "totp_register",
        "auth",
        &format!("source={} first_factor={first_factor}", user.source),
        ip,
    );
    if first_factor {
        state.audit.record(&user.username, "enroll_done", "auth", "method=totp", ip);
    }
    match apply_mfa_success(state, &actor, "totp", ip) {
        Ok(cookie) => {
            let next = actor.next().to_string();
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "next": next, "mfa_complete": true } }),
                cookie.as_deref(),
            )
            .await;
            200
        }
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            st as i64
        }
    }
}

// ---------------------------------------------------------------------------
// 通行密钥（passkey / WebAuthn）
// ---------------------------------------------------------------------------

async fn handle_passkey_register_begin(state: &AppState, session: &mut Session) -> i64 {
    let auth = &state.auth;
    let v = match read_json_body(session).await {
        Ok(v) => v,
        Err(_) => v_missing_token(), // body 可空：token 缺省 = Cookie
    };
    let token = v.get("token").and_then(|x| x.as_str()).map(|s| s.to_string());
    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let req = session.req_header();
    let s = auth.settings();
    match webauthn::begin_registration(
        &auth.store,
        &auth.mfa,
        &s.webauthn,
        req,
        actor.username(),
        actor.display_name(),
        actor.ctx(),
    ) {
        Ok((ch_token, public_key)) => {
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "challenge_token": ch_token, "public_key": public_key } }),
                None,
            )
            .await;
            200
        }
        Err(e) => {
            // IP 直连 / origin 问题等 → 400 + 友好提示
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            400
        }
    }
}

/// 空 body 时 token 走 Cookie（`read_json_body` 失败也按无 token 处理）
fn v_missing_token() -> serde_json::Value {
    serde_json::json!({})
}

async fn handle_passkey_register_finish(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let (token, cred_value) = match parse_passkey_finish_body(session).await {
        Ok(x) => x,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential = match serde_json::from_value(cred_value) {
        Ok(c) => c,
        Err(_) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "credential 格式无效" }), None).await;
            return 400;
        }
    };
    let req = session.req_header();
    let s = auth.settings();
    let outcome = match webauthn::finish_registration(
        &auth.store,
        &auth.mfa,
        &s.webauthn,
        req,
        &token,
        &credential,
    ) {
        Ok(o) => o,
        Err(e) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 400;
        }
    };
    state.audit.record(
        &outcome.username,
        "passkey_register",
        "auth",
        &format!("credential_id={}", outcome.credential_id),
        ip,
    );

    match &outcome.ctx {
        MfaCtx::Pending { pending_token } => {
            let entry = auth.mfa.peek_pending(pending_token);
            let next = entry.as_ref().map(|e| e.next.clone()).unwrap_or_else(|| "/".to_string());
            // 首次绑定（Enroll）→ 消费凭据签发 level-2 会话；
            // MFA 验证（Mfa，刚注册的 passkey 尚不满足已绑定前提之外的因素）→ 保留 pending，继续走 MFA
            if entry.as_ref().map(|e| e.kind == mfa::PendingKind::Enroll).unwrap_or(false) {
                match apply_mfa_success(state, &pending_actor(pending_token.clone()), "passkey", ip) {
                    Ok(cookie) => {
                        // 首个因子（此前无任何凭据）
                        state.audit.record(&outcome.username, "enroll_done", "auth", "method=passkey", ip);
                        respond_json(
                            session,
                            200,
                            &serde_json::json!({ "ok": true, "data": { "next": next, "mfa_complete": true } }),
                            cookie.as_deref(),
                        )
                        .await;
                        200
                    }
                    Err((st, msg)) => {
                        respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
                        st as i64
                    }
                }
            } else {
                respond_json(
                    session,
                    200,
                    &serde_json::json!({ "ok": true, "data": { "need_mfa": true, "mfa_token": pending_token, "next": next } }),
                    None,
                )
                .await;
                200
            }
        }
        _ => {
            // Reauth / SelfManaged：按会话就地升级（apply 需要 actor，从 ctx 反推）
            let next = "/".to_string();
            if let MfaCtx::Reauth { token_hash } = &outcome.ctx {
                if auth.sessions.upgrade_auth_level(token_hash, 2) {
                    state.audit.record(&outcome.username, "mfa_ok", "auth", "method=passkey reauth=true", ip);
                }
            }
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "next": next, "mfa_complete": true } }),
                None,
            )
            .await;
            200
        }
    }
}

/// 从 MfaCtx::Pending 重建 actor（apply_mfa_success 只依赖 token）
fn pending_actor(token: String) -> MfaActor {
    // apply_mfa_success 内部只用 token 消费 pending，快照内容无实际用途
    MfaActor::Pending(
        mfa::PendingEntry {
            username: String::new(),
            subject: String::new(),
            display_name: String::new(),
            source: String::new(),
            groups: Vec::new(),
            ip: String::new(),
            next: String::new(),
            kind: mfa::PendingKind::Mfa,
            created_at: 0,
        },
        token,
    )
}

async fn handle_passkey_auth_begin(state: &AppState, session: &mut Session) -> i64 {
    let auth = &state.auth;
    let v = match read_json_body(session).await {
        Ok(v) => v,
        Err(_) => v_missing_token(),
    };
    let token = v.get("token").and_then(|x| x.as_str()).map(|s| s.to_string());
    let actor = match resolve_actor(state, session, token.as_deref()).await {
        Ok(a) => a,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let req = session.req_header();
    let s = auth.settings();
    match webauthn::begin_authentication(&auth.store, &auth.mfa, &s.webauthn, req, actor.username(), actor.ctx(), actor.next()) {
        Ok((ch_token, public_key)) => {
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "challenge_token": ch_token, "public_key": public_key } }),
                None,
            )
            .await;
            200
        }
        Err(e) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            400
        }
    }
}

async fn handle_passkey_auth_finish(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let (token, cred_value) = match parse_passkey_finish_body(session).await {
        Ok(x) => x,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let credential: webauthn_rs::prelude::PublicKeyCredential = match serde_json::from_value(cred_value) {
        Ok(c) => c,
        Err(_) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "credential 格式无效" }), None).await;
            return 400;
        }
    };
    let req = session.req_header();
    let s = auth.settings();
    let outcome = match webauthn::finish_authentication(
        &auth.store,
        &auth.mfa,
        &s.webauthn,
        req,
        &token,
        &credential,
    ) {
        Ok(o) => o,
        Err(e) => {
            state.audit.record("-", "mfa_fail", "auth", "method=passkey", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 401;
        }
    };
    auth.mfa.guard.record_success(ip);
    state.audit.record(
        &outcome.username,
        "mfa_ok",
        "auth",
        &format!("method=passkey uv={}", outcome.user_verified),
        ip,
    );

    match &outcome.ctx {
        MfaCtx::Pending { pending_token } => {
            let entry = auth.mfa.peek_pending(pending_token);
            let next = entry.as_ref().map(|e| e.next.clone()).unwrap_or_else(|| "/".to_string());
            match apply_mfa_success(state, &pending_actor(pending_token.clone()), "passkey", ip) {
                Ok(cookie) => {
                    respond_json(
                        session,
                        200,
                        &serde_json::json!({ "ok": true, "data": { "next": next } }),
                        cookie.as_deref(),
                    )
                    .await;
                    200
                }
                Err((st, msg)) => {
                    respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
                    st as i64
                }
            }
        }
        MfaCtx::Reauth { token_hash } => {
            let upgraded = auth.sessions.upgrade_auth_level(token_hash, 2);
            // MFA 通过即活跃：刷新空闲计时（level-2 空闲重验证同样走此分支）
            auth.sessions.touch(token_hash);
            if upgraded {
                state.audit.record(&outcome.username, "mfa_ok", "auth", "method=passkey reauth=upgraded", ip);
            }
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "next": outcome.next, "mfa_complete": true } }),
                None,
            )
            .await;
            200
        }
        MfaCtx::SelfManaged => {
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "next": outcome.next, "mfa_complete": true } }),
                None,
            )
            .await;
            200
        }
        MfaCtx::Login { .. } => {
            // 直接登录的挑战只能由 /passkey/login/finish 消费
            respond_json(
                session,
                400,
                &serde_json::json!({ "ok": false, "error": "挑战类型不匹配，请重新发起" }),
                None,
            )
            .await;
            400
        }
    }
}

// ---------------------------------------------------------------------------
// 通行密钥直接登录（首因素，免密码）
// ---------------------------------------------------------------------------

/// 第一步：按用户名确认账号存在、可用且已绑定通行密钥，发起 WebAuthn 断言挑战。
/// 不校验密码；LDAP 用户走服务账号查询（不消耗用户密码）。
async fn handle_passkey_login_begin(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();

    // 与密码登录共用的按 IP 限流（锁定中直接 429，不碰后端）
    if let Some(secs) = auth.ratelimit.is_locked(ip) {
        respond_json(
            session,
            429,
            &serde_json::json!({ "ok": false, "error": "尝试过于频繁，请稍后再试", "retry_after_secs": secs }),
            None,
        )
        .await;
        return 429;
    }

    let body = match read_body(session).await {
        Ok(b) => b,
        Err(e) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 400;
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "请求体格式无效" }), None).await;
            return 400;
        }
    };
    let username = v.get("username").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    // 与密码登录同一套格式校验（防 LDAP 注入面）
    if username.len() < 2
        || username.len() > 64
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "用户名格式无效" }), None).await;
        return 400;
    }

    let user = match identity::resolve_login(&auth.store, &auth.ldap_cache, &s, &username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            state.audit.record(&username, "login_fail", "auth", "method=passkey reason=user_not_found", ip);
            respond_json(
                session,
                401,
                &serde_json::json!({ "ok": false, "error": "用户不存在或该用户未绑定通行密钥" }),
                None,
            )
            .await;
            return 401;
        }
        Err(identity::AuthFail::Disabled) => {
            state.audit.record(&username, "login_fail", "auth", "method=passkey reason=disabled", ip);
            respond_json(session, 403, &serde_json::json!({ "ok": false, "error": "账号已被禁用，请联系管理员" }), None).await;
            return 403;
        }
        Err(identity::AuthFail::BadCredentials) => {
            state.audit.record(&username, "login_fail", "auth", "method=passkey reason=ldap_unavailable", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "无法确认账号（认证源异常），请稍后重试" }), None).await;
            return 401;
        }
    };

    if user.passkey_count == 0 {
        respond_json(
            session,
            400,
            &serde_json::json!({ "ok": false, "error": "该用户未绑定通行密钥，请用密码登录后绑定" }),
            None,
        )
        .await;
        return 400;
    }

    let next = v
        .get("next")
        .and_then(|x| x.as_str())
        .map(|raw| next_redirect_url(raw))
        .filter(|n| n.starts_with('/') && !n.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());
    let req = session.req_header();
    let ctx = mfa::MfaCtx::Login {
        subject: user.subject.clone(),
        display_name: user.display_name.clone(),
        source: user.source.clone(),
        groups: user.groups.clone(),
    };
    match webauthn::begin_authentication(&auth.store, &auth.mfa, &s.webauthn, req, &username, ctx, &next) {
        Ok((ch_token, public_key)) => {
            respond_json(
                session,
                200,
                &serde_json::json!({ "ok": true, "data": { "challenge_token": ch_token, "public_key": public_key } }),
                None,
            )
            .await;
            200
        }
        Err(e) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": e }), None).await;
            400
        }
    }
}

/// 第二步：校验 WebAuthn 断言，通过后直接签发 level-2 会话（通行密钥本身即满足 MFA 强度，
/// 无需再走 TOTP；uv=required 由 webauthn 库强制）。
async fn handle_passkey_login_finish(state: &AppState, session: &mut Session, ip: &str) -> i64 {
    let auth = &state.auth;
    let (token, cred_value) = match parse_passkey_finish_body(session).await {
        Ok(x) => x,
        Err((st, msg)) => {
            respond_json(session, st, &serde_json::json!({ "ok": false, "error": msg }), None).await;
            return st as i64;
        }
    };
    let credential: webauthn_rs::prelude::PublicKeyCredential = match serde_json::from_value(cred_value) {
        Ok(c) => c,
        Err(_) => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "credential 格式无效" }), None).await;
            return 400;
        }
    };
    let req = session.req_header();
    let s = auth.settings();
    let outcome = match webauthn::finish_authentication(
        &auth.store,
        &auth.mfa,
        &s.webauthn,
        req,
        &token,
        &credential,
    ) {
        Ok(o) => o,
        Err(e) => {
            auth.ratelimit.record_failure(ip);
            auth.mfa.guard.record_failure(ip);
            state.audit.record("-", "login_fail", "auth", "method=passkey", ip);
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 401;
        }
    };
    let (subject, display_name, source, groups) = match &outcome.ctx {
        mfa::MfaCtx::Login {
            subject,
            display_name,
            source,
            groups,
            ..
        } => (subject.clone(), display_name.clone(), source.clone(), groups.clone()),
        _ => {
            respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "挑战类型不匹配，请重新发起通行密钥登录" }), None).await;
            return 400;
        }
    };
    auth.ratelimit.record_success(ip);
    auth.mfa.guard.record_success(ip);
    let token2 = auth.sessions.issue(
        &outcome.username,
        &subject,
        &display_name,
        &source,
        &groups,
        ip,
        2,
        s.session.max_sessions_per_user,
    );
    let secure = if s.session.cookie_secure { "; Secure" } else { "" };
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax{secure}",
        s.session.cookie_name, token2
    );
    state.audit.record(
        &outcome.username,
        "login",
        "auth",
        &format!("method=passkey uv={} source={source} next={}", outcome.user_verified, outcome.next),
        ip,
    );
    log::info!("通行密钥直接登录成功: {} (source={}, IP={ip})", outcome.username, source);
    respond_json(
        session,
        200,
        &serde_json::json!({
            "ok": true,
            "data": {
                "username": outcome.username,
                "display_name": display_name,
                "source": source,
                "redirect": outcome.next,
            }
        }),
        Some(&cookie),
    )
    .await;
    200
}

/// 列出当前用户已绑定的通行密钥（管理页用，仅 Cookie 会话）
async fn handle_passkeys_list(state: &AppState, session: &mut Session) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let req = session.req_header();
    let Some(cookie) = super::gate::extract_token(req, &s.session.cookie_name) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "未登录" }), None).await;
        return 401;
    };
    let Some(info) = auth.sessions.lookup(
        &cookie,
        s.session.idle_timeout_secs as i64,
        s.session.absolute_timeout_secs as i64,
    ) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "登录已过期" }), None).await;
        return 401;
    };
    let list = auth.store.list_passkeys(&info.username);
    let data: Vec<serde_json::Value> = list
        .iter()
        .map(|p| {
            serde_json::json!({
                "credential_id": p.credential_id,
                "name": p.name,
                "rp_id": p.rp_id,
                "sign_count": p.sign_count,
                "created_at": p.created_at,
            })
        })
        .collect();
    respond_json(session, 200, &serde_json::json!({ "ok": true, "data": data }), None).await;
    200
}

async fn handle_passkey_delete(state: &AppState, session: &mut Session, credential_id: &str, ip: &str) -> i64 {
    let auth = &state.auth;
    let s = auth.settings();
    let req = session.req_header();
    let Some(cookie) = super::gate::extract_token(req, &s.session.cookie_name) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "未登录" }), None).await;
        return 401;
    };
    let Some(info) = auth.sessions.lookup(
        &cookie,
        s.session.idle_timeout_secs as i64,
        s.session.absolute_timeout_secs as i64,
    ) else {
        respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "登录已过期" }), None).await;
        return 401;
    };
    let cid = credential_id.trim();
    if cid.is_empty() {
        respond_json(session, 400, &serde_json::json!({ "ok": false, "error": "缺少 credential_id" }), None).await;
        return 400;
    }
    let user = match identity::resolve(&auth.store, &auth.ldap_cache, &s, &info.username, &info.source).await {
        Some(u) => u,
        None => {
            respond_json(session, 401, &serde_json::json!({ "ok": false, "error": "用户已不存在" }), None).await;
            return 401;
        }
    };
    // 归属校验（find_passkey 已按 username 限定）
    if auth.store.find_passkey(&user.username, cid).is_none() {
        respond_json(session, 404, &serde_json::json!({ "ok": false, "error": "通行密钥不存在" }), None).await;
        return 404;
    }
    let remaining = match auth.store.delete_passkey(&user.username, cid) {
        Ok(b) => b,
        Err(e) => {
            respond_json(session, 500, &serde_json::json!({ "ok": false, "error": e }), None).await;
            return 500;
        }
    };
    // 最后一个因子删除且无 TOTP → 自动关闭强制 MFA
    let mfa_off = if !remaining && !user.totp_bound {
        if user.source == "ldap" {
            let _ = auth.store.set_ldap_mfa_required(&user.username, false);
        } else {
            let _ = auth.store.update_local_user(&user.username, None, None, None, Some(false));
        }
        true
    } else {
        false
    };
    state.audit.record(
        &user.username,
        "passkey_delete",
        "auth",
        &format!("credential_id={cid} mfa_off={mfa_off}"),
        ip,
    );
    respond_json(
        session,
        200,
        &serde_json::json!({ "ok": true, "data": { "mfa_required_off": mfa_off } }),
        None,
    )
    .await;
    200
}

/// 解析 passkey finish 请求体 {token, credential}
async fn parse_passkey_finish_body(
    session: &mut Session,
) -> Result<(String, serde_json::Value), (u16, String)> {
    let body = read_body(session)
        .await
        .map_err(|e| (400, e))?;
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| (400, format!("请求体 JSON 解析失败: {e}")))?;
    let token = v
        .get("token")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let credential = v
        .get("credential")
        .cloned()
        .ok_or_else(|| (400, "缺少 credential 字段".to_string()))?;
    Ok((token, credential))
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

async fn read_json_body(session: &mut Session) -> Result<serde_json::Value, (u16, String)> {
    let body = read_body(session).await.map_err(|e| (400, e))?;
    serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|e| (400, format!("请求体 JSON 解析失败: {e}")))
}

/// 取 URL query 参数（原始值，未解码）
fn query_param(session: &Session, key: &str) -> Option<String> {
    let q = session.req_header().uri.query()?;
    q.split('&').find_map(|kv| {
        kv.strip_prefix(key).and_then(|v| v.strip_prefix('=').map(|s| s.to_string()))
    })
}

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
    match session.read_request_body().await {
        Ok(Some(b)) => {
            if b.len() > BODY_CAP {
                return Err("请求体过大".to_string());
            }
            Ok(b.to_vec())
        }
        Ok(None) => Ok(Vec::new()),
        Err(e) => Err(format!("读取请求体失败: {e}")),
    }
}

/// next 参数校验：仅允许同源站内路径（解码后 / 开头、非 //、无协议头）
fn next_redirect_url(raw: &str) -> String {
    let decoded = percent_decode(raw);
    if !decoded.starts_with('/')
        || decoded.starts_with("//")
        || decoded.contains('\\')
        || decoded.contains("://")
    {
        return "/".to_string();
    }
    decoded
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
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
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_url_allows_same_origin() {
        assert_eq!(next_redirect_url("/sites/x"), "/sites/x");
        assert_eq!(next_redirect_url("/a%20b"), "/a b");
    }

    #[test]
    fn next_url_blocks_open_redirect() {
        assert_eq!(next_redirect_url("//evil.com"), "/");
        assert_eq!(next_redirect_url("https://evil.com"), "/");
        assert_eq!(next_redirect_url("/\\evil.com"), "/");
    }
}
