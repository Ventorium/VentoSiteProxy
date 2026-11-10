//! Passkey / WebAuthn 支持（P3）
//!
//! - `Webauthn` 按请求构建：origin 取 `X-Forwarded-Proto`（仅 http/https，默认 http）
//!   + `Host` 头；rp_id 可配置（`auth.webauthn.rp_id`），缺省 = Host 的可注册域名
//!   （eTLD+1，如 `app.ventosite.com` → `ventosite.com`）。浏览器要求 rp_id 必须是
//!   可注册域名（或页面有效域名的可注册域名后缀），传完整子域名会同步抛 SecurityError。
//!   IP 直连无法使用 passkey（WebAuthn 要求域名 origin），返回友好提示。
//! - 挑战状态（`PasskeyRegistration`/`PasskeyAuthentication`）不可序列化、必须服务端
//!   持有，存 `mfa::MfaState`（一次性，TTL 5 分钟）。
//! - passkey 持久化：`auth_passkeys.public_key` BLOB = webauthn-rs `Passkey` 的 JSON。
//! - credential_id 统一用 base64url **无填充**（与浏览器 `credential.id` 一致）。

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use pingora::http::RequestHeader;
use serde_json::{json, Value};
use webauthn_rs::prelude::{
    AuthenticationResult, CredentialID, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use crate::auth::mfa::{now_secs, new_token, ChallengeEntry, MfaCtx, MfaState};
use crate::auth::store::UserStore;
use crate::config::WebAuthnSettings;

/// 固定命名空间：用户名 → 稳定 per-user WebAuthn user ID
/// （Uuid::new_v5 非常量函数，用 OnceLock 惰性初始化）
fn user_id_namespace() -> uuid::Uuid {
    static NS: std::sync::OnceLock<uuid::Uuid> = std::sync::OnceLock::new();
    *NS.get_or_init(|| {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"ventositeproxy.mfa.passkey.user")
    })
}

/// 派生用户级稳定 UUID（跨设备/跨凭据一致）
pub fn user_uuid(username: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&user_id_namespace(), username.as_bytes())
}

/// base64url 无填充编码（浏览器 credential.id 的格式）
pub fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url 解码（容忍带/不带填充）
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let res = if s.contains('=') {
        base64::engine::general_purpose::URL_SAFE.decode(s)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
    };
    res.map_err(|e| format!("credential id 解码失败: {e}"))
}

/// 从请求推导 origin：(scheme, host)。IP 直连 → Err（友好中文提示）
pub fn request_origin(req: &RequestHeader) -> Result<(String, String), String> {
    let host = req
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    if host.is_empty() {
        return Err("请求缺少 Host 头，无法确定来源".into());
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err("通行密钥需要域名访问，IP 直连不可用；请改用域名访问本代理".into());
    }
    let scheme = req
        .headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim())
        .filter(|s| *s == "http" || *s == "https")
        .unwrap_or("http");
    Ok((scheme.to_string(), host))
}

/// 可注册域名（eTLD+1，基于公共后缀表 PSL）：
/// `egt-dsh.aihualing.com` → `aihualing.com`；`a.b.c.ainanjing.org.cn` → `ainanjing.org.cn`。
/// 浏览器 WebAuthn 规定 rp_id 必须是可注册域名（或有效域名的可注册域名后缀），
/// 传完整子域名会令 `navigator.credentials.create/get` 同步抛 SecurityError。
/// PSL 无法解析时（单标签主机名、未知后缀等）返回 None，调用方回退为 host 原样。
/// 注意：PSL 含数字 TLD（如 223），IP 也可能"解析成功"，但 `request_origin`
/// 在调用本函数之前已拒绝 IP 直连，故无影响。
pub fn registrable_domain(host: &str) -> Option<String> {
    let bare = host.split(':').next()?;
    if bare.is_empty() {
        return None;
    }
    psl::domain_str(bare).map(str::to_string)
}

/// rp_id：配置优先（`auth.webauthn.rp_id`），否则取 Host 的可注册域名（eTLD+1）。
pub fn rp_id_for(settings: &WebAuthnSettings, host: &str) -> String {
    let cfg = settings.rp_id.trim();
    if !cfg.is_empty() {
        return cfg.to_string();
    }
    registrable_domain(host)
        .unwrap_or_else(|| host.split(':').next().unwrap_or("").to_string())
}

/// 按当前请求构建 Webauthn（rp_id/origin 均请求级推导，支持多站点/多域名）
pub fn build_webauthn(
    settings: &WebAuthnSettings,
    req: &RequestHeader,
) -> Result<(Arc<Webauthn>, String), String> {
    let (scheme, host) = request_origin(req)?;
    let rp_id = rp_id_for(settings, &host);
    if rp_id.is_empty() {
        return Err("无法确定 rp_id：Host 为空且 auth.yaml 未配置 auth.webauthn.rp_id".into());
    }
    let origin = format!("{scheme}://{host}");
    let origin_url = Url::parse(&origin).map_err(|e| format!("origin 无效 {origin}: {e}"))?;
    let mut builder = WebauthnBuilder::new(&rp_id, &origin_url)
        .map_err(|e| format!("WebAuthn 初始化失败（rp_id 与来源域名不匹配）: {e}"))?;
    if !settings.rp_name.is_empty() {
        builder = builder.rp_name(&settings.rp_name);
    }
    builder = builder
        .allow_any_port(true)
        .timeout(Duration::from_secs(60));
    for o in &settings.origins {
        match Url::parse(o) {
            Ok(u) => builder = builder.append_allowed_origin(&u),
            Err(e) => log::warn!("auth.webauthn.origins 中 {o} 不是合法 URL，已忽略: {e}"),
        }
    }
    let wa = builder
        .build()
        .map_err(|e| format!("WebAuthn 初始化失败: {e}"))?;
    Ok((Arc::new(wa), rp_id))
}

/// 注册结果（api 层据此落地：入库 + 会话）
pub struct FinishRegistrationOutcome {
    pub username: String,
    pub credential_id: String,
    pub ctx: MfaCtx,
}

/// 认证结果（api 层据此落地：计数器回写 + 会话）
pub struct FinishAuthenticationOutcome {
    pub username: String,
    pub ctx: MfaCtx,
    pub user_verified: bool,
    /// 通过后要回到的路径（begin 时记录）
    pub next: String,
}

/// 发起 passkey 注册；返回 (challenge_token, public_key JSON)
pub fn begin_registration(
    store: &UserStore,
    mfa: &MfaState,
    settings: &WebAuthnSettings,
    req: &RequestHeader,
    username: &str,
    display_name: &str,
    ctx: MfaCtx,
) -> Result<(String, Value), String> {
    let (wa, rp_id) = build_webauthn(settings, req)?;
    // exclude 已绑定凭据，防止同一凭据重复注册
    let mut exclude: Vec<CredentialID> = Vec::new();
    for row in store.list_passkeys(username) {
        match serde_json::from_slice::<Passkey>(&row.public_key) {
            Ok(pk) => exclude.push(pk.cred_id().clone()),
            Err(e) => log::warn!("passkey {} 反序列化失败，跳过: {e}", row.credential_id),
        }
    }
    let (challenge, registration) = wa
        .start_passkey_registration(
            user_uuid(username),
            username,
            display_name,
            if exclude.is_empty() { None } else { Some(exclude) },
        )
        .map_err(|e| format!("发起 passkey 注册失败: {e}"))?;
    let token = new_token();
    mfa.store_challenge(token.clone(), ChallengeEntry::Register {
        username: username.to_string(),
        display_name: display_name.to_string(),
        rp_id,
        ctx,
        reg: registration,
        created_at: now_secs(),
    });
    // 直接下发浏览器所需的 PublicKeyCredentialCreationOptions（challenge / user.id
    // 为 base64url 字符串，前端需还原为 ArrayBuffer 后才能传给 navigator.credentials.create）。
    let public_key = serde_json::to_value(&challenge.public_key)
        .map_err(|e| format!("序列化注册挑战失败: {e}"))?;
    Ok((token, public_key))
}

/// 完成 passkey 注册：校验 + 入库。会话落地由 api 层执行。
pub fn finish_registration(
    store: &UserStore,
    mfa: &MfaState,
    settings: &WebAuthnSettings,
    req: &RequestHeader,
    token: &str,
    credential: &RegisterPublicKeyCredential,
) -> Result<FinishRegistrationOutcome, String> {
    let Some(entry) = mfa.take_challenge(token) else {
        return Err("passkey 挑战已过期或不存在，请重试".into());
    };
    let (username, display_name, ctx, reg) = match entry {
        ChallengeEntry::Register { username, display_name, ctx, reg, .. } => {
            (username, display_name, ctx, reg)
        }
        _ => return Err("挑战类型不匹配，请重试".into()),
    };
    let (wa, rp_id) = build_webauthn(settings, req)?;
    let passkey = wa
        .finish_passkey_registration(credential, &reg)
        .map_err(|e| format!("passkey 注册校验失败: {e}"))?;
    let cred_id = b64url_encode(passkey.cred_id());
    let pk_bytes =
        serde_json::to_vec(&passkey).map_err(|e| format!("passkey 序列化失败: {e}"))?;
    store
        .add_passkey(&username, &cred_id, &display_name, &pk_bytes, &rp_id)
        .map_err(|e| format!("保存 passkey 失败: {e}"))?;
    Ok(FinishRegistrationOutcome {
        username: username.to_string(),
        credential_id: cred_id,
        ctx,
    })
}

/// 发起 passkey 认证；返回 (challenge_token, public_key JSON)
pub fn begin_authentication(
    store: &UserStore,
    mfa: &MfaState,
    settings: &WebAuthnSettings,
    req: &RequestHeader,
    username: &str,
    ctx: MfaCtx,
    next: &str,
) -> Result<(String, Value), String> {
    let rows = store.list_passkeys(username);
    let mut passkeys: Vec<Passkey> = Vec::new();
    for row in rows {
        match serde_json::from_slice::<Passkey>(&row.public_key) {
            Ok(pk) => passkeys.push(pk),
            Err(e) => log::warn!("passkey {} 反序列化失败，跳过: {e}", row.credential_id),
        }
    }
    if passkeys.is_empty() {
        return Err("尚未注册通行密钥，请先绑定动态口令或通行密钥".into());
    }
    let (wa, rp_id) = build_webauthn(settings, req)?;
    let (challenge, authentication) = wa
        .start_passkey_authentication(&passkeys)
        .map_err(|e| format!("发起 passkey 验证失败: {e}"))?;
    let token = new_token();
    mfa.store_challenge(token.clone(), ChallengeEntry::Authenticate {
        username: username.to_string(),
        rp_id,
        ctx,
        auth: authentication,
        created_at: now_secs(),
        next: next.to_string(),
    });
    // 同上：直接下发 PublicKeyCredentialRequestOptions 本体（camelCase JSON），
    // 前端还原二进制字段后可直接传给 navigator.credentials.get。
    let public_key = serde_json::to_value(&challenge.public_key)
        .map_err(|e| format!("序列化验证挑战失败: {e}"))?;
    Ok((token, public_key))
}

/// 完成 passkey 认证：校验 + 计数器回写。会话落地由 api 层执行。
pub fn finish_authentication(
    store: &UserStore,
    mfa: &MfaState,
    settings: &WebAuthnSettings,
    req: &RequestHeader,
    token: &str,
    credential: &PublicKeyCredential,
) -> Result<FinishAuthenticationOutcome, String> {
    let Some(entry) = mfa.take_challenge(token) else {
        return Err("passkey 挑战已过期或不存在，请重试".into());
    };
    let (username, ctx, auth_state, next) = match entry {
        ChallengeEntry::Authenticate {
            username,
            ctx,
            auth,
            next,
            ..
        } => (username, ctx, auth, next),
        _ => return Err("挑战类型不匹配，请重试".into()),
    };
    let (wa, _) = build_webauthn(settings, req)?;
    let result: AuthenticationResult = wa
        .finish_passkey_authentication(credential, &auth_state)
        .map_err(|e| format!("passkey 验证失败: {e}"))?;
    // 计数器/公钥更新回写（失败仅告警，不影响本次登录）
    if result.needs_update() {
        let cred_id = b64url_encode(result.cred_id());
        if let Some(row) = store.find_passkey(&username, &cred_id) {
            match serde_json::from_slice::<Passkey>(&row.public_key) {
                Ok(mut pk) => {
                    let _ = pk.update_credential(&result);
                    if let Ok(bytes) = serde_json::to_vec(&pk) {
                        if let Err(e) =
                            store.update_passkey(&cred_id, &username, &bytes, result.counter() as i64)
                        {
                            log::warn!("回写 passkey 计数器失败: {e}");
                        }
                    }
                }
                Err(e) => log::warn!("passkey {} 反序列化失败，跳过回写: {e}", cred_id),
            }
        }
    }
    Ok(FinishAuthenticationOutcome {
        username: username.to_string(),
        ctx,
        user_verified: result.user_verified(),
        next,
    })
}

/// 供管理端/测试：把浏览器回传的 credential id（b64url）转成字节
#[allow(dead_code)]
pub fn parse_credential_id(s: &str) -> Result<Vec<u8>, String> {
    b64url_decode(s)
}

/// 请求体解析辅助：{token, credential}
#[allow(dead_code)]
pub fn parse_auth_body(body: &str) -> Result<(String, Value), String> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| format!("请求体 JSON 解析失败: {e}"))?;
    let token = v
        .get("token")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let credential = v
        .get("credential")
        .cloned()
        .ok_or_else(|| "缺少 credential 字段".to_string())?;
    Ok((token, credential))
}

/// 供测试断言：RequestChallengeResponse 可序列化为 camelCase JSON
#[allow(dead_code)]
pub fn debug_challenge_json(ch: &RequestChallengeResponse) -> Value {
    serde_json::to_value(ch).unwrap_or_else(|_| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_subdomain_to_etld1() {
        assert_eq!(
            registrable_domain("egt-dsh.aihualing.com").as_deref(),
            Some("aihualing.com")
        );
        assert_eq!(
            registrable_domain("a.b.c.ainanjing.org.cn").as_deref(),
            Some("ainanjing.org.cn")
        );
        assert_eq!(
            registrable_domain("pktest.invalid").as_deref(),
            Some("pktest.invalid")
        );
        assert_eq!(
            registrable_domain("sub.pktest.invalid").as_deref(),
            Some("pktest.invalid")
        );
        // 带端口
        assert_eq!(
            registrable_domain("app.example.com:8443").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn registrable_domain_unresolvable_returns_none() {
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("proxy"), None);
        assert_eq!(registrable_domain(":8080"), None);
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn registrable_domain_ip_has_psl_numeric_tld() {
        // PSL 含数字 TLD（223）→ 会"成功"解析；实际 IP 直连已被 request_origin 拦截
        assert_eq!(
            registrable_domain("192.168.211.223").as_deref(),
            Some("211.223")
        );
    }

    #[test]
    fn rp_id_prefers_config_override() {
        let mut s = WebAuthnSettings::default();
        s.rp_id = "custom.example.com".into();
        assert_eq!(rp_id_for(&s, "x.other.com:443"), "custom.example.com");
    }

    #[test]
    fn rp_id_falls_back_to_etld1() {
        let s = WebAuthnSettings::default();
        assert_eq!(rp_id_for(&s, "egt-dsh.aihualing.com"), "aihualing.com");
        // PSL 无法解析（单标签）→ 原样返回
        assert_eq!(rp_id_for(&s, "proxy"), "proxy");
    }
}
