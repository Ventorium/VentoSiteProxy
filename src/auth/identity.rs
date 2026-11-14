//! 身份解析：凭证验证 → `AuthUser`
//!
//! P1：本地用户（argon2id 校验，禁用检查在验证之后以统一错误语义）。
//! P2：LDAP simple-bind 登录 + 覆盖合并（`providers_order` 顺序尝试）；
//!     持续评估走 TTL 缓存 + 服务账号在线复核（stale/deny 降级）。

use super::ldap::{self, LdapCache, LdapUser};
use super::store::UserStore;
use crate::admin::auth::verify_password;
use crate::config::AuthSettings;

/// 认证通过后的用户身份（会话中保存其快照）
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// `local:alice` / `ldap:zhangsan`
    pub subject: String,
    pub username: String,
    pub display_name: String,
    /// `local` | `ldap`
    pub source: String,
    /// 本地组 ∪ LDAP 组（同一池，供站点 ACL 匹配）
    pub groups: Vec<String>,
    pub enabled: bool,
    /// P3 生效：true 时登录后必须完成 MFA（P1 仅存储不强制）
    pub mfa_required: bool,
    pub totp_bound: bool,
    pub passkey_count: usize,
}

/// 登录失败原因
pub enum AuthFail {
    /// 用户不存在或密码错误（对外统一提示，避免用户名枚举）
    BadCredentials,
    /// 账号被禁用
    Disabled,
}

impl std::fmt::Debug for AuthFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthFail::BadCredentials => write!(f, "BadCredentials"),
            AuthFail::Disabled => write!(f, "Disabled"),
        }
    }
}

fn display_of(username: &str, display_name: &str) -> String {
    if display_name.trim().is_empty() {
        username.to_string()
    } else {
        display_name.to_string()
    }
}

/// 本地用户登录。用户不存在 → `Ok(None)`（继续尝试下一个 provider）
fn login_local(store: &UserStore, username: &str, password: &str) -> Result<Option<AuthUser>, AuthFail> {
    let Some(u) = store.local_user(username) else {
        return Ok(None);
    };
    if !matches!(verify_password(password, &u.password_hash), Ok(true)) {
        return Err(AuthFail::BadCredentials);
    }
    if !u.enabled {
        return Err(AuthFail::Disabled);
    }
    Ok(Some(AuthUser {
        subject: format!("local:{username}"),
        username: u.username.clone(),
        display_name: display_of(&u.username, &u.display_name),
        source: "local".to_string(),
        groups: u.groups,
        enabled: true,
        mfa_required: u.mfa_required,
        totp_bound: u.totp_secret.is_some(),
        passkey_count: store.passkey_count(&u.username),
    }))
}

/// LDAP 用户 + 本地覆盖（`auth_ldap_overrides`）合并为 `AuthUser`
fn merge_ldap_user(store: &UserStore, u: LdapUser) -> AuthUser {
    let ov = store.ldap_override(&u.username);
    let mut groups = u.groups;
    if let Some(o) = &ov {
        groups.extend(o.extra_groups.iter().cloned());
    }
    groups.sort();
    groups.dedup();
    let passkey_count = store.passkey_count(&u.username);
    AuthUser {
        subject: format!("ldap:{}", u.username),
        display_name: ov
            .as_ref()
            .and_then(|o| o.display_name.clone())
            .filter(|d| !d.trim().is_empty())
            .unwrap_or(u.display_name),
        source: "ldap".to_string(),
        username: u.username,
        groups,
        enabled: ov.as_ref().and_then(|o| o.enabled).unwrap_or(true),
        mfa_required: ov.as_ref().and_then(|o| o.mfa_required).unwrap_or(false),
        totp_bound: ov.as_ref().map(|o| o.totp_secret.is_some()).unwrap_or(false),
        passkey_count,
    }
}

/// 按 `providers_order` 顺序尝试登录（local → ldap 可配置）。
///
/// - local 命中（密码正确）→ 返回本地用户
/// - local 用户存在但密码错误 → 继续尝试后续 provider（占位密码的 LDAP 同步用户走 LDAP 校验）
/// - local 用户被禁用 → `Err(Disabled)` 短路（管理端禁用语义覆盖所有来源）
/// - local 用户不存在 → 继续尝试后续 provider
/// - ldap 命中 → 合并覆盖后返回；`enabled=Some(false)` → `Err(Disabled)`
/// - ldap 侧任何故障（不可达/服务账号失败/超时）→ `Err(BadCredentials)`（统一 401，详情仅记日志）
pub async fn authenticate(
    store: &UserStore,
    ldap_cache: &LdapCache,
    settings: &AuthSettings,
    username: &str,
    password: &str,
) -> Result<Option<AuthUser>, AuthFail> {
    let order = if settings.providers_order.is_empty() {
        vec!["local".to_string()]
    } else {
        settings.providers_order.clone()
    };
    for p in &order {
        match p.as_str() {
            "local" => match login_local(store, username, password) {
                Ok(Some(u)) => return Ok(Some(u)),
                Ok(None) => {} // 本地无此用户，继续后续 provider
                Err(AuthFail::BadCredentials) => {} // 本地密码不匹配（如 LDAP 同步用户的占位密码），继续后续 provider
                Err(AuthFail::Disabled) => return Err(AuthFail::Disabled),
            },
            "ldap" => match ldap::login_ldap(ldap_cache, &settings.ldap, username, password).await {
                Ok(Some(u)) => {
                    let user = merge_ldap_user(store, u);
                    if !user.enabled {
                        return Err(AuthFail::Disabled);
                    }
                    return Ok(Some(user));
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("LDAP 登录失败 {username}: {e}");
                    return Err(AuthFail::BadCredentials);
                }
            },
            other => log::warn!("未知认证提供者: {other}"),
        }
    }
    Ok(None)
}

/// 持续评估用：从快照重新解析用户（会话有效但账号可能已被删除/禁用）。
///
/// - local：直接读快照（含禁用态）
/// - ldap：TTL 缓存命中直接用；过期则服务账号在线复核：
///   `UserNotFound`（用户已从 LDAP 删除）→ None（任何 fail_mode 都撤销）；
///   网络/服务端 `Err` → `fail_mode=stale` 且有旧缓存时用旧值，否则 None。
pub async fn resolve(
    store: &UserStore,
    ldap_cache: &LdapCache,
    settings: &AuthSettings,
    username: &str,
    source: &str,
) -> Option<AuthUser> {
    match source {
        "local" => {
            let u = store.local_user(username)?;
            Some(AuthUser {
                subject: format!("local:{username}"),
                username: u.username.clone(),
                display_name: display_of(&u.username, &u.display_name),
                source: "local".to_string(),
                groups: u.groups,
                enabled: u.enabled,
                mfa_required: u.mfa_required,
                totp_bound: u.totp_secret.is_some(),
                passkey_count: store.passkey_count(&u.username),
            })
        }
        "ldap" => {
            let ttl = settings.ldap.cache_ttl_secs.max(1);
            if let Some(u) = ldap_cache.get(username, ttl) {
                return Some(merge_ldap_user(store, u));
            }
            match ldap::refresh_ldap(ldap_cache, &settings.ldap, username).await {
                Ok(ldap::RefreshOutcome::Found(u)) => Some(merge_ldap_user(store, u)),
                Ok(ldap::RefreshOutcome::UserNotFound) => {
                    log::info!("LDAP 复核: 用户 {username} 已不存在，会话按未认证处理");
                    None
                }
                Err(e) => {
                    if settings.ldap.fail_mode == "stale" {
                        if let Some(u) = ldap_cache.get_stale(username) {
                            log::error!("LDAP 复核失败({username})，fail_mode=stale 沿用缓存: {e}");
                            return Some(merge_ldap_user(store, u));
                        }
                    }
                    log::error!("LDAP 复核失败({username}, fail_mode={})，会话按未认证处理: {e}", settings.ldap.fail_mode);
                    None
                }
            }
        }
        // P3：passkey 独立来源
        other => {
            log::debug!("resolve: 未知来源 {other}({username})，按未认证处理");
            None
        }
    }
}

/// 免密身份解析（通行密钥直接登录的首因素）：仅凭用户名确认账号存在且可用，不校验密码。
///
/// - 本地用户存在 → 按本地用户返回（禁用 → `Err(Disabled)`）
/// - 本地不存在且 provider 含 ldap → 服务账号查询（不消耗用户密码）；
///   LDAP 故障按 `fail_mode` 降级，最终仍不可用 → `Err(BadCredentials)`（统一错误语义）
/// - 用户不存在 → `Ok(None)`（调用方返回统一提示，避免用户名枚举）
pub async fn resolve_login(
    store: &UserStore,
    ldap_cache: &LdapCache,
    settings: &AuthSettings,
    username: &str,
) -> Result<Option<AuthUser>, AuthFail> {
    if let Some(u) = store.local_user(username) {
        if !u.enabled {
            return Err(AuthFail::Disabled);
        }
        return Ok(Some(AuthUser {
            subject: format!("local:{username}"),
            username: u.username.clone(),
            display_name: display_of(&u.username, &u.display_name),
            source: "local".to_string(),
            groups: u.groups,
            enabled: true,
            mfa_required: u.mfa_required,
            totp_bound: u.totp_secret.is_some(),
            passkey_count: store.passkey_count(&u.username),
        }));
    }
    let has_ldap = settings.providers_order.iter().any(|p| p == "ldap");
    if !has_ldap {
        return Ok(None);
    }
    let ttl = settings.ldap.cache_ttl_secs.max(1);
    if let Some(u) = ldap_cache.get(username, ttl) {
        let merged = merge_ldap_user(store, u);
        if !merged.enabled {
            return Err(AuthFail::Disabled);
        }
        return Ok(Some(merged));
    }
    match ldap::refresh_ldap(ldap_cache, &settings.ldap, username).await {
        Ok(ldap::RefreshOutcome::Found(u)) => {
            let merged = merge_ldap_user(store, u);
            if !merged.enabled {
                return Err(AuthFail::Disabled);
            }
            Ok(Some(merged))
        }
        Ok(ldap::RefreshOutcome::UserNotFound) => Ok(None),
        Err(e) => {
            log::warn!("通行密钥登录 LDAP 查询失败 {username}: {e}");
            if settings.ldap.fail_mode == "stale" {
                if let Some(u) = ldap_cache.get_stale(username) {
                    let merged = merge_ldap_user(store, u);
                    if !merged.enabled {
                        return Err(AuthFail::Disabled);
                    }
                    return Ok(Some(merged));
                }
            }
            Err(AuthFail::BadCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> UserStore {
        let p = std::env::temp_dir().join(format!(
            "vsp_resolve_login_{tag}_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        UserStore::open(&p).unwrap()
    }

    #[tokio::test]
    async fn resolve_login_local_found_and_not_found() {
        let store = tmp_store("basic");
        store
            .create_local_user("alice", "Alice", "$argon2id$xxx", &[], true)
            .unwrap();
        let cache = LdapCache::default();
        let s = crate::config::AuthSettings::default();

        let u = resolve_login(&store, &cache, &s, "alice")
            .await
            .unwrap()
            .expect("本地用户应存在");
        assert_eq!(u.username, "alice");
        assert_eq!(u.source, "local");
        assert!(u.enabled);

        // 默认配置 providers_order=[local]：未知用户 → None（不触 LDAP）
        assert!(resolve_login(&store, &cache, &s, "nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn resolve_login_local_disabled() {
        let store = tmp_store("disabled");
        store
            .create_local_user("bob", "Bob", "$argon2id$xxx", &[], true)
            .unwrap();
        store.update_local_user("bob", None, None, Some(false), None).unwrap();
        let cache = LdapCache::default();
        let s = crate::config::AuthSettings::default();
        assert!(matches!(
            resolve_login(&store, &cache, &s, "bob").await,
            Err(AuthFail::Disabled)
        ));
    }

    #[tokio::test]
    async fn resolve_login_ldap_cache_hit() {
        let store = tmp_store("ldap");
        let mut s = crate::config::AuthSettings::default();
        s.providers_order = vec!["local".to_string(), "ldap".to_string()];
        let cache = LdapCache::default();
        cache.put(
            "carol",
            LdapUser {
                username: "carol".to_string(),
                dn: "uid=carol,ou=people,dc=example,dc=org".to_string(),
                display_name: "Carol".to_string(),
                mail: "carol@example.org".to_string(),
                groups: vec!["eng".to_string()],
            },
        );
        let u = resolve_login(&store, &cache, &s, "carol")
            .await
            .unwrap()
            .expect("LDAP 缓存命中应返回");
        assert_eq!(u.source, "ldap");
        assert_eq!(u.groups, vec!["eng".to_string()]);
    }
}
