//! LDAP 认证 provider（P2）：simple-bind 登录 + 用户属性/组反查 + TTL 缓存。
//!
//! 登录流程（设计 §4.3，一次连接完成全部步骤）：
//! ① 服务账号绑定（`bind_dn`/`bind_password`）
//! ② 用户搜索：`base=user_search_base`、`filter=({attr_login}={username})`、Subtree
//! ③ 用户绑定：`user_dn + password` —— 成功即完成认证；
//!    密码错误/账号被锁等失败统一对外 401（不区分原因，防用户名枚举）
//! ④ 服务账号重读用户属性 + 组反查
//!    （`base=group_search_base`、`filter=(|(uniqueMember=<dn>)(member=<dn>))`）
//! ⑤ 结果写入 TTL 缓存
//!
//! 持续评估（`refresh_ldap`，供 `identity::resolve` 与后台评估器复用）：
//! 只做**服务账号搜索**（不校验密码），区分三类结果：
//! - `Found`：用户仍在，属性/组已刷新入缓存
//! - `UserNotFound`：搜索成功但无此用户 → 调用方应撤销会话（stale 模式也不豁免）
//! - `Err`：网络/服务端故障 → 调用方按 `fail_mode`（stale 用旧缓存 / deny 拒绝）

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use crate::config::LdapSettings;

/// LDAP resultCode（本 crate 无公开常量，按 RFC 4511 局部定义）
#[allow(dead_code)]
pub const LDAP_RC_OK: u32 = 0;
#[allow(dead_code)]
pub const LDAP_RC_NO_SUCH_OBJECT: u32 = 32;
pub const LDAP_RC_INVALID_CREDENTIALS: u32 = 49;
#[allow(dead_code)]
pub const LDAP_RC_INSUFFICIENT_ACCESS: u32 = 50;
#[allow(dead_code)]
pub const LDAP_RC_BUSY: u32 = 51;
#[allow(dead_code)]
pub const LDAP_RC_UNWILLING_TO_PERFORM: u32 = 53;

// ---------------------------------------------------------------------------
// 缓存
// ---------------------------------------------------------------------------

/// 缓存的 LDAP 用户信息（登录/复核成功后刷新）
#[derive(Debug, Clone, PartialEq)]
pub struct LdapUser {
    pub username: String,
    pub dn: String,
    pub display_name: String,
    /// 缓存备查（管理端/P3 展示用）
    #[allow(dead_code)]
    pub mail: String,
    /// 反查得到的组名（同一池，供站点 ACL 匹配）
    pub groups: Vec<String>,
}

struct CacheEntry {
    user: LdapUser,
    verified_at: Instant,
}

/// LDAP 用户缓存（挂在 `AuthState` 上，跨请求共享）
#[derive(Default)]
pub struct LdapCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl LdapCache {
    /// TTL 内命中；`ttl_secs` 传 0 表示“已过期”（只用于测试/取旧值前判断）
    pub fn get(&self, username: &str, ttl_secs: u64) -> Option<LdapUser> {
        let m = self.entries.lock().ok()?;
        let e = m.get(username)?;
        (e.verified_at.elapsed() < Duration::from_secs(ttl_secs)).then(|| e.user.clone())
    }

    /// 忽略 TTL 取旧值（fail_mode=stale 降级用）
    pub fn get_stale(&self, username: &str) -> Option<LdapUser> {
        let m = self.entries.lock().ok()?;
        m.get(username).map(|e| e.user.clone())
    }

    pub fn put(&self, username: &str, user: LdapUser) {
        if let Ok(mut m) = self.entries.lock() {
            m.insert(
                username.to_string(),
                CacheEntry {
                    user,
                    verified_at: Instant::now(),
                },
            );
        }
    }

    /// 用户已从 LDAP 删除时清缓存；返回是否命中并删除
    pub fn remove(&self, username: &str) -> bool {
        self.entries.lock().ok().map(|mut m| m.remove(username).is_some()).unwrap_or(false)
    }

    // 管理端/诊断用；当前主程序未调用
    #[allow(dead_code)]
    pub fn usernames(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// 过滤串构造（RFC 4515，可单测）
// ---------------------------------------------------------------------------

/// 转义 RFC 4515 过滤值中的特殊字符：`* ( ) \ NUL`
pub fn escape_filter_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '*' => out.push_str(r"\*"),
            '(' => out.push_str(r"\("),
            ')' => out.push_str(r"\)"),
            '\\' => out.push_str(r"\\"),
            '\0' => out.push_str(r"\00"),
            _ => out.push(c),
        }
    }
    out
}

/// 登录用户名搜索过滤：`({attr_login}={username})`
pub fn user_search_filter(login_attr: &str, username: &str) -> String {
    format!("({login_attr}={})", escape_filter_value(username))
}

/// 组反查过滤（兼容 groupOfUniqueNames 与 posixGroup 混用）
pub fn group_reverse_filter(user_dn: &str) -> String {
    let dn = escape_filter_value(user_dn);
    format!("(|(uniqueMember={dn})(member={dn}))")
}

// ---------------------------------------------------------------------------
// 连接与基础操作
// ---------------------------------------------------------------------------

fn clamp_timeout_ms(ms: u64) -> Duration {
    Duration::from_millis(ms.clamp(100, 60_000))
}

/// 打开 LDAP 连接并后台驱动；丢弃最后一个 `Ldap` 句柄即关闭连接。
async fn open_conn(settings: &LdapSettings) -> Result<Ldap, String> {
    let s = LdapConnSettings::new().set_conn_timeout(clamp_timeout_ms(settings.timeout_ms as u64));
    let (conn, ldap) = LdapConnAsync::with_settings(s, &settings.uri)
        .await
        .map_err(|e| format!("LDAP 连接失败({}): {e}", settings.uri))?;
    // 必须后台 drive，否则请求/响应无法送达（ldap3::drive! 等价物）
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            log::warn!("LDAP 连接退出: {e}");
        }
    });
    Ok(ldap)
}

/// 服务账号绑定；空密码视为未配置直接报错
async fn service_bind(ldap: &mut Ldap, settings: &LdapSettings) -> Result<(), String> {
    if settings.bind_password.is_empty() {
        return Err("LDAP 服务账号密码未配置".to_string());
    }
    let r = ldap
        .simple_bind(&settings.bind_dn, &settings.bind_password)
        .await
        .map_err(|e| format!("LDAP 服务账号绑定请求失败: {e}"))?;
    if r.rc != LDAP_RC_OK {
        return Err(match r.rc {
            LDAP_RC_INVALID_CREDENTIALS => "LDAP 服务账号用户名或密码错误".to_string(),
            other => format!("LDAP 服务账号绑定失败(rc={other}): {}", r.text),
        });
    }
    Ok(())
}

/// 属性值查找（忽略大小写，跳过空值）
fn attr_str<'a>(attrs: &'a HashMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.iter().find(|v| !v.trim().is_empty()))
        .map(|v| v.trim())
}

/// 显示名回退链：`attr_name` → `cn` → `attr_login` → username
pub fn pick_display_name(
    attrs: &HashMap<String, Vec<String>>,
    name_attr: &str,
    login_attr: &str,
    username: &str,
) -> String {
    for k in [name_attr, "cn", login_attr] {
        if let Some(v) = attr_str(attrs, k) {
            return v.to_string();
        }
    }
    username.to_string()
}

/// 组条目取名：`cn` 优先，缺失时退化为 DN 第一个 RDN 的值
fn group_name(e: &SearchEntry) -> Option<String> {
    if let Some(cn) = attr_str(&e.attrs, "cn") {
        return Some(cn.to_string());
    }
    e.dn
        .split(',')
        .next()
        .and_then(|rdn| rdn.splitn(2, '=').nth(1))
        .map(|v| v.to_string())
}

/// 搜索用户条目（要求已服务绑定）；0 条 → Ok(None)
async fn fetch_user(
    ldap: &mut Ldap,
    settings: &LdapSettings,
    username: &str,
) -> Result<Option<LdapUser>, String> {
    let filter = user_search_filter(&settings.attr_login, username);
    let mut attrs: Vec<&str> = vec![settings.attr_login.as_str(), "dn", "mail"];
    if settings.attr_name != settings.attr_login {
        attrs.push(settings.attr_name.as_str());
    }
    attrs.push("cn");
    let res = ldap
        .search(&settings.user_search_base, Scope::Subtree, &filter, &attrs)
        .await
        .map_err(|e| format!("LDAP 用户搜索失败: {e}"))?;
    if res.1.rc != LDAP_RC_OK {
        return Err(format!("LDAP 用户搜索错误(rc={}): {}", res.1.rc, res.1.text));
    }
    let entries: Vec<SearchEntry> = res.0.into_iter().map(SearchEntry::construct).collect();
    if entries.len() > 1 {
        log::warn!("LDAP 用户 {username} 匹配到 {} 条记录，取第一条", entries.len());
    }
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(LdapUser {
        username: username.to_string(),
        dn: entry.dn.clone(),
        display_name: pick_display_name(&entry.attrs, &settings.attr_name, &settings.attr_login, username),
        mail: attr_str(&entry.attrs, "mail").unwrap_or("").to_string(),
        groups: Vec::new(),
    }))
}

/// 组反查（要求已服务绑定）
async fn fetch_groups(ldap: &mut Ldap, settings: &LdapSettings, user_dn: &str) -> Result<Vec<String>, String> {
    let filter = group_reverse_filter(user_dn);
    let res = ldap
        .search(&settings.group_search_base, Scope::Subtree, &filter, &["cn"])
        .await
        .map_err(|e| format!("LDAP 组搜索失败: {e}"))?;
    if res.1.rc != LDAP_RC_OK {
        return Err(format!("LDAP 组搜索错误(rc={}): {}", res.1.rc, res.1.text));
    }
    let mut groups: Vec<String> = res
        .0
        .into_iter()
        .map(SearchEntry::construct)
        .filter_map(|e| group_name(&e))
        .collect();
    groups.sort();
    groups.dedup();
    Ok(groups)
}

// ---------------------------------------------------------------------------
// 登录 / 复核 / 连接测试
// ---------------------------------------------------------------------------

/// LDAP 登录：服务绑定 → 用户搜索 → 用户绑定 → 属性+组读取 → 写缓存。
///
/// - 用户不存在 → `Ok(None)`（调用方继续下一个 provider）
/// - 用户绑定失败 / 服务故障 / 超时 → `Err`（调用方统一 401，详情仅记日志）
pub async fn login_ldap(
    cache: &LdapCache,
    settings: &LdapSettings,
    username: &str,
    password: &str,
) -> Result<Option<LdapUser>, String> {
    let timeout = clamp_timeout_ms(settings.timeout_ms as u64);
    let result = tokio::time::timeout(timeout, async {
        let mut ldap = open_conn(settings).await?;
        service_bind(&mut ldap, settings).await?;
        let Some(mut user) = fetch_user(&mut ldap, settings, username).await? else {
            return Ok(None);
        };
        let r = ldap
            .simple_bind(&user.dn, password)
            .await
            .map_err(|e| format!("LDAP 用户绑定请求失败: {e}"))?;
        if r.rc != LDAP_RC_OK {
            return Err(match r.rc {
                LDAP_RC_INVALID_CREDENTIALS => "LDAP 用户绑定失败(密码错误)".to_string(),
                other => format!("LDAP 用户绑定失败(rc={other}): {}", r.text),
            });
        }
        user.groups = fetch_groups(&mut ldap, settings, &user.dn).await?;
        Ok(Some(user))
    })
    .await;

    match result {
        Err(_) => Err(format!("LDAP 操作超时({}ms)", settings.timeout_ms)),
        Ok(Ok(Some(user))) => {
            cache.put(&user.username, user.clone());
            Ok(Some(user))
        }
        Ok(other) => other,
    }
}

/// 持续评估复核结果
pub enum RefreshOutcome {
    /// 用户仍在（属性/组已刷新入缓存）
    Found(LdapUser),
    /// 搜索成功但用户已不存在（调用方应撤销会话，stale 模式也不豁免）
    UserNotFound,
}

/// 服务账号在线复核（不校验密码）。网络/服务端故障 → `Err`。
pub async fn refresh_ldap(
    cache: &LdapCache,
    settings: &LdapSettings,
    username: &str,
) -> Result<RefreshOutcome, String> {
    let timeout = clamp_timeout_ms(settings.timeout_ms as u64);
    let result = tokio::time::timeout(timeout, async {
        let mut ldap = open_conn(settings).await?;
        service_bind(&mut ldap, settings).await?;
        let Some(mut user) = fetch_user(&mut ldap, settings, username).await? else {
            return Ok(RefreshOutcome::UserNotFound);
        };
        user.groups = fetch_groups(&mut ldap, settings, &user.dn).await?;
        Ok(RefreshOutcome::Found(user))
    })
    .await;

    match result {
        Err(_) => Err(format!("LDAP 操作超时({}ms)", settings.timeout_ms)),
        Ok(Ok(RefreshOutcome::Found(user))) => {
            cache.put(username, user.clone());
            Ok(RefreshOutcome::Found(user))
        }
        Ok(Ok(RefreshOutcome::UserNotFound)) => {
            cache.remove(username);
            Ok(RefreshOutcome::UserNotFound)
        }
        Ok(Err(e)) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// 管理端连接测试
// ---------------------------------------------------------------------------

/// 连接测试样例（首个用户 + 其组）
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdapSampleUser {
    pub username: String,
    pub dn: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

/// 连接测试结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdapConnTestResult {
    pub latency_ms: u64,
    pub user_count: usize,
    pub sample: Option<LdapSampleUser>,
}

/// 管理端“测试连接”：服务绑定 + 用户计数 + 首个用户组反查（全部在 timeout 内）
pub async fn test_connection(settings: &LdapSettings) -> Result<LdapConnTestResult, String> {
    let timeout = clamp_timeout_ms(settings.timeout_ms as u64);
    let t0 = Instant::now();

    let inner = async {
        let mut ldap = open_conn(settings).await?;
        service_bind(&mut ldap, settings).await?;

        let res = ldap
            .search(&settings.user_search_base, Scope::Subtree, "(objectClass=person)", &[settings.attr_login.as_str()])
            .await
            .map_err(|e| format!("LDAP 用户枚举失败: {e}"))?;
        if res.1.rc != LDAP_RC_OK {
            return Err(format!("LDAP 用户枚举错误(rc={}): {}", res.1.rc, res.1.text));
        }
        let entries: Vec<SearchEntry> = res.0.into_iter().map(SearchEntry::construct).collect();
        let user_count = entries.len();

        let sample = entries.first().map(|first| LdapSampleUser {
            username: attr_str(&first.attrs, &settings.attr_login).unwrap_or("").to_string(),
            dn: first.dn.clone(),
            display_name: pick_display_name(&first.attrs, &settings.attr_name, &settings.attr_login, ""),
            groups: Vec::new(),
        });
        // 首个用户的组反查（验证组搜索路径可用；失败不阻断，仅提示）
        let sample = match sample {
            Some(mut s) => {
                match fetch_groups(&mut ldap, settings, &s.dn).await {
                    Ok(g) => s.groups = g,
                    Err(e) => log::warn!("LDAP 组反查失败: {e}"),
                }
                Some(s)
            }
            None => None,
        };

        Ok(LdapConnTestResult {
            latency_ms: t0.elapsed().as_millis() as u64,
            user_count,
            sample,
        })
    };

    match tokio::time::timeout(timeout, inner).await {
        Ok(r) => r,
        Err(_) => Err(format!("LDAP 操作超时({}ms)", settings.timeout_ms)),
    }
}

// ---------------------------------------------------------------------------
// 用户同步（管理端「从 LDAP 同步」）
// ---------------------------------------------------------------------------

/// 「从 LDAP 同步」结果
#[derive(Debug, serde::Serialize)]
pub struct LdapSyncResult {
    /// 目录中枚举到的可导入用户数（含登录名属性）
    pub total: usize,
    /// 在本地用户库新建的用户数（占位密码，登录走 LDAP）
    pub created: usize,
    /// 已存在、刷新了显示名并合并了组的用户数
    pub updated: usize,
    /// 组反查失败的用户（不阻断同步，仅提示）
    pub group_failures: Vec<String>,
}

/// 从 LDAP 全量同步用户到本地用户库：
/// 服务绑定 → 枚举 `user_search_base` 下所有用户 → 逐个组反查 → upsert。
///
/// 不变式：
/// - 新用户：占位密码（随机串，本地永远无法匹配），登录后由 LDAP provider 校验密码
/// - 已有用户：只更新显示名、合并组（本地已有组 ∪ LDAP 组）；
///   **永不触碰密码 / enabled / mfa_required / TOTP**
pub async fn sync_users(
    store: &super::store::UserStore,
    settings: &LdapSettings,
) -> Result<LdapSyncResult, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // 全量枚举 + 逐用户组反查，比单次登录重得多；给 120s 全局上限
    let timeout = Duration::from_secs(120);
    let inner = async {
        let mut ldap = open_conn(settings).await?;
        service_bind(&mut ldap, settings).await?;

        let res = ldap
            .search(
                &settings.user_search_base,
                Scope::Subtree,
                "(objectClass=person)",
                &[settings.attr_login.as_str()],
            )
            .await
            .map_err(|e| format!("LDAP 用户枚举失败: {e}"))?;
        if res.1.rc != LDAP_RC_OK {
            return Err(format!(
                "LDAP 用户枚举错误(rc={}): {}",
                res.1.rc, res.1.text
            ));
        }
        let entries: Vec<SearchEntry> = res.0.into_iter().map(SearchEntry::construct).collect();

        let mut total = 0usize;
        let mut created = 0usize;
        let mut updated = 0usize;
        let mut group_failures: Vec<String> = Vec::new();

        for e in entries {
            let username = match attr_str(&e.attrs, &settings.attr_login) {
                Some(u) if !u.trim().is_empty() => u.to_string(),
                _ => continue, // 无登录名的条目无法导入
            };
            total += 1;
            let display =
                pick_display_name(&e.attrs, &settings.attr_name, &settings.attr_login, &username);
            let groups = match fetch_groups(&mut ldap, settings, &e.dn).await {
                Ok(g) => g,
                Err(err) => {
                    log::warn!("LDAP 组反查失败({username}): {err}");
                    group_failures.push(username.clone());
                    Vec::new()
                }
            };

            if let Some(cur) = store.local_user(&username) {
                // 已有本地用户：显示名刷新为目录值；组 = 本地已有 ∪ LDAP（保留手工加的组）
                let mut merged = groups;
                for g in &cur.groups {
                    if !merged.contains(g) {
                        merged.push(g.clone());
                    }
                }
                merged.sort();
                merged.dedup();
                store
                    .update_local_user(&username, Some(&display), Some(&merged), None, None)
                    .map_err(|err| format!("更新用户 {username} 失败: {err}"))?;
                updated += 1;
            } else {
                let placeholder = format!(
                    "vsp-ldap-sync-{username}-{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                );
                let hash = crate::config::AdminConf::generate_password_hash(&placeholder)
                    .map_err(|err| format!("生成占位密码失败({username}): {err}"))?;
                store
                    .create_local_user(&username, &display, &hash, &groups, false)
                    .map_err(|err| format!("创建用户 {username} 失败: {err}"))?;
                created += 1;
            }
        }

        Ok(LdapSyncResult {
            total,
            created,
            updated,
            group_failures,
        })
    };

    match tokio::time::timeout(timeout, inner).await {
        Ok(r) => r,
        Err(_) => Err("LDAP 同步超时（>120s），请重试".to_string()),
    }
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_basics() {
        assert_eq!(escape_filter_value("abc"), "abc");
        assert_eq!(escape_filter_value("xieyun"), "xieyun");
        assert_eq!(escape_filter_value("a*b"), r"a\*b");
        assert_eq!(escape_filter_value("a(b)"), r"a\(b\)");
        assert_eq!(escape_filter_value("a\\b"), r"a\\b");
        assert_eq!(escape_filter_value("a\0b"), r"a\00b");
        // 中文等非 ASCII 不转义
        assert_eq!(escape_filter_value("张三"), "张三");
        // DN 含逗号/等号不转义（RFC 4515 逗号不在特殊字符集内）
        assert_eq!(escape_filter_value("cn=x,dc=a,dc=b"), "cn=x,dc=a,dc=b");
    }

    #[test]
    fn filter_building() {
        assert_eq!(user_search_filter("uid", "xieyun"), "(uid=xieyun)");
        assert_eq!(
            user_search_filter("sAMAccountName", "a(b)*"),
            r"(sAMAccountName=a\(b\)\*)"
        );
        let dn = "cn=张三,ou=People,dc=ainanjing,dc=org,dc=cn";
        assert_eq!(
            group_reverse_filter(dn),
            format!("(|(uniqueMember={dn})(member={dn}))")
        );
    }

    #[test]
    fn display_name_fallback_chain() {
        let mut attrs = HashMap::new();
        attrs.insert("displayName".to_string(), vec!["".to_string()]);
        attrs.insert("cn".to_string(), vec!["张三".to_string()]);
        assert_eq!(pick_display_name(&attrs, "displayName", "uid", "zhangsan"), "张三");

        let mut attrs = HashMap::new();
        attrs.insert("DisplayName".to_string(), vec!["  Zhang San  ".to_string()]);
        assert_eq!(pick_display_name(&attrs, "displayName", "uid", "zhangsan"), "Zhang San");

        assert_eq!(pick_display_name(&HashMap::new(), "displayName", "uid", "zhangsan"), "zhangsan");
    }

    #[test]
    fn cache_ttl_and_stale() {
        let c = LdapCache::default();
        assert!(c.is_empty());
        let u = LdapUser {
            username: "u1".into(),
            dn: "cn=u1,dc=a".into(),
            display_name: "U1".into(),
            mail: "".into(),
            groups: vec!["g1".into()],
        };
        c.put("u1", u.clone());
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("u1", 300).unwrap(), u);
        assert!(c.get("u1", 0).is_none(), "ttl=0 应视为过期");
        assert_eq!(c.get_stale("u1").unwrap(), u, "stale 不受 TTL 限制");
        assert!(c.remove("u1"));
        assert!(c.get_stale("u1").is_none());
        assert!(c.usernames().is_empty());
        // 覆盖 put
        c.put("u1", u.clone());
        c.put("u1", u);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn cache_expiry_by_time() {
        let c = LdapCache::default();
        c.put("u", LdapUser {
            username: "u".into(),
            dn: "d".into(),
            display_name: "d".into(),
            mail: "".into(),
            groups: vec![],
        });
        assert!(c.get("u", 300).is_some());
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get("u", 0).is_none());
        assert!(c.get_stale("u").is_some());
    }
}
