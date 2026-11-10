//! VentoSiteProxy 配置模型：
//! - `MainConf`：服务端自身配置（ventsitemproxy.yaml → 程序化构造 ServerConf）
//! - `AppConfig`：站点 / TCP 流 路由表（sites.yaml，管理端每次变更后原子落盘 + ArcSwap 热切换）
//! - `AdminConf`：管理端认证配置（admin.yaml）
//! - `AppState`：各服务共享的运行时状态

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 主配置（ventsitemproxy.yaml）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MainConf {
    pub version: u32,
    pub proxy_listen: String,
    pub admin_listen: String,
    pub threads: u32,
    pub grace_period_seconds: u64,
    pub upgrade_sock: String,
    pub pid_file: String,
    pub sites_file: String,
    pub admin_file: String,
    pub log_dir: String,
    /// 可选：错误日志文件；留空则输出到 stdout
    #[serde(default)]
    pub error_log: Option<String>,
    /// 零信任认证配置（auth.yaml，chmod 600，热加载）
    /// 注意：不能加字段级 `#[serde(default)]` —— 缺键时会取 String::default()（空串），
    /// 而不是结构体级 Default impl 里的 /opt/ventositeproxy 路径；统一走结构体级 default。
    pub auth_file: String,
    /// 零信任认证用户库（SQLite）
    pub auth_db: String,
}

impl Default for MainConf {
    fn default() -> Self {
        Self {
            version: 1,
            proxy_listen: "0.0.0.0:8880".into(),
            admin_listen: "0.0.0.0:8890".into(),
            threads: 4,
            grace_period_seconds: 30,
            upgrade_sock: "/opt/ventositeproxy/upgrade.sock".into(),
            pid_file: "/opt/ventositeproxy/ventositeproxy.pid".into(),
            sites_file: "/opt/ventositeproxy/sites.yaml".into(),
            admin_file: "/opt/ventositeproxy/admin.yaml".into(),
            log_dir: "/opt/ventositeproxy/logs".into(),
            error_log: None,
            auth_file: "/opt/ventositeproxy/auth.yaml".into(),
            auth_db: "/opt/ventositeproxy/auth.db".into(),
        }
    }
}

impl MainConf {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("主配置文件不存在: {}", path.display()));
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let conf: MainConf = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
        Ok(conf)
    }

    pub fn sites_path(&self) -> PathBuf {
        PathBuf::from(&self.sites_file)
    }

    pub fn admin_path(&self) -> PathBuf {
        PathBuf::from(&self.admin_file)
    }

    pub fn log_dir(&self) -> PathBuf {
        PathBuf::from(&self.log_dir)
    }

    pub fn audit_path(&self) -> PathBuf {
        self.log_dir().join("audit.jsonl")
    }

    pub fn auth_path(&self) -> PathBuf {
        PathBuf::from(&self.auth_file)
    }

    pub fn auth_db_path(&self) -> PathBuf {
        PathBuf::from(&self.auth_db)
    }

    pub fn access_log_dir(&self) -> PathBuf {
        self.log_dir().join("access")
    }
}

// ---------------------------------------------------------------------------
// 路由表（sites.yaml）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRule {
    pub pattern: String,
    #[serde(default = "default_action_allow")]
    pub action: UrlAction,
}

fn default_action_allow() -> UrlAction {
    UrlAction::Allow
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Location {
    /// glob 路径，如 `/mqtt*`
    pub path: String,
    pub upstream: String,
    #[serde(default = "default_scheme")]
    pub upstream_scheme: String,
    #[serde(default)]
    pub connect_timeout: u64,
    #[serde(default)]
    pub read_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 是否记录本站点的访问日志
    #[serde(default = "default_true")]
    pub access_log: bool,
    pub domains: Vec<String>,
    pub upstream: String,
    #[serde(default = "default_scheme")]
    pub upstream_scheme: String,
    /// 上游 TLS 时的 SNI；留空自动取上游地址（IP 则不发送 SNI）
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default)]
    pub verify_cert: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    /// 秒；0 = 不限制（SSE / 长连接场景）
    #[serde(default)]
    pub read_timeout: u64,
    #[serde(default)]
    pub write_timeout: u64,
    /// 按序匹配的 location 级上游覆盖（对应 NPM 的 locations）
    #[serde(default)]
    pub locations: Vec<Location>,
    /// 按序匹配，首个命中生效（白名单=默认 deny + 放行规则；黑名单=默认 allow + 拦截规则）
    #[serde(default)]
    pub url_rules: Vec<UrlRule>,
    /// 未命中任何规则时的动作；默认放行（黑名单模式）
    #[serde(default = "default_action_allow")]
    pub url_default: UrlAction,
    /// 本站零信任访问控制（None = 跟随全局开关）
    #[serde(default)]
    pub auth: Option<SiteAuth>,
}

fn default_true() -> bool {
    true
}
fn default_scheme() -> String {
    "http".into()
}
fn default_connect_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStream {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 监听地址，如 `0.0.0.0:8008`
    pub listen: String,
    /// 上游地址，如 `192.168.1.10:8002`
    pub upstream: String,
}

/// 未匹配 Host 时的默认响应模式
pub const DEFAULT_404_STATUS: &str = "status"; // 只返回 404 状态码 + 最小文本（默认）
pub const DEFAULT_404_PAGE: &str = "page";     // 内置通用 404 页面
pub const DEFAULT_404_CUSTOM: &str = "custom"; // 用户自定义目录

pub fn is_valid_default_404(m: &str) -> bool {
    m == DEFAULT_404_STATUS || m == DEFAULT_404_PAGE || m == DEFAULT_404_CUSTOM
}

/// 访问日志自动清理：归档日期早于保留天数的日志文件将被删除（默认开启，保留 180 天）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogCleanup {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_retention_days() -> u32 {
    180
}

impl Default for LogCleanup {
    fn default() -> Self {
        Self { enabled: true, retention_days: 180 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub version: u32,
    pub sites: Vec<Site>,
    pub streams: Vec<TcpStream>,
    /// 请求 Host 未命中任何启用站点时的默认响应：status / page / custom
    pub default_404: String,
    /// custom 模式使用的文件目录（放 404.html 及页面引用的 css/图片等）
    pub custom_404_dir: String,
    /// 访问日志自动清理（默认开启，保留 180 天）
    #[serde(default)]
    pub log_cleanup: LogCleanup,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: 0,
            sites: Vec::new(),
            streams: Vec::new(),
            default_404: DEFAULT_404_STATUS.into(),
            custom_404_dir: "custom404".into(),
            log_cleanup: LogCleanup::default(),
        }
    }
}

impl AppConfig {
    pub fn next_site_id(&self) -> u64 {
        self.sites.iter().map(|s| s.id).max().unwrap_or(0) + 1
    }

    pub fn next_stream_id(&self) -> u64 {
        self.streams.iter().map(|s| s.id).max().unwrap_or(0) + 1
    }
}

pub fn load_app_config(path: &Path) -> Result<AppConfig, String> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let cfg: AppConfig = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// 零信任认证配置（auth.yaml）
// 与 admin.yaml / sites.yaml 分离：认证开关、会话、MFA、LDAP、限流独立热加载。
// ---------------------------------------------------------------------------

/// auth.yaml 文件结构（顶层 `auth:` 段）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthFileConf {
    pub version: u32,
    pub auth: AuthSettings,
}

impl Default for AuthFileConf {
    fn default() -> Self {
        Self { version: 1, auth: AuthSettings::default() }
    }
}

/// 认证全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSettings {
    /// 总开关；关闭时网关行为与未启用零信任完全一致
    pub enabled: bool,
    /// 提供者顺序（P1 仅 local；P2 追加 ldap）
    pub providers_order: Vec<String>,
    /// 是否向上游注入 X-VSP-* 身份头
    pub inject_upstream_headers: bool,
    pub session: SessionSettings,
    pub webauthn: WebAuthnSettings,
    pub ldap: LdapSettings,
    pub ratelimit: RatelimitSettings,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            providers_order: vec!["local".to_string()],
            inject_upstream_headers: true,
            session: SessionSettings::default(),
            webauthn: WebAuthnSettings::default(),
            ldap: LdapSettings::default(),
            ratelimit: RatelimitSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionSettings {
    /// 空闲超时（秒），默认 8 小时
    pub idle_timeout_secs: u64,
    /// 绝对寿命（秒），默认 30 天
    pub absolute_timeout_secs: u64,
    /// 每用户最大并发会话数
    pub max_sessions_per_user: usize,
    /// 会话 Cookie 名称
    pub cookie_name: String,
    /// Cookie 是否带 Secure（frp HTTPS 外层应为 true；直连 HTTP 测试可关）
    pub cookie_secure: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 8 * 3600,
            absolute_timeout_secs: 30 * 86400,
            max_sessions_per_user: 5,
            cookie_name: "vsp_session".to_string(),
            cookie_secure: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebAuthnSettings {
    pub rp_name: String,
    /// 留空 = 从请求 Host 自动推导
    pub rp_id: String,
    /// 留空 = 自动推导为 https://<Host>（页面可配置多域名，逗号分隔）
    pub origins: Vec<String>,
}

impl Default for WebAuthnSettings {
    fn default() -> Self {
        Self {
            rp_name: "VentoSiteProxy".to_string(),
            rp_id: String::new(),
            origins: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LdapSettings {
    /// 如 ldap://192.168.209.101:389（636 走 ldaps）
    pub uri: String,
    /// 服务账号 DN（本阶段使用 cn=admin，简单绑定）
    pub bind_dn: String,
    /// 服务账号密码（仅存 auth.yaml，管理端 API 脱敏展示）
    pub bind_password: String,
    pub user_search_base: String,
    pub group_search_base: String,
    /// 登录属性（DN 组件名），如 uid
    pub attr_login: String,
    /// 显示名属性，如 displayName
    pub attr_name: String,
    /// 用户/组属性缓存 TTL（秒）
    pub cache_ttl_secs: u64,
    /// 连接与查询超时（毫秒）
    pub timeout_ms: u64,
    /// LDAP 服务故障策略：stale=容忍陈旧缓存，deny=拒绝登录
    pub fail_mode: String,
}

impl Default for LdapSettings {
    fn default() -> Self {
        let dc = "dc=ainanjing,dc=org,dc=cn";
        Self {
            uri: "ldap://192.168.209.101:389".to_string(),
            bind_dn: format!("cn=admin,{dc}"),
            bind_password: String::new(),
            user_search_base: format!("ou=People,{dc}"),
            group_search_base: format!("ou=Groups,{dc}"),
            attr_login: "uid".to_string(),
            attr_name: "displayName".to_string(),
            cache_ttl_secs: 300,
            timeout_ms: 5000,
            fail_mode: "stale".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RatelimitSettings {
    /// 窗口内最大登录失败次数
    pub max_failed: u32,
    /// 失败计数窗口（秒）
    pub window_secs: u64,
    /// 超限后锁定（秒）
    pub lockout_secs: u64,
}

impl Default for RatelimitSettings {
    fn default() -> Self {
        Self { max_failed: 5, window_secs: 600, lockout_secs: 900 }
    }
}

/// 站点级零信任访问控制（写入 sites.yaml 每个站点）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteAuth {
    /// None = 跟随全局开关（auth.yaml 的 enabled，文件级默认值）
    pub enabled: Option<bool>,
    /// 豁免路径（glob，如 /health*），命中则免认证
    pub exempt_paths: Vec<String>,
    /// 允许的登录名（精确匹配）；认证开启时，未命中用户且未命中组 = 拒绝
    pub allowed_users: Vec<String>,
    /// 允许的组（本地组与 LDAP 组同一池）；与 allowed_users 二者皆空 = 拒绝所有已登录用户
    pub allowed_groups: Vec<String>,
}

/// 加载 auth.yaml：文件不存在 → 默认（认证关闭）；解析失败 → 返回 Err（由调用方降级）
pub fn load_auth_config(path: &Path) -> Result<AuthFileConf, String> {
    if !path.exists() {
        return Ok(AuthFileConf::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let conf: AuthFileConf = serde_yaml::from_str(&text)
        .map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
    Ok(conf)
}

/// 认证配置序列化（管理端 API 返回前对 bind_password 脱敏）
pub fn auth_settings_public(s: &AuthSettings) -> serde_json::Value {
    let mut v = serde_json::to_value(s).unwrap_or(serde_json::Value::Null);
    if let Some(ldap) = v.get_mut("ldap").and_then(|x| x.as_object_mut()) {
        ldap.insert(
            "bind_password".to_string(),
            serde_json::Value::String(if s.ldap.bind_password.is_empty() {
                String::new()
            } else {
                "******".to_string()
            }),
        );
    }
    v
}

/// 原子写入：先写 tmp 再 rename，保证管理端每次变更落盘不产生半截文件。
pub fn save_atomic(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, content).map_err(|e| e.to_string())?;
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// 管理端配置（admin.yaml）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConf {
    pub username: String,
    /// argon2id PHC 字符串
    pub password_hash: String,
    pub jwt_secret: String,
    #[serde(default = "default_ttl")]
    pub jwt_ttl_hours: u64,
}

fn default_ttl() -> u64 {
    12
}

impl AdminConf {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let conf: AdminConf = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
        Ok(conf)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_yaml::to_string(self).map_err(|e| e.to_string())?;
        save_atomic(path, &text)
    }

    pub fn generate_password_hash(password: &str) -> Result<String, String> {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    pub fn generate_secret(len: usize) -> String {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf.iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// 运行时共享状态
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LogLine {
    pub slug: String,
    pub line: String,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<AppConfig>>,
    pub admin: Arc<AdminConf>,
    pub sites_file: PathBuf,
    pub log_dir: PathBuf,
    pub audit: Arc<AuditLog>,
    pub log_tx: tokio::sync::mpsc::Sender<LogLine>,
    /// 保护“改内存 + 落盘”组合操作的串行锁
    pub mutate_lock: Arc<Mutex<()>>,
    /// 零信任认证运行时状态（P1：本地用户 + 会话 + 站点 ACL）
    pub auth: Arc<crate::auth::AuthState>,
}

impl AppState {
    pub fn new(
        admin: AdminConf,
        config: AppConfig,
        main_conf: &MainConf,
        audit: Arc<AuditLog>,
        log_tx: tokio::sync::mpsc::Sender<LogLine>,
        auth: Arc<crate::auth::AuthState>,
    ) -> Self {
        Self {
            config: ArcSwap::from_pointee(config).into(),
            admin: Arc::new(admin),
            sites_file: main_conf.sites_path(),
            log_dir: main_conf.log_dir(),
            audit,
            log_tx,
            mutate_lock: Arc::new(Mutex::new(())),
            auth,
        }
    }

    pub fn load_config(&self) -> std::sync::Arc<AppConfig> {
        self.config.load().clone()
    }

    pub fn store_config(&self, cfg: AppConfig) {
        self.config.store(Arc::new(cfg));
    }

    /// 在锁内完成“基于当前快照的变更 → 原子落盘 → ArcSwap 热切换”，
    /// 管理端每次 UI 变更都走这里，保证内存与文件一致。
    pub fn with_mutated_config<F: FnOnce(&mut AppConfig) -> Result<(), String>>(
        &self,
        f: F,
    ) -> Result<AppConfig, String> {
        let _guard = self.mutate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut next: AppConfig = (**self.config.load()).clone();
        f(&mut next)?;
        let yaml = serde_yaml::to_string(&next).map_err(|e| e.to_string())?;
        save_atomic(&self.sites_file, &yaml)?;
        self.config.store(Arc::new(next.clone()));
        Ok(next)
    }
}

// ---------------------------------------------------------------------------
// 操作审计日志（JSONL）
// ---------------------------------------------------------------------------

pub struct AuditLog {
    path: PathBuf,
    guard: Mutex<()>,
}

impl AuditLog {
    pub fn open(path: PathBuf) -> Arc<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Arc::new(Self {
            path,
            guard: Mutex::new(()),
        })
    }

    pub fn record(
        &self,
        user: &str,
        action: &str,
        target: &str,
        detail: &str,
        ip: &str,
    ) {
        let entry = serde_json::json!({
            "ts": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            "user": user,
            "action": action,
            "target": target,
            "detail": detail,
            "ip": ip,
        });
        let _guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        else {
            return;
        };
        let _ = writeln!(f, "{}", entry);
    }

    pub fn tail(&self, limit: usize) -> Vec<serde_json::Value> {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(limit)
            .collect()
    }
}

#[cfg(test)]
mod conf_tests {
    use super::*;

    #[test]
    fn nokey_defaults_probe() {
        let dir = std::env::temp_dir().join(format!("vsp_conf_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("c.yaml");
        std::fs::write(&f, "proxy_listen: \"127.0.0.1:19960\"\nadmin_listen: \"127.0.0.1:19961\"\n")
            .unwrap();
        let c = MainConf::load(&f).unwrap();
        eprintln!(
            "NOKEY PROBE: auth_db={:?} auth_file={:?} sites={:?} log_dir={:?}",
            c.auth_db, c.auth_file, c.sites_file, c.log_dir
        );
        assert_eq!(c.auth_db, "/opt/ventositeproxy/auth.db");
        assert_eq!(c.auth_file, "/opt/ventositeproxy/auth.yaml");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
