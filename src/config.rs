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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: 0,
            sites: Vec::new(),
            streams: Vec::new(),
            default_404: DEFAULT_404_STATUS.into(),
            custom_404_dir: "custom404".into(),
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
}

impl AppState {
    pub fn new(
        admin: AdminConf,
        config: AppConfig,
        main_conf: &MainConf,
        audit: Arc<AuditLog>,
        log_tx: tokio::sync::mpsc::Sender<LogLine>,
    ) -> Self {
        Self {
            config: ArcSwap::from_pointee(config).into(),
            admin: Arc::new(admin),
            sites_file: main_conf.sites_path(),
            log_dir: main_conf.log_dir(),
            audit,
            log_tx,
            mutate_lock: Arc::new(Mutex::new(())),
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
