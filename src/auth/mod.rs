//! 零信任认证模块
//!
//! - P1：本地用户（argon2id）+ 内存会话 + 站点级 ACL + 登录限流
//! - P2：LDAP 用户来源（Turing / IIIS / Global 组，反向搜索成员关系）
//! - P3：MFA（TOTP + passkey，移动端指纹/面容），首登强制绑定
//!
//! 数据面：`auth.yaml`（配置，热加载，chmod 600）+ `auth.db`（SQLite 用户库）
//! + `logs/auth.jsonl`（登录/访问审计，复用 AuditLog 模式）。
//!
//! 会话仅存内存：重启 / `--upgrade` 后全部失效（设计文档 §6.4，已确认接受）。

pub mod api;
pub mod gate;
pub mod identity;
pub mod ldap;
pub mod page;
pub mod ratelimit;
pub mod session;
pub mod store;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::{self, AuditLog, AuthFileConf, AuthSettings};

/// 认证模块运行时句柄（代理侧 / 管理端 / 后台服务共享）
pub struct AuthState {
    /// auth.yaml 的 `auth:` 段（ArcSwap 热切换，读侧无锁）
    pub settings: ArcSwap<AuthSettings>,
    pub auth_file: PathBuf,
    /// SQLite + 用户内存快照
    pub store: store::UserStore,
    /// 内存会话（token → SessionEntry）
    pub sessions: session::SessionStore,
    /// 按 IP 的登录限流
    pub ratelimit: ratelimit::RateLimiter,
    /// 登录/访问审计 logs/auth.jsonl
    pub audit: Arc<AuditLog>,
    /// LDAP 用户缓存（TTL，P2 持续评估 + stale 降级）
    pub ldap_cache: ldap::LdapCache,
}

impl AuthState {
    /// 打开 auth.db（建表）、加载 auth.yaml。
    /// auth.yaml 缺失 → 默认配置（认证关闭）；解析失败 → warn + 默认（绝不拖垮代理）。
    pub fn new(auth_file: &Path, db_path: &Path, log_dir: &Path) -> Result<Arc<Self>, String> {
        let conf = match config::load_auth_config(auth_file) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("加载认证配置 {} 失败，使用默认配置（认证关闭）: {e}", auth_file.display());
                AuthFileConf::default()
            }
        };
        let store = store::UserStore::open(db_path)?;
        log::info!(
            "认证模块就绪: auth.db 本地用户 {} 个 / LDAP 覆盖 {} 个",
            store.local_count(),
            store.override_count()
        );
        Ok(Arc::new(Self {
            settings: ArcSwap::from_pointee(conf.auth),
            auth_file: auth_file.to_path_buf(),
            store,
            sessions: session::SessionStore::new(),
            ratelimit: ratelimit::RateLimiter::default(),
            audit: AuditLog::open(log_dir.join("auth.jsonl")),
            ldap_cache: ldap::LdapCache::default(),
        }))
    }

    /// 当前认证配置（Arc 快照，无锁）
    pub fn settings(&self) -> Arc<AuthSettings> {
        self.settings.load_full()
    }

    /// 热加载 auth.yaml（watcher 调用）；解析失败保留旧配置
    pub fn reload_settings(&self) {
        match config::load_auth_config(&self.auth_file) {
            Ok(c) => {
                self.ratelimit.set_params(c.auth.ratelimit.clone());
                self.settings.store(Arc::new(c.auth));
            }
            Err(e) => {
                log::error!("重载认证配置失败，保留旧配置: {e}");
            }
        }
    }

    /// 持久化认证配置（原子写 + chmod 600 + 内存热切换）
    pub fn save_settings(&self, next: AuthSettings) -> Result<(), String> {
        let file = AuthFileConf { version: 1, auth: next.clone() };
        let text = serde_yaml::to_string(&file).map_err(|e| format!("序列化认证配置失败: {e}"))?;
        config::save_atomic(&self.auth_file, &text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.auth_file, std::fs::Permissions::from_mode(0o600));
        }
        self.ratelimit.set_params(next.ratelimit.clone());
        self.settings.store(Arc::new(next));
        Ok(())
    }
}
