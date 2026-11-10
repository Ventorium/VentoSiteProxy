//! VentoSiteProxy — 基于 Pingora 的反代网关
//!
//! 子命令：
//!   run          启动（默认），代理 + 管理端 + 后台服务
//!   init         生成 admin.yaml（随机密码 + JWT 密钥）
//!   set-password 修改管理员密码
//!   migrate      从 NPM 的 database.sqlite 迁移出 sites.yaml

mod accesslog;
mod admin;
mod auth;
mod config;
mod defaultpage;
mod glob;
mod logcleanup;
mod migrate;
mod proxy;
mod routes;
mod tcp;

use std::path::Path;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use auth::AuthState;
use config::{AdminConf, AppState, AuditLog, MainConf};

#[derive(Parser)]
#[command(name = "ventositeproxy", version, about = "VentoSiteProxy — Pingora 反向代理网关")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动代理（默认子命令）
    Run {
        /// 主配置文件
        #[arg(short, long, default_value = "ventsitemproxy.yaml")]
        config: String,
        /// 升级模式：接管旧进程持有的 socket（零停机发布）
        #[arg(long)]
        upgrade: bool,
    },
    /// 生成 admin.yaml（随机管理员密码 + JWT 密钥）
    Init {
        /// 输出文件
        #[arg(short, long, default_value = "admin.yaml")]
        file: String,
        /// 管理员用户名
        #[arg(long, default_value = "admin")]
        user: String,
        /// 指定密码（默认随机生成并打印）
        #[arg(long)]
        password: Option<String>,
    },
    /// 修改管理员密码
    SetPassword {
        /// admin.yaml 路径
        #[arg(short, long, default_value = "admin.yaml")]
        file: String,
        /// 新密码（缺省时交互式输入）
        #[arg(long)]
        password: Option<String>,
        /// 管理员用户名
        #[arg(short, long, default_value = "admin")]
        user: String,
    },
    /// 从 NPM 数据库迁移到 sites.yaml
    Migrate {
        /// NPM 的 database.sqlite
        #[arg(short, long)]
        db: String,
        /// 输出 sites.yaml 路径
        #[arg(short, long, default_value = "sites.yaml")]
        out: String,
        /// 仅迁移启用的站点
        #[arg(long)]
        enabled_only: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        None => run_upgrade(&Cli::default_config(), false),
        Some(Cmd::Run { config, upgrade }) => run_upgrade(&config, upgrade),
        Some(Cmd::Init { file, user, password }) => cmd_init(&file, &user, password),
        Some(Cmd::SetPassword { file, password, user }) => cmd_set_password(&file, password, &user),
        Some(Cmd::Migrate { db, out, enabled_only }) => migrate::run(&db, &out, enabled_only),
    }
}

impl Cli {
    fn default_config() -> String {
        "ventsitemproxy.yaml".to_string()
    }
}

// ---------------------------------------------------------------------------
// init / set-password
// ---------------------------------------------------------------------------

fn gen_password(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn cmd_init(file: &str, user: &str, password: Option<String>) {
    if Path::new(file).exists() {
        eprintln!("{} 已存在，拒绝覆盖（如需重置请手动删除后重新 init）", file);
        std::process::exit(1);
    }
    let password = password.unwrap_or_else(|| gen_password(24));
    let hash = AdminConf::generate_password_hash(&password)
        .unwrap_or_else(|e| panic!("生成密码哈希失败: {e}"));
    let admin = AdminConf {
        username: user.to_string(),
        password_hash: hash,
        jwt_secret: AdminConf::generate_secret(32),
        jwt_ttl_hours: 12,
    };
    admin
        .save(Path::new(file))
        .unwrap_or_else(|e| panic!("写入 {file} 失败: {e}"));
    println!("已生成 {file}");
    println!("  用户名: {user}");
    println!("  密码:   {password}");
    println!("请妥善保存，之后可用 `ventositeproxy set-password` 修改。");
}

fn cmd_set_password(file: &str, password: Option<String>, user: &str) {
    let mut admin = AdminConf::load(Path::new(file))
        .unwrap_or_else(|e| panic!("读取 {file} 失败: {e}"));
    let password = password.unwrap_or_else(|| {
        use std::io::Write;
        print!("输入新密码: ");
        let _ = std::io::stdout().flush();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).expect("读取密码失败");
        s.trim().to_string()
    });
    if password.len() < 8 {
        eprintln!("密码长度至少 8 位");
        std::process::exit(1);
    }
    admin.username = user.to_string();
    admin.password_hash =
        AdminConf::generate_password_hash(&password).unwrap_or_else(|e| panic!("{e}"));
    admin
        .save(Path::new(file))
        .unwrap_or_else(|e| panic!("写入 {file} 失败: {e}"));
    println!("密码已更新（{file}）");
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn run_upgrade(config_path: &str, upgrade: bool) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mc = MainConf::load(Path::new(config_path))
        .unwrap_or_else(|e| panic!("加载主配置失败: {e}"));
    if upgrade {
        log::info!("升级模式：将接管旧进程的 socket FD");
    }

    // admin.yaml 缺失时自动生成（密码打印到日志，可用 set-password 修改）
    let admin_path = mc.admin_path();
    let admin = if admin_path.exists() {
        AdminConf::load(&admin_path).unwrap_or_else(|e| panic!("加载 admin.yaml 失败: {e}"))
    } else {
        let pw = gen_password(24);
        let hash = AdminConf::generate_password_hash(&pw)
            .unwrap_or_else(|e| panic!("生成密码哈希失败: {e}"));
        let a = AdminConf {
            username: "admin".into(),
            password_hash: hash,
            jwt_secret: AdminConf::generate_secret(32),
            jwt_ttl_hours: 12,
        };
        a.save(&admin_path).unwrap_or_else(|e| panic!("写入 admin.yaml 失败: {e}"));
        log::info!("已自动生成 {} —— 管理员用户: admin, 密码: {pw}（请尽快用 set-password 修改）", admin_path.display());
        a
    };

    let app_cfg = config::load_app_config(&mc.sites_path())
        .unwrap_or_else(|e| panic!("加载 {} 失败: {e}", mc.sites_path().display()));
    log::info!(
        "配置加载完成: {} 个站点, {} 个数据流",
        app_cfg.sites.len(),
        app_cfg.streams.len()
    );

    let _ = std::fs::create_dir_all(mc.access_log_dir());
    let audit = AuditLog::open(mc.audit_path());
    let (log_tx, log_rx) = tokio::sync::mpsc::channel::<config::LogLine>(4096);

    // 零信任认证模块：auth.yaml 缺失 → 默认关闭；auth.db 打开失败 → 终止启动
    let auth = AuthState::new(&mc.auth_path(), &mc.auth_db_path(), &mc.log_dir())
        .unwrap_or_else(|e| panic!("初始化认证模块失败: {e}"));
    if auth.settings().enabled {
        log::info!("零信任认证: 已启用（providers: {:?}）", auth.settings().providers_order);
    } else {
        log::info!("零信任认证: 未启用（auth.yaml 缺失或 enabled=false），行为与旧版一致");
    }

    let state = Arc::new(AppState::new(
        admin,
        app_cfg,
        &mc,
        audit,
        log_tx,
        auth.clone(),
    ));

    // 程序化构造 ServerConf（不从命令行解析，避免与 clap 冲突）
    let mut conf = pingora::server::configuration::ServerConf::default();
    conf.daemon = false;
    conf.threads = mc.threads as usize;
    conf.grace_period_seconds = Some(mc.grace_period_seconds);
    conf.upgrade_sock = mc.upgrade_sock.clone();
    conf.pid_file = mc.pid_file.clone();
    if let Some(e) = &mc.error_log {
        conf.error_log = Some(e.clone());
    }

    let opt = pingora::prelude::Opt {
        upgrade,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    };
    let mut server = pingora::prelude::Server::new_with_opt_and_conf(Some(opt), conf);
    server.bootstrap();

    // 代理服务
    let mut proxy_svc = pingora::proxy::http_proxy_service(
        &server.configuration,
        proxy::ProxyHandler { state: state.clone() },
    );
    proxy_svc.add_tcp(&mc.proxy_listen);
    server.add_service(proxy_svc);
    log::info!("代理服务监听 {}", mc.proxy_listen);

    // 管理端（独立服务，永不走上游）
    let mut admin_svc = pingora::proxy::http_proxy_service_with_name(
        &server.configuration,
        admin::AdminGw { state: state.clone() },
        "vsp-admin",
    );
    admin_svc.add_tcp(&mc.admin_listen);
    server.add_service(admin_svc);
    log::info!("管理端监听 {}", mc.admin_listen);

    // 后台服务
    server.add_service(pingora::prelude::background_service(
        "vsp-tcp-relay",
        tcp::TcpRelaySupervisor { state: state.clone() },
    ));
    server.add_service(pingora::prelude::background_service(
        "vsp-accesslog",
        accesslog::AccessLogWriter { state: state.clone(), rx: std::sync::Mutex::new(log_rx) },
    ));
    server.add_service(pingora::prelude::background_service(
        "vsp-log-cleanup",
        logcleanup::LogCleanupService { state: state.clone() },
    ));
    server.add_service(pingora::prelude::background_service(
        "vsp-config-watch",
        ConfigWatcher { state: state.clone(), path: mc.sites_path() },
    ));
    server.add_service(pingora::prelude::background_service(
        "vsp-auth-watch",
        AuthConfigWatcher { state: state.clone(), path: mc.auth_path() },
    ));
    server.add_service(pingora::prelude::background_service(
        "vsp-auth-evaluator",
        AuthEvaluator { state: state.clone() },
    ));

    log::info!("VentoSiteProxy 启动完成");
    server.run_forever();
}

/// 文件监听：sites.yaml 被外部修改（mtime 变化）时热重载；解析失败保留旧配置。
struct ConfigWatcher {
    state: Arc<AppState>,
    path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for ConfigWatcher {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut last = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
            }
            let mtime = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if Some(mtime) == last {
                continue;
            }
            last = Some(mtime);
            match config::load_app_config(&self.path) {
                Ok(cfg) => {
                    log::info!(
                        "检测到 {} 变更，热重载: {} 站点 / {} 数据流",
                        self.path.display(),
                        cfg.sites.len(),
                        cfg.streams.len()
                    );
                    self.state.store_config(cfg);
                }
                Err(e) => log::error!("重载 {} 失败，保留旧配置: {e}", self.path.display()),
            }
        }
        log::info!("配置监听服务退出");
    }
}

/// 认证配置监听：auth.yaml 被外部修改（mtime 变化）时热重载；解析失败保留旧配置。
struct AuthConfigWatcher {
    state: Arc<AppState>,
    path: std::path::PathBuf,
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for AuthConfigWatcher {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut last = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
            }
            let mtime = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if Some(mtime) == last {
                continue;
            }
            last = Some(mtime);
            log::info!("检测到 {} 变更，重载认证配置", self.path.display());
            self.state.auth.reload_settings();
        }
        log::info!("认证配置监听服务退出");
    }
}

/// 认证会话评估器：每 60s 清理过期会话、修剪限流表。
struct AuthEvaluator {
    state: Arc<AppState>,
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for AuthEvaluator {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
            }
            let s = self.state.auth.settings();
            let n = self
                .state
                .auth
                .sessions
                .evict_expired(s.session.idle_timeout_secs as i64, s.session.absolute_timeout_secs as i64);
            if n > 0 {
                log::info!("认证评估器: 清理 {n} 个过期会话");
            }
            self.state.auth.ratelimit.prune();
            self.state.auth.mfa.sweep();
            ldap_reverify(&self.state).await;
        }
        log::info!("认证会话评估器服务退出");
    }
}

/// P2 持续评估：对缓存已过期的 LDAP 会话用户做在线复核（每轮 ≤1 次 LDAP 连接/用户）。
/// - 复核成功 → 刷新缓存，会话保留
/// - 用户已从 LDAP 删除（UserNotFound）→ 撤销其全部会话
/// - 网络/服务端故障 + `fail_mode=stale` 且仍有旧缓存 → 保留会话
/// - 其余故障 → 撤销会话（deny）
async fn ldap_reverify(state: &AppState) {
    let auth = &state.auth;
    let s = auth.settings();
    if !s.providers_order.iter().any(|p| p == "ldap") || s.ldap.bind_password.is_empty() {
        return;
    }
    let ttl = s.ldap.cache_ttl_secs.max(1);
    let mut pending: Vec<String> = Vec::new();
    for info in auth.sessions.list() {
        if info.source != "ldap" {
            continue;
        }
        if auth.ldap_cache.get(&info.username, ttl).is_some() {
            continue;
        }
        if !pending.iter().any(|u| u == &info.username) {
            pending.push(info.username);
        }
    }
    for username in pending {
        match auth::ldap::refresh_ldap(&auth.ldap_cache, &s.ldap, &username).await {
            Ok(auth::ldap::RefreshOutcome::Found(_)) => {}
            Ok(auth::ldap::RefreshOutcome::UserNotFound) => {
                let n = auth.sessions.revoke_user(&username);
                log::warn!("LDAP 复核: 用户 {username} 已从目录删除，撤销 {n} 个会话");
                auth.audit
                    .record(&username, "session_revoked_ldap", "auth", "LDAP 用户已删除，会话被撤销", "-");
            }
            Err(e) => {
                if s.ldap.fail_mode == "stale" && auth.ldap_cache.get_stale(&username).is_some() {
                    log::error!("LDAP 复核失败({username})，fail_mode=stale 保留现有会话: {e}");
                    continue;
                }
                let n = auth.sessions.revoke_user(&username);
                log::error!("LDAP 复核失败({username}, fail_mode={})，撤销 {n} 个会话: {e}", s.ldap.fail_mode);
                auth.audit
                    .record(&username, "session_revoked_ldap", "auth", &format!("LDAP 复核失败: {e}"), "-");
            }
        }
    }
}
