//! LDAP 实环境探测（P2 验证用，非部署产物）
//!
//! 直接编译进 `src/config.rs` 与 `src/auth/ldap.rs` 的生产代码，
//! 对真实目录（默认 192.168.209.101:389）执行：
//!   1. `test_connection`：服务绑定 + 用户枚举 + 首个用户组反查
//!   2. （可选）`login_ldap`：用户绑定全链路（服务绑定→用户搜索→用户绑定→组反查→写缓存）
//!
//! 用法：
//!   # 仅连接测试（密码从 /tmp/.vsp_ldap_pw 读取）
//!   cargo run --release --example ldap_probe
//!   # 附带用户绑定探测
//!   cargo run --release --example ldap_probe -- <username> <password>
//!
//! 注意：本文件为临时验证脚本，P2 验收完成后可删除。

#[path = "../src/config.rs"]
mod config;

// config.rs 的 AppState 引用 crate::auth::AuthState；probe 不需要真实实现
mod auth {
    pub struct AuthState;
}

// ldap.rs 中 sync_users 的签名引用 super::store::UserStore；直接引入真实 store 模块
#[path = "../src/auth/store.rs"]
mod store;

#[path = "../src/auth/ldap.rs"]
mod ldap;

#[tokio::main]
async fn main() {
    env_logger::init();
    let pw = std::fs::read_to_string("/tmp/.vsp_ldap_pw")
        .expect("读不到 /tmp/.vsp_ldap_pw（LDAP 服务账号密码，600）");
    let mut s = config::LdapSettings::default();
    s.bind_password = pw.trim().to_string();

    println!("目标: {}  服务账号: {}", s.uri, s.bind_dn);

    println!("\n== 1/2 连接测试（服务绑定 + 用户枚举 + 组反查）");
    match ldap::test_connection(&s).await {
        Ok(r) => {
            println!("  OK  延迟={}ms  用户数={}", r.latency_ms, r.user_count);
            if let Some(sm) = &r.sample {
                println!("  示例用户: {}  dn={}", sm.username, sm.dn);
                println!("  显示名: {}   组: {:?}", sm.display_name, sm.groups);
            } else {
                println!("  （基下无用户）");
            }
        }
        Err(e) => {
            eprintln!("  FAIL: {e}");
            std::process::exit(1);
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 {
        let (u, p) = (args[1].as_str(), args[2].as_str());
        println!("\n== 2/2 用户绑定探测: {u}");
        let cache = ldap::LdapCache::default();
        match ldap::login_ldap(&cache, &s, u, p).await {
            Ok(Some(user)) => {
                println!("  OK  dn={}", user.dn);
                println!("  显示名: {}   组: {:?}", user.display_name, user.groups);
            }
            Ok(None) => println!("  用户不存在（UserNotFound，登录链会继续下一个 provider）"),
            Err(e) => {
                println!("  FAIL: {e}");
                std::process::exit(2);
            }
        }
    }
}
