//! 用户存储：SQLite（rusqlite bundled，WAL）+ ArcSwap 内存快照。
//!
//! 表：
//! - `auth_users`           本地用户（argon2id PHC）
//! - `auth_ldap_overrides`  LDAP 用户覆盖（P2：显示名/启用/MFA/附加组）
//! - `auth_passkeys`        WebAuthn passkey（P3）
//!
//! 单写者模型：写操作持有连接互斥锁，完成后全量重建内存快照；
//! 读操作只走快照，热路径不碰数据库。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

/// 本地用户
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalUser {
    pub username: String,
    pub display_name: String,
    /// argon2id PHC（不外泄）
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub groups: Vec<String>,
    pub enabled: bool,
    pub mfa_required: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// LDAP 用户覆盖（P2）：None 字段 = 不覆盖
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdapOverride {
    pub username: String,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub mfa_required: Option<bool>,
    pub extra_groups: Vec<String>,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub updated_at: i64,
}

/// passkey（P3）
#[derive(Debug, Clone)]
pub struct Passkey {
    pub credential_id: String,
    pub username: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub rp_id: String,
    pub sign_count: i64,
    pub created_at: i64,
}

/// 内存快照（每次写后全量重建）
#[derive(Default)]
pub struct Snapshot {
    pub users: HashMap<String, LocalUser>,
    pub overrides: HashMap<String, LdapOverride>,
    pub passkeys: HashMap<String, Vec<Passkey>>,
    pub all_groups: HashSet<String>,
}

pub struct UserStore {
    conn: Mutex<Connection>,
    snapshot: ArcSwap<Snapshot>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS auth_users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    groups        TEXT NOT NULL DEFAULT '[]',
    enabled       INTEGER NOT NULL DEFAULT 1,
    mfa_required  INTEGER NOT NULL DEFAULT 0,
    totp_secret   TEXT,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_ldap_overrides (
    username     TEXT PRIMARY KEY,
    display_name TEXT,
    enabled      INTEGER,
    mfa_required INTEGER,
    extra_groups TEXT NOT NULL DEFAULT '[]',
    totp_secret  TEXT,
    updated_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_passkeys (
    credential_id TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    public_key    BLOB NOT NULL,
    rp_id         TEXT NOT NULL DEFAULT '',
    sign_count    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_passkeys_username ON auth_passkeys(username);
"#;

impl UserStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        // 防御：空路径在 SQLite 中会被当作内存库静默打开（数据不落盘，重启即丢）
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(format!(
                "auth.db 路径无效: {:?} —— 必须为非空文件路径，请检查主配置 auth_db 项",
                path.display()
            ));
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("创建目录 {} 失败: {e}", dir.display()))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("打开 {path:?} 失败: {e}"))?;
        conn.execute_batch(SCHEMA).map_err(|e| format!("初始化 auth.db 表结构失败: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("设置 WAL 模式失败: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let this = Self { conn: Mutex::new(conn), snapshot: ArcSwap::from_pointee(Snapshot::default()) };
        this.rebuild();
        Ok(this)
    }

    // ---- 读（快照，无 DB 锁）----

    /// 全量快照；P3/管理端接线用
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    pub fn local_user(&self, username: &str) -> Option<LocalUser> {
        self.snapshot.load().users.get(username).cloned()
    }

    pub fn all_local_users(&self) -> Vec<LocalUser> {
        let mut v: Vec<LocalUser> = self.snapshot.load().users.values().cloned().collect();
        v.sort_by(|a, b| a.username.cmp(&b.username));
        v
    }

    pub fn all_overrides(&self) -> Vec<LdapOverride> {
        let mut v: Vec<LdapOverride> = self.snapshot.load().overrides.values().cloned().collect();
        v.sort_by(|a, b| a.username.cmp(&b.username));
        v
    }

    pub fn ldap_override(&self, username: &str) -> Option<LdapOverride> {
        self.snapshot.load().overrides.get(username).cloned()
    }

    pub fn all_groups(&self) -> Vec<String> {
        let mut v: Vec<String> = self.snapshot.load().all_groups.iter().cloned().collect();
        v.sort();
        v
    }

    pub fn passkey_count(&self, username: &str) -> usize {
        self.snapshot.load().passkeys.get(username).map(|v| v.len()).unwrap_or(0)
    }

    /// 列出用户全部 passkey（快照，按创建时间升序）
    pub fn list_passkeys(&self, username: &str) -> Vec<Passkey> {
        let mut v = self.snapshot.load().passkeys.get(username).cloned().unwrap_or_default();
        v.sort_by_key(|p| p.created_at);
        v
    }

    /// 按 credential_id 查找用户的单个 passkey（快照）
    pub fn find_passkey(&self, username: &str, credential_id: &str) -> Option<Passkey> {
        self.snapshot.load().passkeys.get(username)?.iter().find(|p| p.credential_id == credential_id).cloned()
    }

    pub fn local_count(&self) -> usize {
        self.snapshot.load().users.len()
    }

    pub fn override_count(&self) -> usize {
        self.snapshot.load().overrides.len()
    }

    // ---- 写（持锁 + 重建快照）----

    pub fn create_local_user(
        &self,
        username: &str,
        display_name: &str,
        password_hash: &str,
        groups: &[String],
        mfa_required: bool,
    ) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let groups_json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".to_string());
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO auth_users
               (username, display_name, password_hash, groups, enabled, mfa_required, totp_secret, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL, ?6, ?6)",
            params![username, display_name, password_hash, groups_json, mfa_required as i64, now],
        )
        .map_err(|e| format!("创建用户失败（用户名可能已存在）: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 更新本地用户；None 字段保持不变。用户不存在 → Err。
    pub fn update_local_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        groups: Option<&[String]>,
        enabled: Option<bool>,
        mfa_required: Option<bool>,
    ) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        let (cur_dn, cur_groups, cur_enabled, cur_mfa): (String, Vec<String>, i64, i64) = conn
            .query_row(
                "SELECT display_name, groups, enabled, mfa_required FROM auth_users WHERE username = ?1",
                params![username],
                |r| {
                    Ok((
                        r.get(0)?,
                        serde_json::from_str(r.get::<_, String>(1)?.as_str()).unwrap_or_default(),
                        r.get(2)?,
                        r.get(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("查询用户失败: {e}"))?
            .ok_or_else(|| format!("用户 {username} 不存在"))?;
        let dn = display_name.map(|s| s.to_string()).unwrap_or(cur_dn);
        let gs = groups.map(|g| g.to_vec()).unwrap_or(cur_groups);
        let en = enabled.unwrap_or(cur_enabled != 0) as i64;
        let mf = mfa_required.unwrap_or(cur_mfa != 0) as i64;
        let groups_json = serde_json::to_string(&gs).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "UPDATE auth_users
              SET display_name = ?2, groups = ?3, enabled = ?4, mfa_required = ?5, updated_at = ?6
            WHERE username = ?1",
            params![username, dn, groups_json, en, mf, now],
        )
        .map_err(|e| format!("更新用户失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    pub fn delete_local_user(&self, username: &str) -> Result<(), String> {
        let conn = self.lock_conn();
        let n = conn
            .execute("DELETE FROM auth_users WHERE username = ?1", params![username])
            .map_err(|e| format!("删除用户失败: {e}"))?;
        if n == 0 {
            return Err(format!("用户 {username} 不存在"));
        }
        // 连带清理 passkey（P3）
        let _ = conn.execute("DELETE FROM auth_passkeys WHERE username = ?1", params![username]);
        self.rebuild_with(&conn);
        Ok(())
    }

    pub fn set_local_password(&self, username: &str, password_hash: &str) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        let n = conn
            .execute(
                "UPDATE auth_users SET password_hash = ?2, updated_at = ?3 WHERE username = ?1",
                params![username, password_hash, now],
            )
            .map_err(|e| format!("重置密码失败: {e}"))?;
        if n == 0 {
            return Err(format!("用户 {username} 不存在"));
        }
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 设置/解绑本地用户 TOTP secret（None = 解绑）
    pub fn set_local_totp(&self, username: &str, secret: Option<&str>) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        let n = conn
            .execute(
                "UPDATE auth_users SET totp_secret = ?2, updated_at = ?3 WHERE username = ?1",
                params![username, secret, now],
            )
            .map_err(|e| format!("更新 TOTP 失败: {e}"))?;
        if n == 0 {
            return Err(format!("用户 {username} 不存在"));
        }
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 保存 LDAP 覆盖（P2 管理端接线）；None 字段 = 清除该覆盖项
    #[allow(dead_code)]
    pub fn upsert_ldap_override(
        &self,
        username: &str,
        display_name: Option<String>,
        enabled: Option<bool>,
        mfa_required: Option<bool>,
        extra_groups: &[String],
    ) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let groups_json = serde_json::to_string(extra_groups).unwrap_or_else(|_| "[]".to_string());
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO auth_ldap_overrides
               (username, display_name, enabled, mfa_required, extra_groups, totp_secret, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)
             ON CONFLICT(username) DO UPDATE SET
               display_name = excluded.display_name,
               enabled = excluded.enabled,
               mfa_required = excluded.mfa_required,
               extra_groups = excluded.extra_groups,
               updated_at = excluded.updated_at",
            params![
                username,
                display_name,
                enabled.map(|b| b as i64),
                mfa_required.map(|b| b as i64),
                groups_json,
                now
            ],
        )
        .map_err(|e| format!("保存 LDAP 覆盖失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 删除 LDAP 覆盖（P2 管理端接线）
    #[allow(dead_code)]
    pub fn delete_ldap_override(&self, username: &str) -> Result<(), String> {
        let conn = self.lock_conn();
        let _ = conn
            .execute("DELETE FROM auth_ldap_overrides WHERE username = ?1", params![username])
            .map_err(|e| format!("清除 LDAP 覆盖失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 设置/解绑 LDAP 覆盖的 TOTP secret（P3；None = 解绑）。
    /// 覆盖行不存在时自动创建一条仅含 totp_secret 的默认行（其余覆盖项保持未设置）。
    pub fn set_ldap_totp(&self, username: &str, secret: Option<&str>) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO auth_ldap_overrides
               (username, display_name, enabled, mfa_required, extra_groups, totp_secret, updated_at)
             VALUES (?1, NULL, NULL, NULL, '[]', ?2, ?3)
             ON CONFLICT(username) DO UPDATE SET
               totp_secret = excluded.totp_secret,
               updated_at = excluded.updated_at",
            params![username, secret, now],
        )
        .map_err(|e| format!("更新 LDAP TOTP 失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 仅更新 LDAP 覆盖的 mfa_required 列（P3：最后凭据删除后自动关闭强制 MFA）。
    /// 不触碰其他覆盖项；覆盖行不存在时自动创建一条仅含 mfa_required 的默认行。
    pub fn set_ldap_mfa_required(&self, username: &str, v: bool) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO auth_ldap_overrides
                (username, display_name, enabled, mfa_required, extra_groups, totp_secret, updated_at)
              VALUES (?1, NULL, NULL, ?2, '[]', NULL, ?3)
              ON CONFLICT(username) DO UPDATE SET
                mfa_required = excluded.mfa_required,
                updated_at = excluded.updated_at",
            params![username, v as i64, now],
        )
        .map_err(|e| format!("保存 LDAP 覆盖失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 保存 passkey（P3）；`public_key` 存 webauthn-rs `Passkey` 的 JSON 序列化
    pub fn add_passkey(
        &self,
        username: &str,
        credential_id: &str,
        name: &str,
        public_key: &[u8],
        rp_id: &str,
    ) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO auth_passkeys (credential_id, username, name, public_key, rp_id, sign_count, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![credential_id, username, name, public_key, rp_id, now],
        )
        .map_err(|e| format!("保存 passkey 失败: {e}"))?;
        self.rebuild_with(&conn);
        Ok(())
    }

    /// 删除 passkey（P3）；返回是否还存在该用户其他 passkey
    pub fn delete_passkey(&self, username: &str, credential_id: &str) -> Result<bool, String> {
        let conn = self.lock_conn();
        let n = conn
            .execute(
                "DELETE FROM auth_passkeys WHERE credential_id = ?1 AND username = ?2",
                params![credential_id, username],
            )
            .map_err(|e| format!("删除 passkey 失败: {e}"))?;
        if n == 0 {
            return Err(format!("passkey 不存在"));
        }
        self.rebuild_with(&conn);
        Ok(!self.snapshot.load().passkeys.get(username).map(|v| v.is_empty()).unwrap_or(true))
    }

    /// 更新已存 passkey（P3：认证通过后回写新 public_key 与计数器）
    pub fn update_passkey(
        &self,
        credential_id: &str,
        username: &str,
        public_key: &[u8],
        sign_count: i64,
    ) -> Result<(), String> {
        let conn = self.lock_conn();
        let n = conn
            .execute(
                "UPDATE auth_passkeys SET public_key = ?3, sign_count = ?4
                 WHERE credential_id = ?1 AND username = ?2",
                params![credential_id, username, public_key, sign_count],
            )
            .map_err(|e| format!("更新 passkey 失败: {e}"))?;
        if n == 0 {
            return Err(format!("passkey 不存在"));
        }
        self.rebuild_with(&conn);
        Ok(())
    }

    // ---- 内部 ----

    fn lock_conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn rebuild(&self) {
        let conn = self.lock_conn();
        self.rebuild_with(&conn);
    }

    fn rebuild_with(&self, conn: &Connection) {
        let mut snap = Snapshot::default();
        {
            let mut st = conn
                .prepare("SELECT username, display_name, password_hash, groups, enabled, mfa_required, totp_secret, created_at, updated_at FROM auth_users")
                .expect("prepare auth_users");
            let rows = st
                .query_map([], |r| {
                    Ok(LocalUser {
                        username: r.get(0)?,
                        display_name: r.get(1)?,
                        password_hash: r.get(2)?,
                        groups: serde_json::from_str(r.get::<_, String>(3)?.as_str()).unwrap_or_default(),
                        enabled: r.get::<_, i64>(4)? != 0,
                        mfa_required: r.get::<_, i64>(5)? != 0,
                        totp_secret: r.get(6)?,
                        created_at: r.get(7)?,
                        updated_at: r.get(8)?,
                    })
                })
                .expect("query auth_users");
            for row in rows.flatten() {
                for g in &row.groups {
                    snap.all_groups.insert(g.clone());
                }
                snap.users.insert(row.username.clone(), row);
            }
        }
        {
            let mut st = conn
                .prepare("SELECT username, display_name, enabled, mfa_required, extra_groups, totp_secret, updated_at FROM auth_ldap_overrides")
                .expect("prepare auth_ldap_overrides");
            let rows = st
                .query_map([], |r| {
                    Ok(LdapOverride {
                        username: r.get(0)?,
                        display_name: r.get(1)?,
                        enabled: r.get::<_, Option<i64>>(2)?.map(|v| v != 0),
                        mfa_required: r.get::<_, Option<i64>>(3)?.map(|v| v != 0),
                        extra_groups: serde_json::from_str(r.get::<_, String>(4)?.as_str()).unwrap_or_default(),
                        totp_secret: r.get(5)?,
                        updated_at: r.get(6)?,
                    })
                })
                .expect("query auth_ldap_overrides");
            for row in rows.flatten() {
                for g in &row.extra_groups {
                    snap.all_groups.insert(g.clone());
                }
                snap.overrides.insert(row.username.clone(), row);
            }
        }
        {
            let mut st = conn
                .prepare("SELECT credential_id, username, name, public_key, rp_id, sign_count, created_at FROM auth_passkeys")
                .expect("prepare auth_passkeys");
            let rows = st
                .query_map([], |r| {
                    Ok(Passkey {
                        credential_id: r.get(0)?,
                        username: r.get(1)?,
                        name: r.get(2)?,
                        public_key: r.get(3)?,
                        rp_id: r.get(4)?,
                        sign_count: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                })
                .expect("query auth_passkeys");
            for row in rows.flatten() {
                snap.passkeys.entry(row.username.clone()).or_default().push(row);
            }
        }
        self.snapshot.store(Arc::new(snap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vsp_auth_test_{name}_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn crud_roundtrip() {
        let p = tmp_db("crud");
        let s = UserStore::open(&p).unwrap();
        assert_eq!(s.local_count(), 0);

        s.create_local_user("alice", "Alice 爱丽丝", "$argon2id$xxx", &["Turing".to_string()], true)
            .unwrap();
        assert_eq!(s.local_count(), 1);
        let u = s.local_user("alice").unwrap();
        assert_eq!(u.display_name, "Alice 爱丽丝");
        assert_eq!(u.groups, vec!["Turing".to_string()]);
        assert!(u.mfa_required);
        assert!(u.enabled);

        // 重复创建失败
        assert!(s.create_local_user("alice", "", "", &[], false).is_err());

        // 局部更新（只改 display_name）
        s.update_local_user("alice", Some("A2"), None, Some(false), None).unwrap();
        let u = s.local_user("alice").unwrap();
        assert_eq!(u.display_name, "A2");
        assert!(!u.enabled);
        assert_eq!(u.groups, vec!["Turing".to_string()]);

        s.set_local_password("alice", "$argon2id$yyy").unwrap();
        assert_eq!(s.local_user("alice").unwrap().password_hash, "$argon2id$yyy");

        assert_eq!(s.all_groups(), vec!["Turing".to_string()]);

        s.delete_local_user("alice").unwrap();
        assert!(s.local_user("alice").is_none());
        assert!(s.delete_local_user("alice").is_err());

        // LDAP 覆盖 upsert
        s.upsert_ldap_override("zhangsan", Some("张三".into()), Some(false), None, &["IIIS".into()])
            .unwrap();
        let o = s.all_overrides().pop().unwrap();
        assert_eq!(o.username, "zhangsan");
        assert_eq!(o.display_name.as_deref(), Some("张三"));
        assert_eq!(o.enabled, Some(false));
        assert!(s.all_groups().contains(&"IIIS".to_string()));

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn empty_path_rejected() {
        // 回归：空路径 / :memory: 必须报错，禁止静默内存库
        assert!(UserStore::open(std::path::Path::new("")).is_err());
        assert!(UserStore::open(std::path::Path::new(":memory:")).is_err());
    }
}
