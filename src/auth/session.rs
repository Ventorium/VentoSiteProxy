//! 内存会话：32 字节随机 token（仅存 sha256(token)），`ArcSwap<HashMap>` + 每条目空闲计数。
//!
//! - `issue`：签发（每用户超限时按最后活跃时间淘汰最旧会话）
//! - `lookup`：校验绝对寿命 + 空闲超时，命中则刷新 last_active 并返回副本
//! - `revoke_user`：账号删除/禁用/重置密码后一键下线
//! - `evict_expired`：后台评估器 60s 定期清理
//!
//! 重启 / `--upgrade` 后全部会话失效（设计 §6.4，已确认接受）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};

/// token → sha256 hex（会话表中只存哈希）
pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex_of(&h.finalize())
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 会话信息（校验通过后返回的快照副本）
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token_hash: String,
    pub username: String,
    pub subject: String,
    pub display_name: String,
    pub source: String,
    pub groups: Vec<String>,
    pub ip: String,
    pub issued_at: i64,
    pub last_active: i64,
    /// 1 = 仅密码；P3：2 = 密码 + MFA
    pub auth_level: u8,
}

struct SessionEntry {
    token_hash: String,
    username: String,
    subject: String,
    display_name: String,
    source: String,
    groups: Vec<String>,
    ip: String,
    issued_at: i64,
    last_active: AtomicI64,
    /// 1 = 仅密码；2 = 密码 + MFA（P3 重认证成功后就地升级）
    auth_level: AtomicU8,
    /// 签发序号（同秒内 last_active 相同时的确定性淘汰次序）
    seq: u64,
}

impl SessionEntry {
    fn info(&self, last_active: i64) -> SessionInfo {
        SessionInfo {
            token_hash: self.token_hash.clone(),
            username: self.username.clone(),
            subject: self.subject.clone(),
            display_name: self.display_name.clone(),
            source: self.source.clone(),
            groups: self.groups.clone(),
            ip: self.ip.clone(),
            issued_at: self.issued_at,
            last_active,
            auth_level: self.auth_level.load(Ordering::Relaxed),
        }
    }
}

pub struct SessionStore {
    map: ArcSwap<HashMap<String, Arc<SessionEntry>>>,
    /// 单调递增签发序号：同秒内多个会话 last_active 相同时的确定性淘汰次序
    seq: AtomicU64,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            map: ArcSwap::from_pointee(HashMap::new()),
            seq: AtomicU64::new(0),
        }
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    /// 签发新会话（每用户超 max_per_user 时淘汰最久不活跃者）；返回明文 token（仅此时可见）
    pub fn issue(
        &self,
        username: &str,
        subject: &str,
        display_name: &str,
        source: &str,
        groups: &[String],
        ip: &str,
        auth_level: u8,
        max_per_user: usize,
    ) -> String {
        let now = Self::now();
        let mut rng = rand::thread_rng();
        let token: String = (0..32).map(|_| format!("{:02x}", rng.gen_range(0..=u8::MAX))).collect();
        let token_hash = hash_token(&token);

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut next = (**self.map.load()).clone();
        if max_per_user > 0 {
            let mine: Vec<(String, i64, u64)> = next
                .iter()
                .filter(|(_, e)| e.username == username)
                .map(|(k, e)| (k.clone(), e.last_active.load(Ordering::Relaxed), e.seq))
                .collect();
            let excess = mine.len().saturating_add(1).saturating_sub(max_per_user);
            let mut mine = mine;
            // 最久不活跃在前 → 优先淘汰；同秒时按签发序号（先到先淘汰）
            mine.sort_by_key(|(_, t, s)| (*t, *s));
            for (k, _, _) in mine.into_iter().take(excess) {
                next.remove(&k);
            }
        }
        next.insert(
            token_hash.clone(),
            Arc::new(SessionEntry {
                token_hash,
                username: username.to_string(),
                subject: subject.to_string(),
                display_name: display_name.to_string(),
                source: source.to_string(),
                groups: groups.to_vec(),
                ip: ip.to_string(),
                issued_at: now,
                last_active: AtomicI64::new(now),
                auth_level: AtomicU8::new(auth_level),
                seq,
            }),
        );
        self.map.store(Arc::new(next));
        token
    }

    /// 就地升级会话认证级别（P3 重认证 MFA 成功后 1 → 2）；已是更高级别时不降级。
    /// 返回是否发生升级。
    pub fn upgrade_auth_level(&self, token_hash: &str, level: u8) -> bool {
        let cur = self.map.load();
        let entry = match cur.get(token_hash) {
            Some(e) => e,
            None => return false,
        };
        let level0 = entry.auth_level.load(Ordering::Relaxed);
        if level0 < level {
            entry.auth_level.store(level, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// 校验会话：绝对寿命 / 空闲超时命中 → 移除并返回 None；通过则刷新 last_active
    pub fn lookup(&self, token: &str, idle_secs: i64, absolute_secs: i64) -> Option<SessionInfo> {
        let h = hash_token(token);
        let now = Self::now();
        let cur = self.map.load();
        let entry = cur.get(&h)?;
        if now - entry.issued_at > absolute_secs {
            self.remove_if_present(&h);
            return None;
        }
        let last = entry.last_active.load(Ordering::Relaxed);
        if now - last > idle_secs {
            self.remove_if_present(&h);
            return None;
        }
        entry.last_active.store(now, Ordering::Relaxed);
        Some(entry.info(now))
    }

    pub fn remove_if_present(&self, token_hash: &str) -> bool {
        let cur = self.map.load();
        if !cur.contains_key(token_hash) {
            return false;
        }
        let mut next = (**cur).clone();
        next.remove(token_hash);
        self.map.store(Arc::new(next));
        true
    }

    /// 下线用户的全部会话（删除/禁用/重置密码）；返回被撤销数
    pub fn revoke_user(&self, username: &str) -> usize {
        let cur = self.map.load();
        let keys: Vec<String> = cur
            .iter()
            .filter(|(_, e)| e.username == username)
            .map(|(k, _)| k.clone())
            .collect();
        if keys.is_empty() {
            return 0;
        }
        let mut next = (**cur).clone();
        for k in &keys {
            next.remove(k);
        }
        self.map.store(Arc::new(next));
        keys.len()
    }

    /// 按 token_hash 前缀撤销（管理端 /api/sessions/{prefix}，prefix ≥ 16 位 hex）；返回被撤销数
    pub fn remove_by_prefix(&self, prefix: &str) -> usize {
        let cur = self.map.load();
        let keys: Vec<String> = cur.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
        if keys.is_empty() {
            return 0;
        }
        let mut next = (**cur).clone();
        for k in &keys {
            next.remove(k);
        }
        self.map.store(Arc::new(next));
        keys.len()
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let cur = self.map.load();
        cur.iter().map(|(_, e)| e.info(e.last_active.load(Ordering::Relaxed))).collect()
    }

    /// 供管理端会话面板使用（尚未接线）
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.map.load().len()
    }

    /// 定期清理过期会话（vsp-auth-evaluator）；返回清理数
    pub fn evict_expired(&self, idle_secs: i64, absolute_secs: i64) -> usize {
        let now = Self::now();
        let cur = self.map.load();
        let dead: Vec<String> = cur
            .iter()
            .filter(|(_, e)| {
                now - e.issued_at > absolute_secs || now - e.last_active.load(Ordering::Relaxed) > idle_secs
            })
            .map(|(k, _)| k.clone())
            .collect();
        if dead.is_empty() {
            return 0;
        }
        let mut next = (**cur).clone();
        for k in &dead {
            next.remove(k);
        }
        self.map.store(Arc::new(next));
        dead.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_lookup_revoke() {
        let s = SessionStore::new();
        let t = s.issue("alice", "local:alice", "Alice", "local", &["Turing".into()], "1.2.3.4", 1, 5);
        assert_eq!(s.count(), 1);
        let info = s.lookup(&t, 60, 3600).unwrap();
        assert_eq!(info.username, "alice");
        assert_eq!(info.groups, vec!["Turing".to_string()]);

        // 错误 token
        assert!(s.lookup("deadbeef", 60, 3600).is_none());
        // 空闲超时（idle_secs=0 → 同一秒内也可能 >0？用绝对寿命 0 验证移除）
        assert!(s.lookup(&t, 86400, -1).is_none());
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn max_sessions_evicts_oldest() {
        let s = SessionStore::new();
        let a = s.issue("alice", "local:alice", "A", "local", &[], "1.1.1.1", 1, 2);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = s.issue("alice", "local:alice", "A", "local", &[], "1.1.1.1", 1, 2);
        // 新会话 c 触发淘汰 → 最旧的 a 被移除
        let _c = s.issue("alice", "local:alice", "A", "local", &[], "1.1.1.1", 1, 2);
        assert!(s.lookup(&a, 60, 3600).is_none());
        assert!(s.lookup(&b, 60, 3600).is_some());
        assert_eq!(s.count(), 2);

        // revoke_user 全部下线
        assert_eq!(s.revoke_user("alice"), 2);
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn token_is_hashed_and_unique() {
        let s = SessionStore::new();
        let t1 = s.issue("u", "local:u", "U", "local", &[], "1.1.1.1", 1, 5);
        let t2 = s.issue("u", "local:u", "U", "local", &[], "1.1.1.1", 1, 5);
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        assert!(s.list()[0].token_hash.len() == 64);
    }
}
