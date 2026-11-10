//! MFA 一次性凭据（全部仅存内存，TTL 5 分钟，一次性）：
//!
//! - **pending**：密码通过但 MFA 未完成（`Mfa`）或尚无凭据需先绑定（`Enroll`）。
//!   登录时签发，MFA 成功后消费并升级/发放 level-2 会话。
//! - **challenge**：passkey 注册/认证的服务端状态（webauthn-rs 状态对象不可序列化，
//!   必须存服务端防重放）。
//! - **MfaGuard**：按 IP 的 MFA 失败锁定（10 次失败 / 5 分钟 → 锁 15 分钟），
//!   模式与登录限流一致。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use rand::RngCore;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

/// 凭据 TTL（秒）
const TTL_SECS: i64 = 300;
/// MFA 失败锁定窗口（秒）/ 窗口内最大失败次数 / 锁定时长（秒）
const FAIL_WINDOW_SECS: i64 = 300;
const FAIL_MAX: usize = 10;
const LOCK_SECS: i64 = 900;

/// MFA 阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// 密码已通过，需完成 MFA 验证
    Mfa,
    /// 账号要求 MFA 但尚未绑定任何凭据，需先绑定
    Enroll,
}

/// 密码验证通过后的一次性凭据（身份快照；MFA 成功后据此发放 level-2 会话）
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub username: String,
    pub subject: String,
    pub display_name: String,
    pub source: String,
    pub groups: Vec<String>,
    pub ip: String,
    /// 登录时的 `?next=`（同源路径，已校验）
    pub next: String,
    pub kind: PendingKind,
    pub created_at: i64,
}

/// passkey 挑战的上下文：MFA 成功后如何落地
#[derive(Debug, Clone)]
pub enum MfaCtx {
    /// 来自 pending 凭据（登录 MFA / 首登绑定）；token 用于成功后消费
    Pending { pending_token: String },
    /// 来自 level-1 会话（门禁重认证）——成功后就地升级该会话
    Reauth { token_hash: String },
    /// 已登录用户自助管理（仅记录凭据，不改变会话级别）
    SelfManaged,
}

/// passkey 挑战条目（webauthn 状态对象，服务端必须持有）
pub enum ChallengeEntry {
    Register {
        username: String,
        display_name: String,
        /// 发起时实际使用的 rp_id（finish 时凭据必须一致才有效）
        rp_id: String,
        ctx: MfaCtx,
        reg: PasskeyRegistration,
        created_at: i64,
    },
    Authenticate {
        username: String,
        rp_id: String,
        ctx: MfaCtx,
        auth: PasskeyAuthentication,
        created_at: i64,
    },
}

/// 按 IP 的 MFA 失败锁定
pub struct MfaGuard {
    failures: Mutex<HashMap<String, VecDeque<i64>>>,
    locked_until: Mutex<HashMap<String, i64>>,
}

impl MfaGuard {
    /// 是否在锁定中；是则返回剩余秒数
    pub fn is_locked(&self, ip: &str) -> Option<u64> {
        let now = now_secs();
        let mut map = self.locked_until.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(ip) {
            Some(&until) if until > now => Some((until - now) as u64),
            Some(_) => {
                map.remove(ip);
                None
            }
            None => None,
        }
    }

    /// 记录一次失败；窗口内达到阈值则锁定
    pub fn record_failure(&self, ip: &str) {
        let now = now_secs();
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let v = map.entry(ip.to_string()).or_default();
        v.push_back(now);
        while let Some(&first) = v.front() {
            if now - first > FAIL_WINDOW_SECS {
                v.pop_front();
            } else {
                break;
            }
        }
        if v.len() >= FAIL_MAX {
            v.clear();
            drop(map);
            let mut locked = self.locked_until.lock().unwrap_or_else(|e| e.into_inner());
            locked.insert(ip.to_string(), now + LOCK_SECS);
            log::warn!("MFA 连续失败，IP {ip} 锁定 {LOCK_SECS}s");
        }
    }

    /// 成功（或开始流程）后清除失败记录
    pub fn record_success(&self, ip: &str) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(ip);
    }

    /// 定期清理（vsp-auth-evaluator 调用）
    pub fn prune(&self) {
        let now = now_secs();
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, v| v.iter().any(|t| now - t <= FAIL_WINDOW_SECS));
        let mut locked = self.locked_until.lock().unwrap_or_else(|e| e.into_inner());
        locked.retain(|_, &mut until| until > now);
    }
}

impl Default for MfaGuard {
    fn default() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            locked_until: Mutex::new(HashMap::new()),
        }
    }
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 生成 32 字节 hex token（与 session token 同等强度）
pub fn new_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// MFA 一次性凭据存储（AuthState 持有，全局单例）
pub struct MfaState {
    pending: Mutex<HashMap<String, PendingEntry>>,
    challenges: Mutex<HashMap<String, ChallengeEntry>>,
    pub guard: MfaGuard,
}

impl MfaState {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            guard: MfaGuard::default(),
        }
    }

    /// 签发 pending（同一用户至多一条，重签覆盖并作废其未完成挑战）
    pub fn issue_pending(&self, entry: PendingEntry) -> String {
        let token = new_token();
        let username = entry.username.clone();
        {
            let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            p.retain(|_, e| e.username != username);
            p.insert(token.clone(), entry);
        }
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, ch| challenge_username(ch) != username);
        token
    }

    /// 只读查看 pending（passkey begin 时取身份快照；不消费）
    pub fn peek_pending(&self, token: &str) -> Option<PendingEntry> {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let entry = p.get(token)?;
        if now_secs() - entry.created_at > TTL_SECS {
            p.remove(token);
            return None;
        }
        Some(entry.clone())
    }

    /// 消费 pending（MFA 成功落地时调用；TTL 过期视为无效）
    pub fn consume_pending(&self, token: &str) -> Option<PendingEntry> {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let entry = p.get(token)?;
        if now_secs() - entry.created_at > TTL_SECS {
            p.remove(token);
            return None;
        }
        p.remove(token)
    }

    /// 存储 passkey 挑战（同一用户至多一条，重发覆盖）
    pub fn store_challenge(&self, token: String, entry: ChallengeEntry) {
        let username = challenge_username(&entry).to_string();
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, ch| challenge_username(ch) != username);
        c.insert(token, entry);
    }

    /// 消费 passkey 挑战（一次性；TTL 过期视为无效）
    pub fn take_challenge(&self, token: &str) -> Option<ChallengeEntry> {
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        let entry = c.get(token)?;
        if now_secs() - challenge_created(entry) > TTL_SECS {
            c.remove(token);
            return None;
        }
        c.remove(token)
    }

    /// 定期清理过期条目（vsp-auth-evaluator 调用）
    pub fn sweep(&self) {
        let now = now_secs();
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        p.retain(|_, e| now - e.created_at <= TTL_SECS);
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, ch| now - challenge_created(ch) <= TTL_SECS);
        self.guard.prune();
    }
}

impl Default for MfaState {
    fn default() -> Self {
        Self::new()
    }
}

fn challenge_username(ch: &ChallengeEntry) -> &str {
    match ch {
        ChallengeEntry::Register { username, .. } | ChallengeEntry::Authenticate { username, .. } => username,
    }
}

fn challenge_created(ch: &ChallengeEntry) -> i64 {
    match ch {
        ChallengeEntry::Register { created_at, .. } => *created_at,
        ChallengeEntry::Authenticate { created_at, .. } => *created_at,
    }
}
