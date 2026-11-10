//! 登录限流：同一 IP 在窗口内失败 ≥ max_failed 次 → 锁定 lockout_secs 秒。
//!
//! 参数经 `ArcSwap` 热更新（auth.yaml 修改后 2s 内生效）；
//! 计数表由 vsp-auth-evaluator 定期清理。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chrono::Utc;

use crate::config::RatelimitSettings;

#[derive(Default)]
struct Ctr {
    fails: u32,
    window_start: i64,
    locked_until: i64,
}

pub struct RateLimiter {
    params: ArcSwap<RatelimitSettings>,
    inner: Mutex<HashMap<String, Ctr>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RatelimitSettings::default())
    }
}

impl RateLimiter {
    pub fn new(params: RatelimitSettings) -> Self {
        Self { params: ArcSwap::from_pointee(params), inner: Mutex::new(HashMap::new()) }
    }

    /// 热更新限流参数（auth.yaml 保存/重载时调用）
    pub fn set_params(&self, p: RatelimitSettings) {
        self.params.store(Arc::new(p));
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    /// 若已锁定，返回剩余锁定秒数
    pub fn is_locked(&self, ip: &str) -> Option<i64> {
        let now = Self::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let c = g.get_mut(ip)?;
        if c.locked_until > 0 {
            if now < c.locked_until {
                return Some(c.locked_until - now);
            }
            *c = Ctr::default();
        }
        None
    }

    /// 记录一次登录失败；达阈值即锁定
    pub fn record_failure(&self, ip: &str) {
        let p = self.params.load();
        let now = Self::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let c = g.entry(ip.to_string()).or_default();
        if c.window_start == 0 || now - c.window_start >= p.window_secs as i64 {
            c.fails = 1;
            c.window_start = now;
        } else {
            c.fails += 1;
        }
        if c.fails >= p.max_failed && p.max_failed > 0 {
            c.locked_until = now + p.lockout_secs as i64;
            log::warn!("IP {ip} {}s 内登录失败 {} 次，锁定 {}s", p.window_secs, c.fails, p.lockout_secs);
        }
    }

    /// 登录成功：清除该 IP 计数
    pub fn record_success(&self, ip: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.get(ip).map(|c| c.fails).unwrap_or(0) > 0 {
            g.remove(ip);
        }
    }

    /// 定期清理过期条目（vsp-auth-evaluator）
    pub fn prune(&self) {
        let p = self.params.load();
        let now = Self::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, c| {
            (c.locked_until != 0 && now < c.locked_until) || (c.window_start != 0 && now - c.window_start < p.window_secs as i64)
        });
    }

    #[cfg(test)]
    fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_flow() {
        let r = RateLimiter::new(RatelimitSettings { max_failed: 3, window_secs: 600, lockout_secs: 900 });
        assert!(r.is_locked("1.1.1.1").is_none());
        r.record_failure("1.1.1.1");
        r.record_failure("1.1.1.1");
        assert!(r.is_locked("1.1.1.1").is_none());
        r.record_failure("1.1.1.1");
        assert_eq!(r.is_locked("1.1.1.1"), Some(900));

        // 成功后解锁
        r.record_success("1.1.1.1");
        assert!(r.is_locked("1.1.1.1").is_none());
    }

    #[test]
    fn independent_ips() {
        let r = RateLimiter::new(RatelimitSettings { max_failed: 1, window_secs: 600, lockout_secs: 60 });
        r.record_failure("a");
        assert!(r.is_locked("a").is_some());
        assert!(r.is_locked("b").is_none());
    }
}
