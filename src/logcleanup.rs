//! 访问日志自动清理：启动 60 秒后首次执行，之后每 24 小时一次。
//! 删除 logs/access/ 下归档日期早于保留天数的日志文件；
//! 无法从文件名解析日期的旧格式文件（<slug>.log）按文件修改时间判断。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::config::AppState;

pub struct LogCleanupService {
    pub state: Arc<AppState>,
}

#[async_trait]
impl BackgroundService for LogCleanupService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        tokio::select! {
            _ = shutdown.changed() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                loop {
                    Self::run(&self.state);
                    tokio::select! {
                        _ = shutdown.changed() => break,
                        _ = tokio::time::sleep(Duration::from_secs(24 * 3600)) => {}
                    }
                }
            }
        }
        log::info!("log cleanup service exited");
    }
}

impl LogCleanupService {
    fn run(state: &Arc<AppState>) {
        let cfg = state.load_config();
        let lc = &cfg.log_cleanup;
        if !lc.enabled || lc.retention_days == 0 {
            return;
        }
        let dir = state.log_dir.join("access");
        if !dir.is_dir() {
            return;
        }
        let cutoff = chrono::Local::now()
            - chrono::Duration::days(lc.retention_days as i64);
        let cutoff_date = cutoff.format("%Y%m%d").to_string();
        let retention_secs = lc.retention_days as u64 * 86400;
        let mut removed = 0usize;

        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let expired = match archive_date(&path) {
                // 文件名日期与 mtime 一致 → 真归档文件，按归档日期判断
                Some(ds) => ds < cutoff_date,
                // 无日期旧格式 .log 文件（含 slug 以 8 位数字结尾被误判的）→ 按 mtime 判断
                None if name.ends_with(".log") => entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .map(|e| e.as_secs() > retention_secs)
                    .unwrap_or(false),
                // 非 .log 文件一律不清理
                None => false,
            };
            if expired {
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        removed += 1;
                        log::info!("log cleanup: removed expired log {name}");
                    }
                    Err(e) => log::warn!("log cleanup: failed to remove {name}: {e}"),
                }
            }
        }
        if removed > 0 {
            log::info!(
                "log cleanup: removed {removed} expired log file(s) (retention {} days)",
                lc.retention_days
            );
        }
    }
}

/// 解析文件名末尾的归档日期：`<slug>-YYYYMMDD.log` → Some("YYYYMMDD")；无法解析返回 None
pub fn file_date(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".log")?;
    let (_, ds) = stem.rsplit_once('-')?;
    if ds.len() == 8
        && ds.bytes().all(|b| b.is_ascii_digit())
        && chrono::NaiveDate::parse_from_str(ds, "%Y%m%d").is_ok()
    {
        Some(ds.to_string())
    } else {
        None
    }
}

/// 文件名日期与文件 mtime 交叉校验：一致（±2 天）才认定为真归档文件。
/// 防止站点 slug 本身以 8 位日期数字结尾的旧格式文件（如 `site-1-data-20260101.log`）
/// 被误判为 2026-01-01 的归档而被提前删除；此时返回 None，由调用方按 mtime 判断。
pub fn archive_date(path: &std::path::Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let ds = file_date(name)?;
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    let age_secs = mtime.elapsed().ok()?.as_secs() as i64;
    let archived = chrono::NaiveDate::parse_from_str(&ds, "%Y%m%d").ok()?;
    let mdate = (chrono::Local::now() - chrono::Duration::seconds(age_secs)).date_naive();
    (archived - mdate)
        .num_days()
        .abs()
        .le(&2)
        .then(|| ds.to_string())
}

#[cfg(test)]
mod tests {
    use super::file_date;

    #[test]
    fn parses_dated_name() {
        assert_eq!(
            file_date("site-25-oa-aihualing-com-20261029.log").as_deref(),
            Some("20261029")
        );
    }

    #[test]
    fn rejects_undated_name() {
        assert_eq!(file_date("site-25-oa-aihualing-com.log"), None);
    }

    #[test]
    fn rejects_invalid_date() {
        // 13 月不是合法日期
        assert_eq!(file_date("site-1-test-20261301.log"), None);
        assert_eq!(file_date("site-1-test-abcdef12.log"), None);
        assert_eq!(file_date("site-1-test-2026-10-29.log"), None);
    }

    #[test]
    fn date_like_slug_still_works() {
        // slug 本身以数字结尾时，真正的日期仍是最后一个 - 分隔段
        assert_eq!(
            file_date("site-1-test12345678-20261029.log").as_deref(),
            Some("20261029")
        );
    }

    #[test]
    fn archive_date_accepts_consistent_file() {
        // 文件名日期 = 今天且文件刚写入 → 认定为真归档文件
        let dir = std::env::temp_dir().join("vsp-logcleanup-test");
        std::fs::create_dir_all(&dir).unwrap();
        let today = chrono::Local::now().format("%Y%m%d").to_string();
        let p = dir.join(format!("site-1-x-{today}.log"));
        std::fs::write(&p, "test\n").unwrap();
        assert_eq!(super::archive_date(&p).as_deref(), Some(today.as_str()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archive_date_rejects_date_like_slug() {
        // 站点 slug 以 8 位日期结尾的旧格式文件：刚写入（mtime=现在）但文件名日期是去年 → 误判，返回 None
        let dir = std::env::temp_dir().join("vsp-logcleanup-test2");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("site-1-data-20250101.log");
        std::fs::write(&p, "test\n").unwrap();
        assert_eq!(super::archive_date(&p), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
