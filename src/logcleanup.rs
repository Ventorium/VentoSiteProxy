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
            let expired = if let Some(ds) = file_date(name) {
                ds < cutoff_date
            } else if let Ok(md) = entry.metadata() {
                md.modified()
                    .map(|t| t.elapsed().is_ok() && t.elapsed().unwrap().as_secs() > retention_secs)
                    .unwrap_or(false)
            } else {
                false
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
}
