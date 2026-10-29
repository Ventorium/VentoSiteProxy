//! 访问日志：代理热路径上用 `try_send` 非阻塞投递，后台任务批量落盘。
//! 每个站点按天归档：logs/access/<slug>-YYYYMMDD.log（本地时区日期，跨天自动换新文件）

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use tokio::sync::mpsc::{error::TryRecvError, Receiver};
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::config::{AppState, LogLine};

/// 当前本地日期（YYYYMMDD），作为日志归档日期
pub fn log_date() -> String {
    chrono::Local::now().format("%Y%m%d").to_string()
}

/// 某天的归档文件名：<slug>-YYYYMMDD.log
pub fn dated_log_name(slug: &str, date: &str) -> String {
    format!("{slug}-{date}.log")
}

/// 访问日志写入器（在 pingora 运行时内作为后台服务运行）
pub struct AccessLogWriter {
    pub state: std::sync::Arc<AppState>,
    /// 只被本服务任务使用，Mutex 仅为在 `start(&self)` 中获取 `&mut` 借用
    pub rx: std::sync::Mutex<Receiver<LogLine>>,
}

#[async_trait]
impl BackgroundService for AccessLogWriter {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut open: HashMap<String, std::io::BufWriter<File>> = HashMap::new();
        let mut open_date = log_date();
        let mut flush_tick = tokio::time::interval(Duration::from_millis(500));
        flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut dropped = 0u64;

        let drain = |open: &mut HashMap<String, std::io::BufWriter<File>>,
                     rx: &std::sync::Mutex<Receiver<LogLine>>,
                     log_dir: &std::path::Path,
                     date: &str,
                     _dropped: &mut u64| {
            let mut rx = rx.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        let path = log_dir.join(dated_log_name(&line.slug, date));
                        if !open.contains_key(&line.slug) {
                            match OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&path)
                            {
                                Ok(f) => {
                                    open.insert(line.slug.clone(), std::io::BufWriter::new(f));
                                }
                                Err(e) => {
                                    log::error!("open access log file {}: {e}", path.display());
                                    continue;
                                }
                            }
                        }
                        if let Some(entry) = open.get_mut(&line.slug) {
                            let _ = writeln!(entry, "{}", line.line);
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = flush_tick.tick() => {
                    let today = log_date();
                    if today != open_date {
                        // 跨天：关闭所有已打开的归档文件，新日志懒加载打开当日新文件
                        for w in open.values_mut() {
                            let _ = w.flush();
                        }
                        open.clear();
                        open_date = today;
                    }
                    if let Err(e) = std::fs::create_dir_all(self.state.log_dir.join("access")) {
                        log::error!("create access log dir: {e}");
                    }
                    drain(&mut open, &self.rx, &self.state.log_dir.join("access"), &open_date, &mut dropped);
                    for w in open.values_mut() {
                        let _ = w.flush();
                    }
                    if dropped > 0 {
                        log::warn!("access log: channel full, dropped {dropped} lines so far");
                        dropped = 0;
                    }
                }
            }
        }

        // shutdown：确保目录存在后排空剩余日志
        if let Err(e) = std::fs::create_dir_all(self.state.log_dir.join("access")) {
            log::error!("create access log dir: {e}");
        }
        drain(&mut open, &self.rx, &self.state.log_dir.join("access"), &log_date(), &mut dropped);
        for w in open.values_mut() {
            let _ = w.flush();
        }
        log::info!("access log writer exited");
    }
}

/// 格式化一行 nginx 风格访问日志
pub fn format_line(
    client: &str,
    method: &str,
    path: &str,
    version: &str,
    status: u16,
    bytes: u64,
    site_name: &str,
    rt_ms: u64,
) -> String {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    format!(
        "{client} - [{ts}] \"{method} {path} {version}\" {status} {bytes} \"{site_name}\" rt={rt_ms}ms"
    )
}
