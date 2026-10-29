//! 未匹配 Host 的默认响应（可配置默认 404 页面）。
//!
//! 三种模式（`AppConfig::default_404`，默认 `status`）：
//! - `status` → 只返回 404 状态码 + 最小文本
//! - `page`   → 内置通用 404 页面（不含任何站点 / 服务信息）
//! - `custom` → 从 `custom_404_dir` 目录读取用户自定义文件（404.html、css、图片等）
//!
//! 安全约束：任何模式的响应都不得暴露请求 Host、服务器名称或版本；
//! custom 模式的路径解析禁止目录穿越，且状态码恒为 404。

use std::path::{Path, PathBuf};

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::Session;

use crate::config::{is_valid_default_404, AppConfig, DEFAULT_404_CUSTOM, DEFAULT_404_PAGE};

/// 内置通用 404 页面：只表达“未找到”语义，不含 Host / 服务名 / 版本等任何可识别信息。
pub const PAGE_404: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 Not Found</title>
<style>
  html,body{margin:0;height:100%}
  body{display:flex;align-items:center;justify-content:center;background:#0f172a;color:#94a3b8;
       font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
  .c{text-align:center;padding:24px}
  .n{font-size:72px;font-weight:700;line-height:1;color:#e2e8f0;letter-spacing:-.02em}
  .t{margin-top:12px;font-size:16px}
  .d{margin-top:6px;font-size:13px;opacity:.7}
</style>
</head>
<body>
<div class="c"><div class="n">404</div><div class="t">The requested page was not found.</div><div class="d">页面未找到</div></div>
</body>
</html>"#;

fn content_type(p: &str) -> &'static str {
    match p.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).as_deref() {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// 将请求路径解析为 `dir` 下的文件；非法路径（含 `.` / `..` 分量）或文件不存在返回 None。
fn resolve_in_dir(dir: &Path, req_path: &str) -> Option<PathBuf> {
    let rel = req_path.trim_start_matches('/');
    if rel.is_empty() {
        return None;
    }
    let mut out = dir.to_path_buf();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return None;
        }
        out.push(comp);
    }
    // 双重校验：规范化后必须仍是 dir 内的普通文件
    let dir_c = dir.canonicalize().ok()?;
    let f = out.canonicalize().ok()?;
    if f.is_file() && f.starts_with(&dir_c) {
        Some(f)
    } else {
        None
    }
}

async fn write_response(session: &mut Session, status: u16, content_type: &str, body: Bytes) {
    let mut resp = match ResponseHeader::build(status, Some(body.len())) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = resp.insert_header("Content-Type", content_type);
    let _ = resp.insert_header("X-Content-Type-Options", "nosniff");
    let _ = resp.insert_header("Cache-Control", "no-store");
    let end = body.is_empty();
    let _ = session.write_response_header(Box::new(resp), end).await;
    if !end {
        let _ = session.write_response_body(Some(body), true).await;
    }
}

/// 未命中任何启用站点时的默认响应。
///
/// - `status`（默认，含未知值）：404 状态码 + `404 Not Found` 最小文本
/// - `page`：内置通用 404 页面
/// - `custom`：请求 `/` → 目录内 `404.html`；请求其他路径 → 优先精确文件
///   （让用户 404 页面可以引用 `/style.css` 等静态资源），未命中回退 `404.html`；
///   目录缺失 / 文件缺失时回退内置页面。状态码恒为 404。
pub async fn respond_default_404(session: &mut Session, cfg: &AppConfig, req_path: &str) {
    debug_assert!(is_valid_default_404(&cfg.default_404));
    match cfg.default_404.as_str() {
        DEFAULT_404_PAGE => {
            let body = Bytes::from(PAGE_404.to_string());
            write_response(session, 404, "text/html; charset=utf-8", body).await;
        }
        DEFAULT_404_CUSTOM => {
            let dir = PathBuf::from(cfg.custom_404_dir.trim());
            let target = if req_path == "/" || req_path.trim_start_matches('/').is_empty() {
                Some(dir.join("404.html"))
            } else {
                resolve_in_dir(&dir, req_path).or_else(|| Some(dir.join("404.html")))
            };
            let data = target.as_ref().and_then(|p| std::fs::read(p).ok());
            match data {
                Some(bytes) => {
                    let ct = target
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .map(|s| content_type(s))
                        .unwrap_or("application/octet-stream");
                    write_response(session, 404, ct, Bytes::from(bytes)).await;
                }
                None => {
                    let body = Bytes::from(PAGE_404.to_string());
                    write_response(session, 404, "text/html; charset=utf-8", body).await;
                }
            }
        }
        _ => {
            write_response(
                session,
                404,
                "text/plain; charset=utf-8",
                Bytes::from("404 Not Found"),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn resolve_rejects_traversal() {
        let dir = std::env::temp_dir().join("vsp-test-d404");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("style.css");
        let mut w = std::fs::File::create(&f).unwrap();
        let _ = w.write_all(b"body{}");
        assert!(resolve_in_dir(&dir, "/style.css").is_some());
        assert!(resolve_in_dir(&dir, "/../etc/passwd").is_none());
        assert!(resolve_in_dir(&dir, "/..").is_none());
        assert!(resolve_in_dir(&dir, "/sub/../../x").is_none());
        assert!(resolve_in_dir(&dir, "/").is_none());
        assert!(resolve_in_dir(&dir, "/missing.txt").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_type_by_ext() {
        assert_eq!(content_type("/a/b.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("/a/b.HTML"), "text/html; charset=utf-8");
        assert_eq!(content_type("/a/noext"), "application/octet-stream");
        assert_eq!(content_type("/a/b.woff2"), "font/woff2");
    }
}
