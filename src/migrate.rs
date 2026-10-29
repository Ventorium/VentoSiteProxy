//! 从 NPM 的 database.sqlite 迁移到 sites.yaml。
//!
//! 映射：
//!   proxy_host → Site（domain_names / forward_host:port / forward_scheme /
//!     advanced_config 里的 proxy_*_timeout 与 location 块 → locations）
//!   stream     → TcpStream（incoming_port → listen 0.0.0.0:port）
//!
//! NPM 的 buffering / body-size / set_header 类 advanced 配置在 VentoSiteProxy 中
//! 是内置行为（默认流式转发、无 body 大小限制），不迁移、只在 notes 记录。

use crate::config::{save_atomic, Location, Site, TcpStream, UrlAction, AppConfig};
use rusqlite::Connection;

/// 解析 nginx 时间值（"30s" "30m" "24h" "7d" "60"）为秒。
fn parse_secs(v: &str) -> u64 {
    let v = v.trim();
    if v.is_empty() {
        return 0;
    }
    let (num, mult) = if let Some(n) = v.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = v.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = v.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = v.strip_suffix('s') {
        (n, 1)
    } else {
        (v, 1)
    };
    num.trim().parse::<f64>().map(|x| (x * mult as f64) as u64).unwrap_or(0)
}

/// 提取 `directive value;`（value 不含分号）。
/// 只认独立指令名（前一个字符是空白或串首），注释里出现的同名文字不算。
fn directive(s: &str, name: &str) -> Option<u64> {
    for (start, _m) in s.match_indices(name) {
        let end = start + name.len();
        let before_ok = start == 0 || s.as_bytes()[start - 1].is_ascii_whitespace();
        let after = s[end..].trim_start();
        let mut j = 0;
        while j < after.len() && (after.as_bytes()[j].is_ascii_alphanumeric() || after.as_bytes()[j] == b'.') {
            j += 1;
        }
        // 值必须以数字（或小数点）开头，否则名字是更长单词的一部分
        if before_ok && j > 0 && (after.as_bytes()[0].is_ascii_digit() || after.as_bytes()[0] == b'.') {
            return Some(parse_secs(&after[..j]));
        }
    }
    None
}

/// 找 `location PATTERN { ... }` 块（无嵌套大括号）。
fn find_locations(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let Some(rel) = s[i..].find("location ") else {
            break
        };
        let start = i + rel + "location ".len();
        // pattern 到 '{'
        let open = match s[start..].find('{') {
            Some(o) => start + o,
            None => break,
        };
        let pattern = s[start..open].trim().to_string();
        // 找匹配的 '}'
        let mut depth = 1;
        let mut close = open + 1;
        while close < s.len() && depth > 0 {
            match bytes[close] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            if depth > 0 {
                close += 1;
            }
        }
        out.push((pattern, s[open + 1..close.max(open + 1)].to_string()));
        i = close + 1;
    }
    out
}

pub fn run(db: &str, out: &str, enabled_only: bool) {
    let conn = Connection::open(db).unwrap_or_else(|e| panic!("打开数据库失败 {db}: {e}"));

    let mut sites: Vec<Site> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    {
        let mut st = conn
            .prepare(
                "SELECT id, domain_names, forward_host, forward_port, forward_scheme, \
                 enabled, is_deleted, advanced_config FROM proxy_host ORDER BY id",
            )
            .unwrap_or_else(|e| panic!("查询 proxy_host 失败: {e}"));
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            })
            .unwrap_or_else(|e| panic!("遍历 proxy_host 失败: {e}"));
        for row in rows {
            let (id, domains_json, fhost, fport, fscheme, enabled, deleted, adv) =
                row.unwrap_or_else(|e| panic!("读取 proxy_host 行失败: {e}"));
            if deleted == 1 {
                skipped.push(format!("#{id}: 已软删除"));
                continue;
            }
            if enabled_only && enabled != 1 {
                skipped.push(format!("#{id}: 已禁用"));
                continue;
            }
            let domains: Vec<String> = serde_json::from_str::<Vec<String>>(&domains_json)
                .unwrap_or_default()
                .into_iter()
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .collect();
            if domains.is_empty() {
                skipped.push(format!("#{id}: 无域名"));
                continue;
            }
            let name = domains[0].clone();
            let upstream = format!("{fhost}:{fport}");
            let scheme = if fscheme.eq_ignore_ascii_case("https") { "https" } else { "http" }.to_string();

            let adv = adv.unwrap_or_default().replace('\r', "");
            let mut notes: Vec<String> = Vec::new();

            // location 块（NPM 的 locations 列全空，实际在 advanced_config 里）
            let locs_raw = find_locations(&adv);
            let mut locs: Vec<Location> = Vec::new();
            for (pat, body) in &locs_raw {
                let Some(pp) = body.find("proxy_pass") else {
                    notes.push(format!("location {pat}: 无 proxy_pass，跳过"));
                    continue;
                };
                let tail = &body[pp + "proxy_pass".len()..];
                let target = tail.trim_start().split(';').next().unwrap_or("").trim();
                // 形如 http://1.2.3.4:8083 或 https://host:443
                let (lscheme, lhost) = match target.split_once("://") {
                    Some((sc, rest)) => {
                        let (h, p) = match rest.rsplit_once(':') {
                            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p),
                            _ => (rest, "80"),
                        };
                        (sc.to_string(), format!("{h}:{p}"))
                    }
                    None => ("http".into(), target.to_string()),
                };
                let lconn = directive(body, "proxy_connect_timeout").unwrap_or(0);
                let lread = directive(body, "proxy_read_timeout").unwrap_or(0);
                locs.push(Location {
                    path: pat.clone(),
                    upstream: lhost,
                    upstream_scheme: lscheme,
                    connect_timeout: lconn,
                    read_timeout: lread,
                });
            }

            // 站点级超时：只取 location 块之外的指令
            let outer: String = {
                // 去掉所有 location 块后剩下的文本
                let rest = adv.clone();
                let mut out2 = String::new();
                let mut i = 0;
                while i < rest.len() {
                    match rest[i..].find("location ") {
                        None => {
                            out2.push_str(&rest[i..]);
                            break;
                        }
                        Some(rel) => {
                            out2.push_str(&rest[i..i + rel]);
                            let open = i + rel + "location ".len();
                            let open = match rest[open..].find('{') {
                                Some(o) => open + o + 1,
                                None => break,
                            };
                            let mut depth = 1;
                            let mut close = open;
                            while close < rest.len() && depth > 0 {
                                match rest.as_bytes()[close] {
                                    b'{' => depth += 1,
                                    b'}' => depth -= 1,
                                    _ => {}
                                }
                                close += 1;
                            }
                            i = close;
                        }
                    }
                }
                out2
            };
            let connect_timeout = directive(&outer, "proxy_connect_timeout").unwrap_or(10);
            let read_timeout = directive(&outer, "proxy_read_timeout").unwrap_or(0);
            let write_timeout = directive(&outer, "proxy_send_timeout").unwrap_or(0);

            // 无法映射的 advanced 指令记录到 notes
            let adv_trim = adv.trim();
            if !adv_trim.is_empty() && locs.is_empty() {
                let directives: Vec<&str> = adv_trim
                    .split(';')
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty())
                    .filter(|x| {
                        !x.starts_with("proxy_read_timeout")
                            && !x.starts_with("proxy_connect_timeout")
                            && !x.starts_with("proxy_send_timeout")
                    })
                    .collect();
                if !directives.is_empty() {
                    notes.push(format!(
                        "NPM advanced_config 其余指令（内置行为覆盖）: {}",
                        directives.join("; ")
                    ));
                }
            }
            let notes = notes.join(" | ");

            sites.push(Site {
                id: id as u64,
                name,
                notes,
                enabled: enabled == 1,
                access_log: true,
                domains,
                upstream,
                upstream_scheme: scheme,
                upstream_sni: None,
                verify_cert: false,
                connect_timeout,
                read_timeout,
                write_timeout,
                locations: locs,
                url_rules: Vec::new(),
                url_default: UrlAction::Allow,
            });
        }
    }

    let mut streams: Vec<TcpStream> = Vec::new();
    {
        let mut st = conn
            .prepare(
                "SELECT id, incoming_port, forwarding_host, forwarding_port, \
                 enabled, is_deleted, tcp_forwarding, udp_forwarding FROM stream ORDER BY id",
            )
            .unwrap_or_else(|e| panic!("查询 stream 失败: {e}"));
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })
            .unwrap_or_else(|e| panic!("遍历 stream 失败: {e}"));
        for row in rows {
            let (id, inport, fhost, fport, enabled, deleted, tcp, udp) =
                row.unwrap_or_else(|e| panic!("读取 stream 行失败: {e}"));
            if deleted == 1 {
                skipped.push(format!("stream#{id}: 已软删除"));
                continue;
            }
            if enabled_only && enabled != 1 {
                skipped.push(format!("stream#{id}: 已禁用"));
                continue;
            }
            let mut notes = String::new();
            if tcp != 1 {
                notes = format!("NPM 中 TCP 转发未勾选（udp={udp}），VentoSiteProxy 仅支持 TCP 透传");
            }
            streams.push(TcpStream {
                id: id as u64,
                name: format!("tcp-{inport}"),
                notes,
                enabled: enabled == 1,
                listen: format!("0.0.0.0:{inport}"),
                upstream: format!("{fhost}:{fport}"),
            });
        }
    }

    // 保留 NPM 原 id，新站点从 max+1 起
    let max_sid = sites.iter().map(|s| s.id).max().unwrap_or(0);
    let max_mid = streams.iter().map(|s| s.id).max().unwrap_or(0);
    let _ = (max_sid, max_mid);

    let mut cfg = AppConfig::default();
    cfg.version = 1;
    cfg.sites = sites;
    cfg.streams = streams;
    let yaml = serde_yaml::to_string(&cfg).unwrap_or_else(|e| panic!("序列化失败: {e}"));
    save_atomic(std::path::Path::new(out), &yaml).unwrap_or_else(|e| panic!("写入 {out} 失败: {e}"));

    let n_en = cfg.sites.iter().filter(|s| s.enabled).count();
    println!("迁移完成 → {out}");
    println!("  站点: {}（启用 {n_en}）  数据流: {}", cfg.sites.len(), cfg.streams.len());
    println!("  跳过: {} 条", skipped.len());
    for s in &skipped {
        println!("    - {s}");
    }
    let with_adv = cfg.sites.iter().filter(|s| !s.notes.is_empty()).count();
    println!("  带 notes 的站点: {with_adv}");
    for s in &cfg.sites {
        if !s.locations.is_empty() {
            println!("    location 覆盖: site#{} {}", s.id, s.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::directive;

    #[test]
    fn plain_directive() {
        assert_eq!(directive("proxy_read_timeout 3600s;", "proxy_read_timeout"), Some(3600));
        assert_eq!(directive("proxy_connect_timeout 10s;\nproxy_read_timeout 600s;", "proxy_read_timeout"), Some(600));
    }

    #[test]
    fn cjk_comment_does_not_panic() {
        // 回归：指令名出现在中文注释附近时不得 panic（char boundary）
        let s = "# 就是现在卡在 90s 的那个\nproxy_read_timeout    600s;   # 读取超时（SSE/LLM）\nproxy_send_timeout 600s;";
        assert_eq!(directive(s, "proxy_read_timeout"), Some(600));
        assert_eq!(directive(s, "proxy_send_timeout"), Some(600));
    }

    #[test]
    fn word_boundary() {
        // 更长的单词包含目标名时不算命中
        assert_eq!(directive("xproxy_read_timeout 600s;", "proxy_read_timeout"), None);
        assert_eq!(directive("#proxy_read_timeout 600s;", "proxy_read_timeout"), None);
        assert_eq!(directive("proxy_read_timeoutx 600s; proxy_read_timeout 60s;", "proxy_read_timeout"), Some(60));
        assert_eq!(directive("no directives here", "proxy_read_timeout"), None);
    }
}
