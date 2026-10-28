//! Host → 站点 路由：精确匹配优先，其次最长通配符 `*.domain` 命中；仅考虑 enabled 站点。

use crate::config::Site;

pub fn find_site<'a>(sites: &'a [Site], host: &str) -> Option<&'a Site> {
    let mut host = host.trim().to_ascii_lowercase();
    // 去掉可能携带的端口
    if let Some(idx) = host.find(':') {
        host.truncate(idx);
    }
    if host.is_empty() {
        return None;
    }

    let mut wildcard: Option<&Site> = None;
    let mut wildcard_suffix_len = 0usize;

    for site in sites {
        if !site.enabled {
            continue;
        }
        for raw in &site.domains {
            let d = raw.trim().to_ascii_lowercase();
            if d.is_empty() {
                continue;
            }
            if d == host {
                return Some(site);
            }
            if let Some(suffix) = d.strip_prefix("*.") {
                // host 必须以 ".suffix" 结尾，且多出的前缀至少是一个 label（含点）
                let dot_suffix = format!(".{suffix}");
                if host.len() > dot_suffix.len() && host.ends_with(dot_suffix.as_str()) {
                    let prefix = &host[..host.len() - dot_suffix.len()];
                    // `*` 至少匹配一个 label；前缀非空即可（允许多级子域）
                    if !prefix.is_empty() {
                        let len = suffix.len();
                        if len > wildcard_suffix_len {
                            wildcard = Some(site);
                            wildcard_suffix_len = len;
                        }
                    }
                }
            }
        }
    }

    wildcard
}

#[cfg(test)]
mod tests {
    use super::find_site;
    use crate::config::{AppConfig, Site, TcpStream};

    fn site(id: u64, name: &str, domains: &[&str]) -> Site {
        let s = Site {
            id,
            name: name.into(),
            notes: String::new(),
            enabled: true,
            access_log: true,
            domains: domains.iter().map(|s| s.to_string()).collect(),
            upstream: "127.0.0.1:9000".into(),
            upstream_scheme: "http".into(),
            upstream_sni: None,
            verify_cert: false,
            connect_timeout: 10,
            read_timeout: 0,
            write_timeout: 0,
            locations: Vec::new(),
            url_rules: Vec::new(),
            url_default: crate::config::UrlAction::Allow,
        };
        s
    }

    #[test]
    fn exact_beats_wildcard() {
        let a = site(1, "a", &["*.example.com"]);
        let b = site(2, "b", &["example.com"]);
        let cfg = AppConfig { version: 1, sites: vec![a.clone(), b.clone()], streams: Vec::<TcpStream>::new() };
        assert_eq!(find_site(&cfg.sites, "example.com").unwrap().id, 2);
        assert_eq!(find_site(&cfg.sites, "api.example.com").unwrap().id, 1);
    }

    #[test]
    fn disabled_not_matched() {
        let mut a = site(1, "a", &["x.com"]);
        a.enabled = false;
        let cfg = AppConfig { version: 1, sites: vec![a], streams: Vec::new() };
        assert!(find_site(&cfg.sites, "x.com").is_none());
    }

    #[test]
    fn port_stripped() {
        let a = site(1, "a", &["x.com"]);
        let cfg = AppConfig { version: 1, sites: vec![a], streams: Vec::new() };
        assert!(find_site(&cfg.sites, "x.com:8080").is_some());
    }
}
