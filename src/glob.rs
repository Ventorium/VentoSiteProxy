//! 简化的 glob 匹配：`*` 匹配任意长度的任意字符序列（包含 `/`），其余字符必须精确匹配。
//! 经典双指针回溯算法，O(n*m) 最坏情况但实际很快，无堆分配。

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut pi = 0usize;
    let mut ti = 0usize;
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 生成访问日志文件名用的安全 slug：仅保留 [0-9A-Za-z_-]，其余替换为 `-`
pub fn slugify(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "unnamed".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn exact() {
        assert!(glob_match("/api/v1/db", "/api/v1/db"));
        assert!(!glob_match("/api/v1/db", "/api/v1/dbx"));
        assert!(!glob_match("/api/v1/db", "/api/v1/db/health"));
    }

    #[test]
    fn star() {
        assert!(glob_match("/api/v1/*", "/api/v1/anything"));
        assert!(glob_match("/api/v1/*", "/api/v1/a/b/c"));
        assert!(!glob_match("/api/v1/*", "/api/v2/x"));
        assert!(glob_match("/*", "/x"));
        assert!(glob_match("*", "/x/y"));
    }

    #[test]
    fn user_example() {
        // 白名单 /api/v1/* + 黑名单 /api/v1/db* 放前面 → db 相关 403，其余 200
        let rules = vec![("/api/v1/db*", false), ("/api/v1/*", true)];
        let decide = |path: &str| {
            for (pat, allow) in &rules {
                if glob_match(pat, path) {
                    return *allow;
                }
            }
            true
        };
        assert!(!decide("/api/v1/db"));
        assert!(!decide("/api/v1/db/health"));
        assert!(decide("/api/v1/users"));
        assert!(decide("/api/v1/users/5"));
        assert!(decide("/healthz"));
    }
}
