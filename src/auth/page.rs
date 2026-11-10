//! 内置页面（编译期嵌入）

/// 终端用户登录页
pub const LOGIN_HTML: &str = include_str!("../../web/login.html");

/// MFA 二次验证页（TOTP / 通行密钥）
pub const MFA_HTML: &str = include_str!("../../web/mfa.html");

/// MFA 首次绑定页（尚未配置任何凭据的用户）
pub const ENROLL_HTML: &str = include_str!("../../web/enroll.html");
