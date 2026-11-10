//! TOTP（RFC 6238）工具：密钥生成、otpauth URI、二维码、校验。
//!
//! 参数固定 SHA1 / 6 位 / 30 秒 / ±1 窗口（totp-rs 默认值，主流 App 通用）。
//! 未启用 totp-rs 的 `gen_secret` 特性（会引入 rand 0.10 与本项目 rand 0.8 冲突），
//! 20 字节（160-bit）密钥由本项目 rand 0.8 生成。

use rand::RngCore;
use totp_rs::{Builder, Secret, Totp};

/// 默认 issuer（otpauth URI 中的 `issuer=`）
pub const ISSUER: &str = "VentoSiteProxy";

/// 生成随机 20 字节 TOTP 密钥，返回 base32（大写无填充）
pub fn generate_secret() -> String {
    let mut buf = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut buf);
    Secret::from(buf).to_base32()
}

/// 由 base32 密钥构建 TOTP 实例（account_name 不能含 `:`，登录用户名已保证 ASCII 安全字符）
fn build(account_name: &str, secret_b32: &str) -> Result<Totp, String> {
    let secret = Secret::try_from_base32(secret_b32)
        .map_err(|e| format!("TOTP 密钥无效: {e}"))?;
    Builder::new()
        .with_secret(secret)
        .with_account_name(account_name)
        .with_issuer(Some(ISSUER))
        .build()
        .map_err(|e| format!("构建 TOTP 失败: {e}"))
}

/// 校验当前时间窗（±1）的 6 位动态码
pub fn verify(secret_b32: &str, code: &str) -> bool {
    match build("account", secret_b32) {
        Ok(t) => t.check_current(code.trim()).is_some(),
        Err(_) => false,
    }
}

/// otpauth:// URI（供扫码 App 使用）
pub fn otpauth_uri(account_name: &str, secret_b32: &str) -> String {
    match build(account_name, secret_b32) {
        Ok(t) => t.to_url().unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// 二维码 PNG 的 base64（`data:image/png;base64,` 由前端拼接）
pub fn qr_png_base64(account_name: &str, secret_b32: &str) -> Option<String> {
    build(account_name, secret_b32).ok()?.to_qr_base64().ok()
}
