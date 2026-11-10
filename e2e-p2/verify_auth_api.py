#!/usr/bin/env python3
"""E2E: 验证管理端 GET/PUT /api/auth（即 UI「保存」所走的完整链路）。
签发临时 JWT（只读 admin.yaml 的 secret，不改动）；PUT 用与当前完全相同的值 → 零行为变化。
"""
import base64, hashlib, hmac, json, time, subprocess, sys, yaml

def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

admin = yaml.safe_load(open("/opt/ventositeproxy/admin.yaml"))
secret = admin["jwt_secret"]

now = int(time.time())
claims = {"sub": admin["username"], "iat": now, "exp": now + 3600}
h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
p = b64(json.dumps(claims).encode())
sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
tok = f"{h}.{p}.{b64(sig)}"

def api(method, path, body=None):
    cmd = ["curl", "-s", "-o", "/tmp/api_resp.json", "-w", "%{http_code}",
           "-X", method, "-H", f"Authorization: Bearer {tok}",
           "-H", "Content-Type: application/json"]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    cmd += [f"http://127.0.0.1:8890{path}"]
    code = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    data = json.load(open("/tmp/api_resp.json"))
    return int(code), data

# 0) 备份 auth.yaml
subprocess.run(["cp", "-p", "/opt/ventositeproxy/auth.yaml",
                "/tmp/auth.yaml.bak-p2d"], check=True)

# 1) GET /api/auth
code, r = api("GET", "/api/auth")
assert code == 200 and r.get("ok"), f"GET failed: {code} {r}"
s = r["data"]
print("PASS GET /api/auth -> 200, keys:", sorted(s.keys()))

# 2) 旧 URL 确实 404（复现用户报错，证明已修）
code_old, _ = api("GET", "/api/auth/settings")
print(f"INFO old URL GET /api/auth/settings -> {code_old} (期望 404)")

# 3) PUT /api/auth，body = 当前值（bind_password 留空=保持）
body = {
    "inject_upstream_headers": s.get("inject_upstream_headers", True),
    "session": {
        "idle_timeout_secs": s["session"]["idle_timeout_secs"],
        "absolute_timeout_secs": s["session"]["absolute_timeout_secs"],
        "max_sessions_per_user": s["session"]["max_sessions_per_user"],
        "cookie_name": s["session"]["cookie_name"],
        "cookie_secure": s["session"]["cookie_secure"],
    },
    "webauthn": {
        "rp_name": s["webauthn"].get("rp_name", ""),
        "rp_id": s["webauthn"].get("rp_id", ""),
        "origins": s["webauthn"].get("origins", []),
    },
    "ldap": {
        "uri": s["ldap"]["uri"],
        "bind_dn": s["ldap"]["bind_dn"],
        "bind_password": "",
        "user_search_base": s["ldap"]["user_search_base"],
        "group_search_base": s["ldap"]["group_search_base"],
        "attr_login": s["ldap"]["attr_login"],
        "attr_name": s["ldap"]["attr_name"],
        "cache_ttl_secs": s["ldap"]["cache_ttl_secs"],
        "timeout_ms": s["ldap"]["timeout_ms"],
        "fail_mode": s["ldap"]["fail_mode"],
    },
    "ratelimit": {
        "max_failed": s["ratelimit"]["max_failed"],
        "window_secs": s["ratelimit"]["window_secs"],
        "lockout_secs": s["ratelimit"]["lockout_secs"],
    },
}
code, r = api("PUT", "/api/auth", body)
assert code == 200 and r.get("ok"), f"PUT failed: {code} {r}"
print("PASS PUT /api/auth -> 200 ok")

# 4) 落盘文件仍有效且关键值未变
y = yaml.safe_load(open("/opt/ventositeproxy/auth.yaml"))["auth"]
assert y["enabled"] is False, "enabled 被意外改动!"
assert y["ldap"]["uri"] == s["ldap"]["uri"], "ldap.uri 被意外改动!"
assert y["ldap"]["bind_dn"] == s["ldap"]["bind_dn"], "ldap.bind_dn 被意外改动!"
assert y["session"]["cookie_name"] == s["session"]["cookie_name"]
print("PASS auth.yaml 落盘校验：enabled=False, ldap.uri/bind_dn/cookie_name 未变")

# 5) 审计记录
tail = subprocess.run(["tail", "-5", "/opt/ventositeproxy/logs/audit.jsonl"],
                      capture_output=True, text=True).stdout
assert "update_auth_config" in tail, f"audit 未见 update_auth_config: {tail}"
print("PASS 审计日志含 update_auth_config")
print("== VERIFY AUTH API: ALL PASS ==")
