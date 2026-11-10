# P2 · LDAP 接入 交付说明

日期：2026-11-09（CST）
部署机：bbb（192.168.211.223）

## 1. 本期交付内容

| 模块 | 说明 |
| --- | --- |
| LDAP 认证 | `src/auth/ldap.rs`：服务账号 simple-bind → 用户凭证 bind 验证 → 反向组搜索（`uniqueMember`/`member`，兼容 groupOfUniqueNames 与 posixGroup），TTL 300s 缓存，`fail_mode: stale\|deny` |
| 持续身份评估 | `src/auth/identity.rs`：每次请求复核账号仍存在且启用；LDAP 来源走缓存+在线复核，账号被删/禁用立即吊销会话 |
| 配置 | `auth.yaml`（600 权限）新增 `ldap` 段：uri / bind_dn / bind_password / 搜索 base / 属性映射 / 缓存 / 超时 / 故障策略；热加载（2s mtime） |
| 管理端 | 「认证」页 LDAP 表单 + 测试连接按钮（501 → 真实探测）；操作留审计 |
| 网关修正 | `proxy.rs`：门禁已自行响应（302/401/403）后终止管线，**被拒请求不再转发上游**（修复前会泄漏上游并刷 "Respond header is already sent" 警告） |

## 2. 验证结果（主机实测，2026-11-09 21:20）

E2E 16/16 全绿（脚本在 `/opt/ventositeproxy/e2e/`，可随时重跑）：

- 未登录 `GET /` → 401 JSON（`ok:false` + `login_url`）✅
- 错误密码 / 未知用户 → 401 ✅
- `vsp_test_ldap` LDAP 登录 → 200，`source=ldap`，`groups=[VSP_TEST]`，`Set-Cookie: vsp_session` ✅
- 带会话 `GET /` → 200 演示页 ✅
- `/__auth/me` → `source=ldap`，`groups=[VSP_TEST]` ✅
- ACL 热切 `[NOSUCHGRP]` → **403 `无权访问此站点`** + 审计 `access_denied_acl` ✅
- ACL 恢复 `[Turing, VSP_TEST]` → 200 ✅
- 泄漏测试：停上游后触发 403，无上游连接、无 Upstream 错误日志；double-response 警告 = 0 ✅
- 热重载 fail-safe 实测：sites.yaml 损坏时保留旧配置 + journal ERROR，线上不中断 ✅

审计日志（两个文件，勿混淆）：

- `/opt/ventositeproxy/logs/auth.jsonl` — 门禁事件：`access_denied_acl`、`session_revoked_*`
- `/opt/ventositeproxy/logs/audit.jsonl` — 登录/登出/限流/管理端操作

## 3. 浏览器直接验证（演示资产已保留）

1. 本机 `/etc/hosts` 添加：

   ```
   192.168.211.223 p2demo.ainanjing.org.cn
   ```

2. 浏览器打开 `http://p2demo.ainanjing.org.cn` → 302 到登录页。
3. 登录方式二选一：
   - 自己的 LDAP 账号（需在 **Turing** 组）；或
   - 演示账号：`vsp_test_ldap` / `VspTest@2026`（VSP_TEST 组）
4. 登录成功 → 看到 "P2 零信任演示上游" 页面；未登录直接访问则 401（API）/跳登录页（浏览器）。
5. 想看 403：用非 Turing/VSP_TEST 组的 LDAP 账号登录同一站点 → 403 页「您没有权限访问此站点」。
6. 审计实时查看：

   ```bash
   tail -f /opt/ventositeproxy/logs/auth.jsonl /opt/ventositeproxy/logs/audit.jsonl
   ```

## 4. 线上部署状态

| 项 | 值 |
| --- | --- |
| 二进制 | `/usr/local/bin/ventositeproxy`，sha256 `0a8cad2a581077093ae1c16efc45a7361506bb21274c21b169d23b4a6a845b91`（musl 静态） |
| 服务 | ventositeproxy active（:80 + :8890）；p2demo-upstream active（127.0.0.1:9998） |
| 认证配置 | `/opt/ventositeproxy/auth.yaml`：全局关、providers `[local, ldap]`、LDAP 指向 192.168.209.101:389、fail_mode `stale` |
| 演示站点 | sites.yaml id 900「P2-LDAP演示」：`p2demo.ainanjing.org.cn` → 127.0.0.1:9998，`auth: {enabled, allowed_groups: [Turing, VSP_TEST]}` |
| LDAP 对象 | 用户 `cn=vsp_test_ldap,ou=People,…`（口令 `VspTest@2026`）、组 `cn=VSP_TEST,ou=Groups,…` |
| 备份 | 二进制 `bak-p2-20261109185745`、`bak-p2b-20261109131838`；配置 `sites.yaml.bak-p2-20261109190526`、`auth.yaml.bak-p2-20261109190526` |

## 5. 清理 / 回滚步骤（需要时执行）

```bash
# 1) 移除演示站点 + 恢复旧认证配置
cp /opt/ventositeproxy/sites.yaml.bak-p2-20261109190526 /opt/ventositeproxy/sites.yaml
cp /opt/ventositeproxy/auth.yaml.bak-p2-20261109190526  /opt/ventositeproxy/auth.yaml

# 2) 停演示上游
systemctl disable --now p2demo-upstream

# 3) 删除 LDAP 演示对象（192.168.209.101，cn=admin 绑定）
ldapdelete -x -D 'cn=admin,dc=ainanjing,dc=org,dc=cn' -w '<服务账号口令>' \
  'cn=vsp_test_ldap,ou=People,dc=ainanjing,dc=org,dc=cn'
ldapdelete -x -D 'cn=admin,dc=ainanjing,dc=org,dc=cn' -w '<服务账号口令>' \
  'cn=VSP_TEST,ou=Groups,dc=ainanjing,dc=org,dc=cn'

# 4)（可选）回滚二进制到 P2 前
cp /usr/local/bin/ventositeproxy.bak-p2-20261109185745 /usr/local/bin/ventositeproxy
install -m 755 /usr/local/bin/ventositeproxy /usr/local/bin/ventositeproxy
systemctl restart ventositeproxy   # 约 35-40s 后新进程接管
```

## 6. 下一步

- **P3**：TOTP + Passkey（totp-rs 6.0.0 + webauthn-rs 0.6.2），逐人 MFA 开关，enroll/need_mfa/reauth 状态机。
- **P4**：打磨（文档、测试矩阵、发布流程）。
- 代码在工作树未提交，待审查后 commit。
