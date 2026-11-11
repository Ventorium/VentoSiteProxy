# VentoSiteProxy 零信任访问控制 方案设计

> 状态：设计评审稿 v3（用户数据改存 SQLite；按域名配置访问人/组；LDAP 配置放 YAML；**全部开放问题已闭环**）
> 日期：2026-11-09
> 范围：为 8880 代理面的反代内容增加统一身份认证（本地手动用户 + LDAP）、MFA（TOTP + passkey/WebAuthn，移动端指纹/人脸）、会话保持与持续评估；管理端 8890 维持现状不受影响。

---

## 0. 已确认信息（2026-11-09 与用户确认 + 实测）

| # | 事项 | 结论 |
|---|------|------|
| 1 | 外层访问方式 | **最外层为 HTTPS**（部署机 192.168.211.223，443 端口开放，frp 链路提供 TLS）。→ passkey/WebAuthn 的 secure context 前提满足 |
| 2 | LDAP 服务器 | `192.168.209.101`，389（明文）/ 636（ldaps，端口开放）均可达；**默认 389**，uri 等全部参数由用户在管理端页面自配（存 `auth.yaml`，见 §8.1） |
| 6 | rp_id / origins | **不预配**：passkey 的 `rp_id`/`origins` 由用户在管理端「认证」页自配，默认按请求 Host 派生（`https://<host>`），支持多域名逗号分隔 |
| 3 | MFA 策略 | **后台按人控制是否开启 MFA，默认不配置**；开启后用户首次登录若无任何已注册因子，**强制先完成因子注册**（TOTP 或 passkey 二选一均可，都属于"加强"）；之后登录两种因子任一通过即可；每个用户可单独设置是否开启 MFA |
| 4 | 用户存储 | **认证用户存 SQLite 数据库**（`auth.db`，rusqlite，项目已有依赖），与管理后台用户（admin.yaml）完全分离、不混用 |
| 5 | 按域名访问控制 | **每个域名（站点）单独配置**可访问的人：按用户勾选 + 按组勾选，两者并集放行 |

### LDAP 实测结构（已验证可连通、可绑定）

- Base DN：`dc=ainanjing,dc=org,dc=cn`
- 用户：`ou=People`，共 **34 人**，DN 格式 `cn=<uid>,ou=People,dc=ainanjing,dc=org,dc=cn`
  - 属性：`uid`、`cn`、`mail`、`givenName`、`uidNumber`、`gidNumber`、`homeDirectory`、`loginShell`、`telephoneNumber`（`displayName` 基本为空 → 显示名回退用 `cn`）
- 组：`ou=Groups`，约 3 个组（`IIIS`、`Global`、`Turing`），`groupOfUniqueNames`（`uniqueMember`）与 `posixGroup`（`member` + `gidNumber`）混用
- **无 `memberOf` 属性（未装 memberof 覆层）** → 组归属用**反向搜索**：以用户 DN 匹配 `uniqueMember`/`member`（见 §4.3）
- **389 不支持 startTLS**（supportedExtension 中无 1.3.6.1.4.1.1466.20036）；636 开放，生产建议 `ldaps://192.168.209.101:636`
- 服务账号：**本期使用 `cn=admin,dc=ainanjing,dc=org,dc=cn`（用户已确认）**（口令仅存部署机 `auth.yaml`，**禁止写入代码、文档、仓库、日志**；后续可单独建只读服务账号）

---

## 1. 需求与目标

| # | 需求 | 设计目标 |
|---|------|---------|
| R1 | 用户来源：LDAP | 支持 LDAP 作为身份提供方，simple bind 校验，不落地 LDAP 密码；LDAP 连接参数在 YAML 中配置 |
| R2 | 用户来源：手动维护 | 本地用户（argon2id 密码）**存 SQLite**（`auth.db`），管理端可视化增删改 |
| R3 | 两种来源可共存 | 统一身份模型，登录时按可配置顺序查找；本地用户、LDAP 用户、管理端用户三者隔离 |
| R4 | MFA（按人开启，默认关） | 两种因子：**TOTP**（Authenticator App 验证码）与 **passkey/WebAuthn**（移动端指纹/人脸 = 平台认证器，`uv: required`）；开启后首次登录强制注册因子；登录时任一因子通过即可 |
| R5 | 通过后才可访问代理内容 | 代理热路径 `request_filter` 内置认证门（gate），未认证 → 302 登录页 / 401 |
| R6 | 按域名控制可访问人 | 每个站点单独配置：允许的用户（逐人勾选）+ 允许的组（逐组勾选），并集放行；未配置的站点 = 所有已认证用户可访问 |
| R7 | 不重复认证 + 持续评估 | 一次登录签发会话 Cookie（跨站点 SSO），空闲/绝对超时控制；策略变更、用户禁用、LDAP 组变化时"持续评估"自动要求重新认证或失效会话 |

设计原则（零信任）：**默认拒绝、每次请求校验、最小授权（按站点限定用户/组）、全程审计、策略热生效**。

---

## 2. 现状分析（插入点）

- 单二进制 Rust + Pingora，两个前台服务：
  - **代理服务（8880）** `src/proxy.rs::request_filter`：Host → 站点（`routes.rs::find_site`，精确>通配，仅 enabled）→ URL 黑白名单 → `upstream_peer`。
  - **管理服务（8890）** `src/admin/api.rs`：自带 argon2id+JWT（`admin.yaml`），独立于本设计。
- 配置体系：`sites.yaml`（`AppConfig`，ArcSwap 热切换 + `ConfigWatcher` 2s 文件监听）、`admin.yaml`。管理端每次变更走 `AppState::with_mutated_config`（锁内：改内存 → 原子落盘 → ArcSwap）。
- 可复用设施：`glob.rs`（glob 匹配，用于豁免路径）、`AuditLog`（JSONL 审计）、`save_atomic`、`ConfigWatcher`、`rusqlite`（已在依赖中，migrate 命令使用）。
- Web UI：`web/index.html` 单文件，`include_str!` 内嵌，Tab 结构（站点/数据流/设置/操作日志），新增页签即可扩展。

**认证门插入位置**：`request_filter` 中"URL 规则判定为 allow 之后、`upstream_peer` 之前"。认证接口（`/__auth/*`）在代理服务内联处理（与 admin API 同模式：`request_filter` 内直接响应，不上游）。

```
request_filter 处理链（改造后）：
  Host→站点(404) → /__auth/* 内联处理(登录/MFA/因子注册/登出/me)
  → URL 规则(deny→403)
  → 认证门：站点需认证 且 非豁免路径
        ├─ 有有效会话 且 用户被该站点允许 且 MFA 级别满足 → 注入 X-VSP-User 头 → 放行
        ├─ 无会话            → 浏览器: 302 /__auth/login?next=…（HTML）
        │                       API/XHR : 401 {"error":"unauthenticated"}
        └─ 会话在但 MFA 级别不足/策略已变 → 302/401 reason=reauth_required（补 MFA 或重登）
  → upstream_peer（上游）
```

---

## 3. 总体架构

```
                        ┌──────────────────────── 代理服务 :8880 ───────────────────────┐
 浏览器/API ───────────► │ request_filter                                                │
                        │  ① find_site           ② URL 规则                              │
                        │  ③ 认证门 gate.rs ──► session.rs（内存会话表, ArcSwap<HashMap>） │
                        │       │ 需要登录/MFA      用户表快照 ◄─ store.rs（SQLite 只读）  │
                        │       ▼                                                        │
                        │  /__auth/* api.rs ──► identity.rs ──► 本地用户(auth.db)         │
                        │       │                  │            LDAP provider (ldap3,    │
                        │       │                  │            TTL 缓存, fail 可配)      │
                        │       ▼                                                        │
                        │  mfa.rs：totp.rs 校验(TOTP) / webauthn.rs 校验(passkey)        │
                        │  ④ upstream_peer（注入 X-VSP-User / X-VSP-Groups）              │
                        └────────────────────────────────────────────────────────────────┘
 后台服务新增： vsp-auth-evaluator（60s：LDAP 再校验 + 过期会话清扫 + 登录失败锁定清理）
 配置三件套：   auth.yaml（认证配置+LDAP，ArcSwap 热加载）  auth.db（用户/因子，SQLite）
               sites.yaml（站点 + 每站点 auth 访问控制段）
 管理端 :8890 新增 API： /api/users /api/auth/config /api/sessions  +  UI 新页签「用户」「认证」
 审计： logs/auth.jsonl（全部认证事件） + audit.jsonl（管理端操作）
```

新增 Rust 模块（`src/auth/`）：

| 模块 | 职责 |
|------|------|
| `auth/mod.rs` | `AuthState`（`ArcSwap<AuthConf>` + `ArcSwap<UserTable>` 快照 + `SessionStore` + `WebAuthn` 句柄），`AppState` 持有 |
| `auth/store.rs` | **SQLite 访问层**（`auth.db`）：建表、CRUD、单写者 `Mutex<Connection>`；写后重建 `UserTable` 内存快照 |
| `auth/identity.rs` | 统一身份模型 `AuthUser`；本地用户密码校验（argon2id）；LDAP 用户 = LDAP 缓存 + DB override 合并 |
| `auth/ldap.rs` | ldap3 异步客户端：bind 校验 + 用户搜索 + 组反向搜索 + 属性映射 + TTL 缓存 + fail 模式 |
| `auth/mfa.rs` | MFA 调度：因子状态判定（need_mfa / enroll_required / pass）、TOTP 校验、pending 状态管理 |
| `auth/totp.rs` | TOTP 生成/校验/重置（`totp-rs`，含 otpauth URI 与二维码 PNG） |
| `auth/webauthn.rs` | WebAuthn 仪式（注册开始/完成、认证开始/完成）、challenge 一次性管理、凭据读写 `auth.db` |
| `auth/session.rs` | 会话表（内存，ArcSwap<HashMap<token_hash, SessionEntry>>）、签发/校验/吊销、空闲与绝对超时 |
| `auth/gate.rs` | 代理门逻辑：判定 需要认证? 豁免? 会话有效? 站点 ACL? MFA 级别? → 放行/302/401 |
| `auth/api.rs` | 8880 上 `/__auth/*` 内联路由（登录、MFA、因子注册、登出、me）+ 登录页 HTML 服务 |
| `auth/page.rs` | 终端用户登录页（内嵌 HTML，风格对齐管理端，含 TOTP 扫码与 passkey JS） |
| `auth/ratelimit.rs` | 登录限流/锁定（per username+IP 内存令牌桶） |

新增依赖（Cargo.toml）：

| crate | 版本 | 用途 | 说明 |
|-------|------|------|------|
| `ldap3` | 0.12.x | LDAP 异步客户端 | tokio 生态，simple bind；startTLS/ldaps 支持 |
| `webauthn-rs` + `webauthn-rs-types` | 0.6.2 | FIDO2/passkey | kanidm 维护，MPL-2.0，MSRV 1.89；凭据存 `auth.db` 的 passkey 表 |
| `totp-rs` | 6.0.0 | TOTP（RFC 6238） | MIT，MSRV 1.88；features：`gen_secret`、`otpauth`、`qr`（服务端生成二维码 PNG） |
| `sha2` | 0.10 | 会话 token 哈希 | 内存表只存 sha256(token) |

（`jsonwebtoken`/`argon2`/`arc-swap`/`chrono`/`rusqlite` 已有。终端用户会话**不复用管理端 JWT**：用随机不透明 token + 有状态会话表，以获得吊销能力——零信任要求可即时踢人。）

---

## 4. 身份层设计

### 4.1 统一身份模型（运行时合并视图）

```rust
pub struct AuthUser {
    pub subject: String,      // "local:xieyun" 或 "ldap:xieyun"（全局唯一，会话/ACL 用它）
    pub username: String,     // 登录名
    pub display_name: String, // 本地=display_name；LDAP=displayName 或回退 cn；override 可覆盖
    pub source: Source,       // Local | Ldap
    pub groups: Vec<String>,  // 本地=auth.db 中 groups；LDAP=LDAP 组 ∪ override.extra_groups
    pub enabled: bool,        // LDAP 用户 = LDAP 可登录 ∧ override.enabled
    pub mfa_required: bool,   // 按人配置，默认 false（后台可开）
    pub totp_secret: Option<String>,
    pub passkeys: Vec<PasskeyCredential>,
}
```

**因子与 LDAP 用户**：MFA 因子属于"人"而非"来源"。LDAP 用户也可拥有 TOTP/passkey，其策略与因子存 `auth.db`（override 表 + passkey 表），**不写回 LDAP**。

### 4.2 本地手动用户（存 `auth.db`）

- 由管理端 UI 维护：新增、重置密码（重置后该用户全部会话立即吊销）、启用/禁用（禁用后立即吊销其会话）、改组、**切换 MFA 开关**、重置 TOTP、删除 passkey。
- 密码：argon2id（复用 `AdminConf::generate_password_hash`）。
- 数据模型见 §8.2。

### 4.3 LDAP 提供方

- 配置（**`auth.yaml` 的 `ldap` 段**，见 §8.1，已按实测填默认值）：
  - `uri: "ldap://192.168.209.101:389"`（生产建议 `ldaps://192.168.209.101:636`，389 无 startTLS）
  - `bind_dn: "cn=admin,dc=ainanjing,dc=org,dc=cn"`（**建议后续换只读服务账号**）
  - `user_search_base: "ou=People,dc=ainanjing,dc=org,dc=cn"`
  - `user_search_filter: "(uid={username})"`
  - 属性映射：`attr_login: uid`、`attr_name: displayName`（空则回退 `cn`）、`attr_mail: mail`
  - `group_search_base: "ou=Groups,dc=ainanjing,dc=org,dc=cn"`
  - `cache_ttl_seconds: 300`、`timeout_ms: 5000`、`fail_mode: stale`
- 登录校验流程（simple bind，**不落地 LDAP 密码**）：
  1. 服务账号 bind；
  2. 按 `user_search_filter` 搜索用户 DN（`cn=xieyun,ou=People,…`）；
  3. 用 `用户DN + 用户密码` 再 bind 一次——成功即认证通过（LDAP 侧账户禁用/密码错误均在此步失败，天然防枚举：失败统一返回"用户名或密码错误"）；
  4. 服务账号重新读取用户属性 + **组反向搜索**：
     ```
     base=ou=Groups,dc=ainanjing,dc=org,dc=cn
     filter=(|(uniqueMember=<userDN>)(member=<userDN>))
     attrs=cn
     ```
     目录中组很少（当前 3 个），单条搜索即可取回全部所属组（`IIIS`/`Global`/`Turing` 等），无 memberOf 也无妨；结果连同用户属性写入 TTL 缓存。
- 缓存与持续评估：
  - 缓存命中（TTL 内）→ 每请求 O(1) 校验，不打 LDAP；
  - TTL 过期 → 热路径按**旧值放行**并标记待刷新；后台任务 `vsp-auth-evaluator`（60s）异步再校验（重新搜索用户 + 组，检查是否仍存在/可 bind）；
  - 再校验发现用户被删/禁用/移出关键组 → **立即吊销其全部会话**（组变化则按新组在下次请求 ACL 判定中自然拒绝）；
  - LDAP 不可达：`fail_mode: stale`（默认，可用性优先，记 error 日志）或 `deny`（严格模式，LDAP 用户一律拒绝，本地用户不受影响）。

### 4.4 查找顺序与冲突

`auth.providers_order: [local, ldap]`（可配置）。同名用户名：local 命中即返回；LDAP 用户 subject 带 `ldap:` 前缀，与本地永不冲突。LDAP 用户即使没在 `auth.db` 建过 override，也自动出现在用户管理列表中（来源=ldap，组来自 LDAP 缓存）。

---

## 5. MFA 设计（TOTP + passkey，按人开启、默认关）

### 5.1 因子定义

| 因子 | 形态 | 实现 | 移动端体验 |
|------|------|------|-----------|
| **TOTP** | Authenticator App 6 位验证码（RFC 6238，HMAC-SHA1，30s，±1 窗口） | `totp-rs`（`gen_secret`/`otpauth`/`qr`） | 手机 App 看码输码 |
| **passkey** | WebAuthn 平台认证器（生物认证） | `webauthn-rs` 0.6.2 | **指纹 / Touch ID / Face ID** 一次按压，`userVerification: "required"` |

两者地位对等，均为"加强"因子；**开启 MFA 后任一因子通过即满足第二因子要求**（可两者都注册，登录时任选一种）。每个用户是否强制 MFA 由后台**逐人开关**（`mfa_required`，默认关）。

### 5.2 开关与强制首次注册（状态机）

按用户 `mfa_required`（后台逐人切换，默认 `false`）。登录（第一因子通过：本地密码 / LDAP bind）后：

```
第一因子通过
  ├─ mfa_required = false ──────────────────────────► 签发正式会话(auth_level=password)
  └─ mfa_required = true
        ├─ 已有 ≥1 个因子（totp 或 passkey 任一）
        │     → 200 {need_mfa:true, mfa_token}（pending，TTL 5min）
        │     → 用户提交 TOTP 码 或 passkey 断言，任一校验通过
        │       → 签发正式会话(auth_level=password+totp / password+passkey)
        └─ 无任何因子（首次开启后的第一次登录）
              → 200 {enroll_required:true, enroll_token}（TTL 10min，锁定该用户）
              → 强制进入注册页：【绑定 TOTP】(显示二维码+输一次验证码确认)
                                   或【注册 Passkey】(指纹/人脸仪式)
              → 完成任一注册 → 签发正式会话
              → 期间直接访问代理内容一律拒绝；enroll_token 过期/取消 → 回到密码登录
```

要点：
- **强制注册不可跳过**：`enroll_required` 状态下访问任何受保护内容 → 302 回注册页；这是"开启 MFA 即必须有因子"的零信任闭环。
- pending 状态（mfa/enroll token）存内存 `MfaPendingMap`（一次性，TTL 过期自动清；每个 username 同一时刻只有一个 pending）。
- TOTP 校验：30s 周期、±1 步窗口，防同窗口重放（校验通过才签发会话，攻击窗口极小）；重置 TOTP 时生成新 20 字节密钥（base32），旧密钥立即作废。
- passkey 安全细节：challenge 一次性（TTL 5min，绑定用户+origin）；origin 严格白名单校验；`rp_id` 与访问域名一致（外层 HTTPS 域名，可配多域名白名单）；签名计数器单调递增；每用户允许多 passkey（多设备），管理端/本人可单独删除。
- 降级安全：用户**只剩一个因子时删除该因子** → `mfa_required` 自动置回 false（避免把用户锁死在无因子且强制 MFA 的状态）；管理端强制删除时可配置"保留强制"（用户将进入 enroll_required 直到注册新因子）。

### 5.3 会话 MFA 级别与"持续评估"联动

- 会话记录 `auth_level`（password / password+totp / password+passkey）。
- 用户当前 `mfa_required=true` 但会话 `auth_level=password`（例如开 MFA 前登录的存量会话）→ gate 判定 `reauth_required`：浏览器 302 到 `/__auth/mfa?next=…`（**免重输密码**，直接补做 MFA 因子即可恢复）；API 返回 401 `reauth_required`。
- 因子被删/重置 → 该用户会话中已失效因子的 `auth_level` 不满足 → 同上补 MFA 或重登。

---

## 6. 会话与"不重复认证"（持续评估）

### 6.1 会话模型

- 第二因子（或无需 MFA 时的第一因子）通过后，签发 **32 字节随机不透明 token**：
  - 浏览器：`Set-Cookie: vsp_session=<token>; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=<idle_timeout>`（外层已 HTTPS，恒带 Secure）。Cookie 作用于**所有代理域名** → 一次登录，所有启用认证的站点免登（SSO）。
  - API 客户端：响应体 `{token}`，后续 `Authorization: Bearer <token>`。
- 服务端会话表（`SessionStore`，**内存**，不落库）：

```rust
pub struct SessionEntry {
    subject: String,
    username: String,
    source: Source,
    groups: Vec<String>,       // 签发时快照（LDAP 组随 TTL 刷新后更新快照）
    auth_level: AuthLevel,     // Password | PasswordTotp | PasswordPasskey
    ip: String,
    issued_at: i64,
    last_active_at: i64,       // 每请求刷新（idle 计时）
}
// key = sha256(token)；ArcSwap<HashMap> 读无锁，写走锁后整体换 Arc
```

### 6.2 超时策略（均可配，`auth.yaml` 的 `session` 段）

| 参数 | 默认 | 语义 |
|------|------|------|
| `idle_timeout_secs` | 28800（8h） | 无请求超过此时长 → 会话过期（下次请求要求完整登录） |
| `absolute_timeout_secs` | 30d | 自签发起无论如何必须重登（零信任硬上限） |
| `max_sessions_per_user` | 5 | 超出则淘汰最旧会话 |
| `reauth_idle_secs` | 1800 | 空闲重验证阈值（P3e+ 新增）：空闲超过该值但未达空闲超时 → **免密码**、仅 passkey/TOTP 二次验证即可续用会话；`0` = 关闭；生效值自动收敛到「空闲超时 − 60s」，保证先触发重验证而非会话直接过期 |

### 6.3 持续评估（不重复认证 ≠ 永不复查）

**每请求 O(1) 校验**（gate 内，无网络 IO、无锁竞争）：
1. token 存在且未超 idle/absolute 超时（`last_active_at` 顺手刷新）；
2. 用户仍 `enabled`（本地：读 `UserTable` 内存快照；LDAP：读 TTL 缓存 + override）；
3. 站点 ACL 仍允许（§7.2：`allowed_users` ∪ `allowed_groups` 与用户比对——本地用户/策略变更经 DB 写后快照热更即时生效，LDAP 组随 TTL 刷新）;
4. 会话 `auth_level` 满足该用户当前 `mfa_required`（不满足 → `reauth_required` 补因子，§5.3）。

**事件驱动吊销**（即时生效，走管理端 API，写 DB 时同事务标记）：
- 重置密码 / 禁用用户 / 重置 TOTP / 删除最后一个 passkey → 该 subject 全部会话立即删除（或降级为 reauth 状态，见 §5.2）。
- LDAP 用户被删除/禁用（evaluator 发现）→ 立即吊销。

**后台任务 `vsp-auth-evaluator`（60s 周期）**：
- 对缓存过期的 LDAP 活跃用户：重新搜索用户+组（异步、带超时；不可达按 `fail_mode` 处理）；
- 发现禁用/删除 → 吊销会话；组变化 → 更新会话快照（下次请求 ACL 判定即时生效）；
- 清扫过期会话与过期 pending token；清理登录失败计数器（解锁）。

**配置变更**：`auth.yaml` / `sites.yaml` 经既有 `ConfigWatcher` 热加载；`auth.db` 变更由管理端写后**即时**重建内存快照（`UserTable` ArcSwap），无需文件监听。

### 6.4 会话持久化

会话在内存：进程重启/`--upgrade` 后全部会话失效 → 用户重新登录一次。**这是可接受行为**（安全保守、实现简单、零状态运维）；不引入文件/DB 持久化（避免 token 泄露面与清理复杂度）。

---

## 7. 认证门（gate）细节

### 7.1 判定顺序（`request_filter` 内，站点命中后）

```
if !site_auth_enabled(site, global_cfg)            → 放行（现状行为，向后兼容）
if glob_match(site.auth.exempt_paths, path)        → 放行（如 /health*、/static/*）
if path.starts_with("/__auth/")                     → 交 /__auth 内联路由
session = session_store.verify(token, user, site)
  Ok(Active)             → 注入 X-VSP-User/X-VSP-Groups/X-VSP-Auth-Level → 放行上游
  Ok(ReauthNeeded)       → 浏览器: 302 /__auth/mfa?next=…；API: 401 {error:"reauth_required"}
  Err(Expired|Missing)   → 浏览器: 302 /__auth/login?next=<path>；API: 401 {error:"unauthenticated"}
```

- 浏览器判定：`Accept` 含 `text/html` 且非 `X-Requested-With: fetch`。
- **空闲重验证**（P3e+）：会话未过期但 `last_active` 空闲超过 `reauth_idle_secs`（默认 1800s，0=关闭，生效值 ≤ 空闲超时−60s）且用户持有 TOTP/passkey 凭据 → 视同 `ReauthNeeded`（审计 `reauth_required reason=idle`），免密码补因子成功后 `touch` 重置空闲计时续用会话；无二次验证凭据 → 会话直接失效（审计 `session_expired_idle`）。判定与 `/__auth/mfa*` 入口均走 `peek`（只校验、不刷新空闲计时），打开 MFA 页本身不会"复活"空闲过期会话。
- 上游注入头（开关 `auth.inject_upstream_headers`，默认开）：`X-VSP-User`、`X-VSP-Source`、`X-VSP-Groups`（逗号分隔）、`X-VSP-Auth-Level`——上游应用可据此做二级授权。**入口先剥离客户端伪造的 `X-VSP-*` 头再注入**，防 header injection。

### 7.2 站点级访问控制（`sites.yaml` 每站点新增，按域名配置）

```yaml
- id: 3
  name: 财务系统
  domains: ["fin.example.com"]
  upstream: 10.0.0.5:8080
  upstream_host: fin.internal.example.com   # 可选：转发时改写 Host/Origin
  auth:
    enabled: true            # 缺省 = 跟随全局 auth.enabled
    exempt_paths:            # 复用 glob.rs
      - "/health*"
      - "/static/*"
    allowed_users: []        # 按人勾选（username 列表）
    allowed_groups: []       # 按组勾选（本地组名 或 LDAP 组名，如 Turing/IIIS）
```

- **放行规则 = `allowed_users` 命中 ∪ `allowed_groups` 命中其一**；两者皆空 = **谁都不允许**（认证开启且名单皆空时，所有登录用户一律 403 并记入审计）。
- `upstream_host`（P3e+ 新增）：非空时转发到上游前改写 `Host` 头；请求带 `Origin` 头时同步改写为 `{upstream_scheme}://{upstream_host}`。用于上游按 Host 鉴权、或反代隧道/内网地址与对外域名不一致的场景（线上站点 901 配 `192.168.202.87:3080`）；缺省/空串 = 透传浏览器原始 Host。管理端站点弹窗「上游 Host 头」字段可改。
- `enabled` 缺省跟随全局 `auth.enabled`（文件级默认 false）；管理端不暴露全局开关，站点上只有「启用/禁用认证」。
- LDAP 组名（Turing 等）与本地组名同池匹配，LDAP 用户的组来自反向搜索缓存。

### 7.3 终端用户认证 API（8880，`/__auth/*`，内联处理）

| 方法/路径 | 说明 |
|-----------|------|
| `GET /__auth/login?next=…` | 登录页（内嵌 HTML：账号密码；已有因子时显示"使用 TOTP / Passkey 继续"） |
| `GET /__auth/mfa?token=…&next=…` | MFA 页，四种模式自动判定：`verify`（密码后待因子，带一次性 token，无注册入口）/ `reauth`（空闲重验证，凭会话 Cookie，免密码）/ `enroll`（零因子强制注册）/ `manage`（已登录安全设置：TOTP 绑定·重置、passkey 列表·添加·删除） |
| `POST /__auth/login` | `{username, password}` → 无 MFA：200 `{token}` + Set-Cookie；需 MFA：`{need_mfa, mfa_token}`；开启但无因子：`{enroll_required, enroll_token}` |
| `GET /__auth/enroll?next=…` | 强制/自助因子注册页（TOTP 二维码 or Passkey 二选一） |
| `POST /__auth/mfa/totp` | `{token, code}` → TOTP 校验 → 签发会话 |
| `POST /__auth/mfa/passkey` | `{token, credential}`（navigator.credentials.get 结果）→ 校验 → 签发会话 |
| `GET /__auth/totp/setup` | 返回 `{secret(base32), otpauth_uri, qr_png(base64)}`（enroll_token/登录态） |
| `POST /__auth/totp/setup/finish` | `{token, code}` 验证第一个码 → 保存密钥到 auth.db，完成注册 |
| `GET /__auth/passkey/register/begin` | 返回 WebAuthn `publicKey` 选项 JSON（enroll_token/登录态） |
| `POST /__auth/passkey/register/finish` | `{token, credential}` → 校验入库（auth.db），完成注册 |
| `DELETE /__auth/passkey/{credential_id}` | 本人删除自己的 passkey（登录态；删最后一个时 §5.2 降级规则生效） |
| `GET /__auth/me` | 当前会话用户信息（subject/display_name/groups/auth_level/factors） |
| `POST /__auth/logout` | 吊销当前会话 |

### 7.4 审计

`logs/auth.jsonl` 逐事件一行：`login_success / login_failed(bad_password|user_not_found|user_disabled|ratelimited) / mfa_ok / mfa_fail / enroll_start / enroll_done / totp_register / totp_reset / passkey_register / passkey_delete / session_issued / session_expired / session_revoked / reauth_required / gate_denied`，字段：`ts, subject, username, source, ip, site, path, action, detail`。保留策略复用 `log_cleanup`；管理端"操作日志"页签合并展示。

---

## 8. 配置与存储布局

| 文件 | 存什么 | 维护方式 |
|------|--------|---------|
| `auth.yaml`（新） | 认证**配置**：主开关、provider 顺序、会话策略、WebAuthn、**LDAP 参数**、限流 | 原子写 + ArcSwap 热加载（ConfigWatcher 顺带监听），权限 600（内含 LDAP 服务账号口令） |
| `auth.db`（新，SQLite） | 认证**用户与因子**：本地用户、LDAP override、passkey 凭据 | 仅管理端 API 写（单写者）；启动时建表；随 /opt/ventositeproxy 备份 |
| `sites.yaml`（既有） | 站点/数据流 + **每站点 auth 访问控制段**（§7.2） | 现状机制不变 |
| `admin.yaml`（既有） | 管理端账号 | 不动，与认证用户完全隔离 |
| `ventsitemproxy.yaml`（既有） | 服务端自身配置 | 新增 `auth_file`、`auth_db` 两个路径字段（serde default，兼容旧文件） |

### 8.1 `auth.yaml`（认证配置，LDAP 在此配置）

```yaml
version: 1
auth:
  enabled: false                 # 全局主开关（默认 false → 向后兼容；开启后所有站点默认需认证）
  providers_order: [local, ldap]
  inject_upstream_headers: true
  session:
    idle_timeout: "8h"
    absolute_timeout: "30d"
    max_sessions_per_user: 5
    cookie_name: vsp_session
  webauthn:
    rp_name: "VentoSiteProxy"
    rp_id: ""                    # 留空 = 取请求 Host；建议显式配外层 HTTPS 域名（多域名逗号分隔）
    origins: []                  # 显式 origin 白名单，留空 = 按 Host 派生 https://<host>
  ldap:
    enabled: true
    uri: "ldap://192.168.209.101:389"      # 默认 389（用户确认）；管理端页面可改 ldaps://…:636
    bind_dn: "cn=admin,dc=ainanjing,dc=org,dc=cn"   # 本期确认；后续可换只读服务账号
    bind_password: "<仅存于此文件，禁止入库入文档入日志>"
    user_search_base: "ou=People,dc=ainanjing,dc=org,dc=cn"
    user_search_filter: "(uid={username})"
    attr_login: "uid"
    attr_name: "displayName"      # 空值回退 cn
    group_search_base: "ou=Groups,dc=ainanjing,dc=org,dc=cn"
    group_attrs: ["uniqueMember", "member"]
    cache_ttl_seconds: 300
    timeout_ms: 5000
    fail_mode: stale             # stale | deny
  ratelimit:
    max_failed: 5
    window_seconds: 600
    lockout_seconds: 900
```

### 8.2 `auth.db`（SQLite 表结构）

```sql
-- 本地手动用户（source=local）
CREATE TABLE IF NOT EXISTS auth_users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT,
  password_hash TEXT NOT NULL,                 -- argon2id PHC
  groups        TEXT NOT NULL DEFAULT '[]',    -- JSON 数组，如 ["ops","Turing"]
  enabled       INTEGER NOT NULL DEFAULT 1,
  mfa_required  INTEGER NOT NULL DEFAULT 0,    -- 按人 MFA 开关，默认关
  totp_secret   TEXT,                          -- base32；未绑定为 NULL
  created_at    TEXT, updated_at TEXT
);

-- LDAP 用户的本地策略/因子（不写回 LDAP）
CREATE TABLE IF NOT EXISTS auth_ldap_overrides (
  username      TEXT PRIMARY KEY,              -- LDAP 侧登录名
  display_name  TEXT,                          -- NULL = 用 LDAP 侧值
  enabled       INTEGER NOT NULL DEFAULT 1,    -- 本地禁用（不影响 LDAP 侧）
  mfa_required  INTEGER NOT NULL DEFAULT 0,
  extra_groups  TEXT NOT NULL DEFAULT '[]',    -- JSON 数组，叠加在 LDAP 组之上
  totp_secret   TEXT,
  updated_at    TEXT
);

-- passkey 凭据（本地/LDAP 用户通用，按 username 关联）
CREATE TABLE IF NOT EXISTS auth_passkeys (
  credential_id TEXT PRIMARY KEY,              -- base64url
  username      TEXT NOT NULL,
  name          TEXT,                          -- 用户自取名，如"手机指纹"
  public_key    BLOB,
  rp_id         TEXT,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON auth_passkeys(username);
```

- 写入纪律：所有写操作走 `store.rs` 单写者（`Mutex<Connection>`），事务提交后**立即**重建 `UserTable` 内存快照（`ArcSwap` 换 Arc），热路径零锁读。
- `UserTable` 快照 = `HashMap<username, AuthUserView>`（本地用户全量 + override 全量 + passkey 列表）；LDAP 基础信息不进快照（走 LDAP TTL 缓存），避免两套数据打架。

### 8.3 `ventsitemproxy.yaml` 新增

```yaml
auth_file: /opt/ventositeproxy/auth.yaml
auth_db: /opt/ventositeproxy/auth.db
```

（均有 serde default；`auth.yaml` 缺失或 `auth.enabled=false` 时行为与现状完全一致。）

---

## 9. 管理端 API（8890，admin JWT 保护）

| 方法/路径 | 说明 |
|-----------|------|
| `GET /api/auth` | 读取认证配置（bind_password 打码 `******`） |
| `PUT /api/auth` | 更新认证配置（会话/WebAuthn/LDAP/限流/上游头注入）；原子落盘 + 热加载。全局主开关不在管理端暴露（auth.yaml 文件级默认） |
| `POST /api/auth/test-connection` | 用当前 LDAP 配置做 bind + 搜索样例用户 + 组反查 → 返回连通性、样例条目、延迟（配置界面"测试连接"） |
| `POST /api/auth/ldap-sync` | 把 LDAP 用户批量导入本地用户库（只增人；不改已有用户密码/启停；组取并集） |
| `GET /api/auth/groups` | ACL 候选组列表（本地组 + LDAP 缓存组） |
| `GET /api/users` | 合并视图：本地用户（auth.db）+ LDAP 用户（缓存）+ override；字段含来源、组、mfa_required、因子状态（totp ✓ / passkey ×N）、启用态 |
| `POST /api/users` | 新增本地用户（username/display_name/初始密码/组/**mfa_required**） |
| `PUT /api/users/{username}` | 更新（显示名/组/**mfa_required 开关**/enabled）；LDAP 用户写 override |
| `DELETE /api/users/{username}` | 删除本地用户（或清 override + 其因子），同时吊销其会话 |
| `POST /api/users/{username}/reset-password` | 重置（仅本地；吊销其会话） |
| `POST /api/users/{username}/totp/reset` | 重置 TOTP：生成新密钥，返回 `{secret, otpauth_uri, qr_png}`，旧密钥作废 |
| `DELETE /api/users/{username}/passkey/{credential_id}` | 管理端删除用户某 passkey（触发 §5.2 降级/补 MFA 规则） |
| `GET /api/sessions` | 活跃会话列表（subject/ip/issued_at/last_active/auth_level） |
| `DELETE /api/sessions/{id}` | 强制下线单个会话 |
| `DELETE /api/sessions?subject=…` | 强制下线某人全部会话 |

所有写操作：`mutate_lock` 内完成"DB 事务 → 快照重建 → 事件吊销 → audit.jsonl 记录"。

---

## 10. 管理端 UI（web/index.html 增量）

- 新页签 **「用户」**（数据来自 `/api/users`，本地 + LDAP 合并展示）：
  - 用户表：用户名 / 显示名 / **来源(local|ldap)** / 组 / **MFA 开关（逐人勾选）** / 因子状态（TOTP ✓、passkey ×N）/ 启用开关 / 操作列（编辑、重置密码、重置 TOTP【弹二维码模态框】、删除 passkey、强制下线、删除）；
  - 新建本地用户模态框（与站点模态框同风格）；LDAP 用户行不提供"重置密码"（密码在 LDAP 侧）。
  - 会话子区：活跃会话表 + "强制下线"。
- 新页签 **「认证」**：
  - 全局主开关、`providers_order`；
  - 会话策略（idle/absolute/每用户上限）；
  - WebAuthn（rp_name、rp_id、origin 白名单）；
  - **LDAP 表单**（uri/bind_dn/bind_password 打码回填/搜索基/过滤/属性/缓存 TTL/fail_mode）+ **"测试连接"**（显示样例用户与组反查结果）；
  - 限流参数。
- **站点编辑模态框**增加「访问控制」区块（按域名配置）：
  - 启用认证开关（缺省跟随全局）；
  - **允许用户**：checkbox 列表（本地 + LDAP 全量，带搜索过滤）；
  - **允许组**：checkbox 列表（本地组 ∪ LDAP 组：Turing/IIIS/Global…）；
  - 豁免路径（tag 输入）。
- **操作日志**页签：合并展示 audit.jsonl（管理操作）与 auth.jsonl（终端认证事件）。

**终端用户登录页**（`web/login.html`，`include_str!` 内嵌，8880 `/__auth/login` 返回）：
- 与管理端同风格单文件；表单：用户名、密码、[登录]；
- `need_mfa` 分支：输入 TOTP 6 位码 [确认] 或 [使用 Passkey]（`navigator.credentials.get`，移动端弹指纹/人脸）；
- `enroll_required` 分支：强制注册页，两个卡片【绑定 TOTP】（服务端生成二维码 PNG，扫码后输码确认）/【注册 Passkey】（指纹/人脸仪式）；
- 错误提示统一（不区分"用户不存在/密码错"）。

---

## 11. 部署与安全前提

1. **HTTPS（已确认）**：外层 frp 链路提供 TLS（192.168.211.223:443 开放），passkey secure context 满足。**`rp_id` 与 `origins` 不预配**（用户确认）：全部在管理端「认证」页配置，默认按请求 Host 派生（`https://<host>`），支持多域名逗号分隔，frp 域名变更时改页面即可。
2. **LDAP 链路**：默认 `ldap://192.168.209.101:389`（用户确认）；389 无 startTLS，uri 在管理端页面可自配（生产可改 `ldaps://…:636`，端口已开放）。**本期服务账号用 `cn=admin`（用户确认）**，后续可换只读账号（仅需 People/Groups 的 read）。
3. **LDAP 口令管理**：仅存部署机 `/opt/ventositeproxy/auth.yaml`（chmod 600）；不进代码、文档、仓库、日志、审计。
4. **防 Header Injection**：入口剥离客户端 `X-VSP-*` 头后再注入（§7.1）。
5. **TCP 数据流（MQTT 等）不在本期范围**：认证门是 HTTP 层能力；TCP 透传无身份概念，依赖上游自身鉴权。README 注明。
6. **升级兼容**：`auth.yaml`/`auth.db` 缺失或 `auth.enabled=false` 时行为与现状完全一致（现有部署零影响）；所有新字段 serde `default`，旧 `sites.yaml` 直接兼容。
7. **备份**：`auth.db`、`auth.yaml`、`sites.yaml`、`admin.yaml` 同属 `/opt/ventositeproxy/` 备份范围；`auth.db` 建议纳入现有备份脚本（sqlite 在线备份用 `.backup` 或 VACUUM INTO，避免拷半截文件）。
8. **单实例前提**：会话/pending/限流均在内存，当前单实例部署无影响；未来双实例需共享存储（预留 trait）。

---

## 12. 实施计划（分四期，每期可独立验收）

| 期 | 内容 | 交付标准 |
|----|------|---------|
| **P1 核心闭环**（本地用户） | `auth.yaml`/`auth.db` 模型与加载、`store.rs` SQLite 层、本地用户密码登录、会话表 + Cookie/Bearer、代理 gate（302/401/豁免路径/站点 ACL/上游头注入）、登录页、`/__auth/*` API、auth.jsonl 审计、限流 | 开 `auth.enabled` 后未登录访问代理站点 → 登录页；登录后跨站点免登；idle 超时重登；禁用用户立即失效；按站点勾选用户/组后未勾者 401；`cargo test` 覆盖 gate 判定/会话超时/glob 豁免/store CRUD |
| **P2 LDAP** | ldap3 provider（bind 校验/属性映射/组反查/TTL 缓存/fail_mode）、LDAP 配置 UI + 测试连接、evaluator 任务、override 合并 | 对 192.168.209.101 完成登录、Turing/IIIS 组 ACL 生效、TTL 过期再校验、断网 fail_mode 验证 |
| **P3 MFA** | TOTP（生成/校验/重置/二维码）+ passkey（webauthn-rs 注册/认证/多设备管理）、pending 状态机、enroll 强制注册流、reauth 补因子流 | 手机注册 passkey 指纹登录通过；TOTP 扫码绑定+验码通过；开 MFA 无因子用户被强制注册；`uv` 缺失拒绝；挑战重放失败；删最后一因子自动降级 |
| **P4 打磨** | 会话管理 UI（强制下线）、auth.jsonl 进操作日志页、站点编辑框用户/组勾选交互、限流参数 UI、文档/README、压测（gate 路径 P99 开销 < 1ms）、部署（auth.db/auth.yaml 落盘 600、rp_id 配置、备份脚本加 auth.db） | 全部管理端可视化；README 增"零信任"章节与部署 checklist（HTTPS/rp_id/LDAP 636） |

估算：P1 ~1300 行 Rust（含 store.rs）+ 登录页 ~300 行；P2 ~350 行；P3 ~500 行（含登录页 MFA/enroll 流程）；P4 ~200 行 + 管理端 UI ~800 行 JS/HTML。

---

## 13. 风险与开放问题

| # | 问题 | 状态 |
|---|------|------|
| Q1 | 外层 HTTPS 域名（passkey 的 `rp_id`/`origins`） | ✅ 已确认（用户）：不预配，管理端页面自配，默认按 Host 派生，支持多域名 |
| Q2 | LDAP 服务器参数 | ✅ 已实测确认（§0）；**本期 bind 用 cn=admin（用户确认）**，后续可换只读服务账号 |
| Q3 | 管理端（8890）是否接入同一身份体系 | 本期不动 admin.yaml，保持独立（管控面/数据面隔离）；后续可让管理端也走 LDAP |
| Q4 | LDAP 走 389 明文还是 636 ldaps | ✅ 已确认（用户）：默认 389，uri 在管理端页面自配（可改 636） |
| Q5 | MFA 强制范围 | ✅ 已确认：按人配置、默认关、开启后强制注册因子（TOTP/passkey 二选一） |
| Q6 | 上游应用是否消费 `X-VSP-*` 头 | 默认注入；如需改头名/关闭可配 |

---

## 14. 附：与现有代码的改动面清单

| 文件 | 改动 |
|------|------|
| `Cargo.toml` | +ldap3、webauthn-rs、webauthn-rs-types、totp-rs、sha2（rusqlite 已有） |
| `src/main.rs` | `mod auth`；run 时加载 auth.yaml + 打开 auth.db（建表）；AppState 注入 AuthState；新增 `vsp-auth-evaluator` 后台服务；ConfigWatcher 扩展监听 auth.yaml |
| `src/config.rs` | `MainConf` +`auth_file`/`auth_db`；新增 `AuthConf/LdapConf/SessionConf/WebAuthnConf/RatelimitConf` 模型 + 加载/原子保存；`Site` 新增 `auth: Option<SiteAuth>`（enabled/exempt_paths/allowed_users/allowed_groups）；`AppState` 持有 `AuthState` |
| `src/auth/*` | 新增模块（§3 表：mod/**store**/identity/ldap/mfa/totp/webauthn/session/gate/api/page/ratelimit） |
| `src/proxy.rs` | `request_filter` 插入 gate 调用 + `/__auth/*` 内联分发；`upstream_peer` 前剥离/注入 `X-VSP-*` 头 |
| `src/admin/api.rs` | 新增 `/api/users` `/api/auth/*` `/api/sessions` 路由（读写 auth.db + auth.yaml） |
| `src/admin/mod.rs` | 导出新路由 |
| `web/index.html` | 新页签「用户」「认证」+ 站点模态框访问控制区块（用户/组 checkbox）+ 日志合并 |
| `web/login.html` | 新增终端登录页（登录/MFA/强制注册，内嵌） |
| `config/`、`deploy/` | 示例 auth.yaml（auth.enabled: false，LDAP 参数已按实测填）、README 部署说明、备份脚本加 auth.db |
| `README.md` | 功能表 + 使用 + API 概览补充 |
