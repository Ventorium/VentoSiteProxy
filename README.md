# VentoSiteProxy

基于 [Pingora](https://github.com/cloudflare/pingora) 的反代网关，替代 Nginx Proxy Manager：
**账号登录 · 反代站点配置 · 启用/禁用 · 操作日志 · 热重载（配置文件同步）**。

## 为什么是 Pingora

NPM 的痛点全部来自 nginx 默认配置，而 Pingora 是原生行为，无需任何 override：

| NPM 问题 | VentoSiteProxy |
|---|---|
| proxy_buffering 卡 SSE | 默认流式转发，无缓冲 |
| client_max_body_size 1m | 无 body 大小限制 |
| 长连接 60s 断开 | 超时 per-site 可配，`0` = 不限 |
| advanced config 复杂 | 配置模型即能力，管理端可视化 |

## 功能

- **站点（HTTP 反代）**：名称 / 备注 / 多域名（含 `*.wildcard`）/ 上游 http(s) / SNI / 证书校验开关 / 连接·读·写超时（秒，0=不限）
- **location 覆盖**：按序匹配 path，命中后覆盖上游（对应 NPM locations，如 `/mqtt*` 独立 broker + 7 天长超时）
- **URL 黑白名单**：按序匹配、首个命中生效
  - 黑名单模式（默认 `url_default: allow`）：`/api/v1/db*` deny 放前面 → `/api/v1/db`、`/api/v1/db/health` 403，其余放行
  - 白名单模式（`url_default: deny`）：只放行列出的 allow 规则
- **每站点访问日志开关**：按站点、按天归档 `logs/access/site-{id}-{slug}-YYYYMMDD.log`（跨天自动换新文件）
- **访问日志自动清理**：默认开启、保留 180 天；后台任务每日按归档日期删除超期文件（旧格式无日期文件按 mtime 判断），「设置」页可开关 / 改保留天数，即时生效
- **可配置默认 404 页面**：请求 Host 未命中任何启用站点时按 `default_404` 响应（管理端「设置」页可改，即时生效）：
  - `status`（默认）只返回 404 状态码 + 最小文本
  - `page` 内置通用 404 页面（不含 Host / 服务名 / 版本，不暴露信息）
  - `custom` 用户目录 `custom_404_dir` 里的 404.html 等文件（支持 css / 图片引用，防目录穿越，状态码恒 404）
- **TCP 数据流**：透传中继（MQTT 等），启用/停用约 1 秒生效
- **管理端**：argon2id 密码 + JWT（HS256，12h）；操作日志（登录 + 全部增删改启停）JSONL
- **热重载**：管理端保存 = ArcSwap 即时生效 + 原子写回 `sites.yaml`；手工改文件 2 秒内自动生效（解析失败保留旧配置）
- **零停机发布**：`--upgrade` 经 upgrade socket 接管旧进程 FD

## 目录布局（部署机）

```
/usr/local/bin/ventositeproxy        二进制
/opt/ventositeproxy/
  ventsitemproxy.yaml                主配置
  sites.yaml                         站点路由表（管理端自动同步）
  admin.yaml                         管理员认证
  upgrade.sock / *.pid
  logs/access/site-*.log             访问日志（按站点、按天归档）
  logs/audit.jsonl                   操作日志
```

监听：代理 `8880`，管理端 `8890`（frp 端口切换指向 8880 即接入）。

## 使用

```bash
# 1. 初始化管理员（生成随机密码）
ventositeproxy init -f admin.yaml

# 2. 从 NPM 迁移
ventositeproxy migrate -d /opt/nginx-proxy-manager/data/database.sqlite -o sites.yaml

# 3. 启动
ventositeproxy run -c ventsitemproxy.yaml

# 改密码
ventositeproxy set-password -f admin.yaml --new-password 'xxxx'
```

systemd：`deploy/ventositeproxy.service`（`systemctl enable --now ventositeproxy`）。

## API 概览（管理端 :8890）

```
POST /api/login                    {username, password} → {token}
GET  /api/me
GET  /api/sites /api/sites/{id}
POST /api/sites                    新建
PUT  /api/sites/{id}               整体更新
DELETE /api/sites/{id}
POST /api/sites/{id}/enable|disable
GET  /api/streams /api/streams/{id}   POST/PUT/DELETE 同上
POST /api/streams/{id}/enable|disable
GET  /api/audit?limit=200
GET  /api/settings           全局设置（默认 404 页面模式 + 日志自动清理）
PUT  /api/settings           {default_404, custom_404_dir?, log_cleanup: {enabled?, retention_days?}}
```

请求头：`Authorization: Bearer <token>`。

## 构建

```bash
cargo build --release      # x86_64 Linux；rusqlite 为 bundled 编译（仅需 cc）
cargo test                 # glob 匹配 / 路由匹配单测
```

release profile：`opt-level=3, lto=true, codegen-units=1, strip=symbols`。
