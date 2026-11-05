---
id: S_01_oidc-login
title: Web 通道 OpenID Connect 登录
type: S
author: Cursor Agent
author_email: cursoragent@cursor.com
modules:
  - jiuwenswarm/common/auth/oidc
  - jiuwenswarm/channels/web
files:
  - jiuwenswarm/common/auth/oidc/config.py
  - jiuwenswarm/common/auth/oidc/protocol.py
  - jiuwenswarm/common/auth/oidc/http_api.py
  - jiuwenswarm/common/auth/oidc/obo.py
  - jiuwenswarm/channels/web/oidc_http.py
  - jiuwenswarm/channels/web/app_web.py
designs: []
design_note: 本次为已授权的实现任务，没有单独的 D 文档。
---

# Web 通道 OpenID Connect 登录

| 项 | 值 |
| --- | --- |
| 类型 | spec |
| 关联模块 | `jiuwenswarm/common/auth/oidc`、`jiuwenswarm/channels/web` |
| 最近一次修订日期 | 2026-11-05 |
| 关联 feature | [F_20261105_1612_oidc-login](../../../../features/F_20261105_1612_oidc-login.md) |

## 范围与边界

本规约约束浏览器用户通过 `jiuwenswarm-web` 使用通用 OpenID Connect 授权码登录。华为账号 Account Kit（`/api/v1/auth/authorize`、`/callback`、`/claim`）不在本规约内，也不得被本路径替换。

未配置时（签发方、客户端 ID、回调地址皆空，且未显式要求开启）登录保持关闭：状态接口报告 `enabled: false`，登录接口返回 404，界面不渲染 SSO 入口，Web 进程不因本功能拒绝本地启动。

显式 `enabled=false` 同样关闭，即使其它字段已填写。

## 不变量

- 配置有效且未强制关闭时，登录使用授权码流程。默认附加 S256 PKCE，可用配置关掉。
- 授权请求包含一次性 `state` 与 `nonce`。回调必须同时匹配服务端暂存值和浏览器上的 `jiuwenswarm_oidc_tx` Cookie。暂存项只用一次，过期或重放均拒绝。
- 登录后的回跳地址必须是以单个 `/` 开头的同源路径。其它值落到 `/`。
- ID 令牌必须通过发现文档 JWKS 的 RS256 或 ES256 验签，并匹配签发方、受众（客户端 ID）、过期时间和 nonce。拒绝 `none` 与 HMAC。提供 `at_hash` 时必须与访问令牌一致。
- 会话 Cookie `jiuwenswarm_oidc` 为 HttpOnly，不含访问令牌。访问令牌只留在 Web 进程内存。注销后该会话标识失效。
- 签发方必须是 `https`，本机回环 `http` 仅用于测试。发现文档里的端点同样限制。
- `required=true` 只在配置已经有效时拦截匿名访问。配置不完整不得把实例锁死。
- 客户端密钥不得出现在授权 URL、状态响应或日志里。

## 接口

浏览器入口（由 Web 静态服务在转发 `/api` 之前处理）：

| 方法 | 路径 | 结果 |
| --- | --- | --- |
| GET | `/api/v1/auth/oidc/status` | 公开状态，不含密钥 |
| GET | `/api/v1/auth/oidc/login` | 302 到发现文档给出的授权端点 |
| GET | `/api/v1/auth/oidc/callback` | 成功后 302 到安全的 `return_to` 并设置会话 Cookie |
| GET | `/api/v1/auth/oidc/session` | 已登录用户；否则 401 |
| POST | `/api/v1/auth/oidc/logout` | 作废会话。仅当配置了登出后回调且发现文档提供结束会话端点时，返回 IdP 登出地址 |

持有有效会话且进程内仍有访问令牌时，Web 服务在代理 `/api` 与 WebSocket 升级时，若客户端未自带 `X-User-Token`，则附加 `Bearer` 形式的该令牌。令牌含控制字符或非 ASCII 时不附加。

`exchange_on_behalf_of` 仅在 `obo_enabled` 且配置有效时按 RFC 8693 向令牌端点换票。默认关闭，工具路径不调用它。ADFS 的 `requested_token_use=on_behalf_of` 不属于本规约。

## 配置

环境变量优先于 `config.yaml` 的 `oidc` 段。字段与环境变量见 [英文说明](../../../../docs/en/OIDC.md) 与 [中文说明](../../../../docs/zh/OIDC.md)。三者（`issuer`、`client_id`、`redirect_uri`）缺一则不得进入登录。
