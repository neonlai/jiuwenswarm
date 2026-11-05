# OpenID Connect 登录

运维可以让浏览器用户走标准 OpenID Connect 授权码登录。首要目标是企业 ADFS，同一套配置也适用于任何发布 `/.well-known/openid-configuration` 的发行方。

签发方、客户端 ID、回调地址都为空时，这条路径不工作。华为账号登录和未登录的本地使用保持原样，界面也不出现 SSO 入口。

## 配置

环境变量优先于 `config.yaml` 里的 `oidc` 段。客户端密钥放在环境变量里，不要写进会提交的配置文件。

| 配置项 | 环境变量 | 打开登录时是否必填 |
| --- | --- | --- |
| `issuer` | `JIUWENSWARM_OIDC_ISSUER` | 是 |
| `client_id` | `JIUWENSWARM_OIDC_CLIENT_ID` | 是 |
| `redirect_uri` | `JIUWENSWARM_OIDC_REDIRECT_URI` | 是 |
| `client_secret` | `JIUWENSWARM_OIDC_CLIENT_SECRET` | 公共客户端可不填。ADFS 的服务器应用通常需要 |
| `scopes` | `JIUWENSWARM_OIDC_SCOPES` | 否。默认 `openid profile email`。缺 `openid` 时会补上 |
| `pkce` | `JIUWENSWARM_OIDC_PKCE` | 否。默认 `true`（S256） |
| `enabled` | `JIUWENSWARM_OIDC_ENABLED` | 否。不设置时，签发方、客户端 ID、回调地址三者齐全即开启。`false` 强制回到原有行为 |
| `required` | `JIUWENSWARM_OIDC_REQUIRED` | 否。默认 `false`。`true` 时未登录的浏览器用户会转到 IdP，且仅在配置有效之后生效 |
| `post_logout_redirect_uri` | `JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI` | 否。仅当发现文档含 `end_session_endpoint` 时使用 |
| `resource` | `JIUWENSWARM_OIDC_RESOURCE` | 否。ADFS 需要资源标识时，会附加到授权和令牌请求 |
| `obo_enabled` | `JIUWENSWARM_OIDC_OBO_ENABLED` | 否。默认 `false`。见下文令牌交换说明 |
| `cookie_secure` | `JIUWENSWARM_OIDC_COOKIE_SECURE` | 否。默认跟随 `https` 回调和 `X-Forwarded-Proto` |
|  | `JIUWENSWARM_OIDC_SESSION_SECRET` | 否。会话 Cookie 的 HMAC 密钥。不设置时，首次登录成功后在数据目录的 `config/oidc_session.key` 生成 |

本地 Web 服务示例：

```bash
export JIUWENSWARM_OIDC_ISSUER=https://adfs.example.com/adfs
export JIUWENSWARM_OIDC_CLIENT_ID=<application-id>
export JIUWENSWARM_OIDC_CLIENT_SECRET=<secret>
export JIUWENSWARM_OIDC_REDIRECT_URI=http://127.0.0.1:5173/api/v1/auth/oidc/callback
export JIUWENSWARM_OIDC_SCOPES="openid profile email"
```

签发方必须是 `https`。测试用的本机 `http`（`localhost`、`127.0.0.1`、`::1`）除外。配置值必须与发现文档里的 `issuer` 一致，末尾最多差一个斜杠。

这些路由由 `jiuwenswarm-web` 在把 `/api` 转到网关之前处理：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/v1/auth/oidc/status` | 未开启时返回 `{enabled:false}` |
| GET | `/api/v1/auth/oidc/login` | 带 `state`、`nonce` 和 PKCE 重定向到 IdP |
| GET | `/api/v1/auth/oidc/callback` | 校验 `state`、交换授权码、写入会话 Cookie |
| GET | `/api/v1/auth/oidc/session` | 当前用户。Cookie 缺失或已注销时 `401` |
| POST | `/api/v1/auth/oidc/logout` | 作废服务端会话并清除 Cookie |

`npm run dev` 会把 `/api` 直接代理到网关，这条开发服务器上看不到上述路由。请用 `jiuwenswarm-web`（`make start-debug` 的 web 进程）验证登录。

## 浏览器侧结果

- `jiuwenswarm_oidc` 是 HttpOnly 会话 Cookie，里面是主体和显示名，不是访问令牌。
- 访问令牌留在 Web 进程内存里。进程还持有它时，被代理的 `/api` 和 WebSocket 升级会补上 `X-User-Token: Bearer <token>`，前提是浏览器没有自己带这个头。Web 进程重启后内存中的令牌消失，用户需要重新登录，下游调用才能再拿到它。
- 同源页面还会在本地用户 ID 为空、或已经等于 OIDC `sub` 时，把访问令牌写入既有的 `openjiuwen_federation` 记录。这是 Web 客户端原来就使用的请求头路径。
- 登录后的 `return_to` 必须是同源路径，否则回到 `/`。
- `required=true` 时，没有会话的 HTML 导航会转到登录；`/api`、`/ws` 以及文件和分享路由返回 `401`。静态资源和 OIDC 路由仍然可访问。配置不完整时，即使 `required=true` 也不会把实例锁死。

华为账号登录仍走 `/api/v1/auth/authorize`、`/callback` 和 `/claim`。本功能不替换这些路由。

## ADFS

1. 在 ADFS 的应用程序组里创建服务器应用程序（机密客户端）。
2. 复制客户端 ID，生成客户端密钥，放到 `JIUWENSWARM_OIDC_CLIENT_SECRET`。
3. 回调地址必须完全一致，例如 `https://swarm.example.com/api/v1/auth/oidc/callback`。不一致时 ADFS 会拒绝。
4. 签发方设为 `https://<adfs-host>/adfs`。JiuwenSwarm 读取 `https://<adfs-host>/adfs/.well-known/openid-configuration`，并使用文档中的 `authorization_endpoint` 和 `token_endpoint`（通常在 `/adfs/oauth2/` 下）。
5. 放行所配置的范围。默认是 `openid profile email`。ID 令牌没有 `email` 时，若 `upn` 含 `@` 则用它。账户名依次取 `preferred_username`、`unique_name`、`upn`。
6. ADFS 2019 及更新版本保持 PKCE 开启。更老的场如果拒绝 `code_challenge`，设置 `JIUWENSWARM_OIDC_PKCE=false`。客户端密钥仍放在令牌请求正文里（`client_secret_post`）。
7. 场站要求资源标识时，设置 `JIUWENSWARM_OIDC_RESOURCE`。
8. 若还要在 ADFS 侧登出，先登记登出后回调，再设置 `JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI`。否则登出只清除 JiuwenSwarm 会话。
9. ID 令牌会校验签名（发现文档 JWKS 上的 RS256 或 ES256）、签发方、受众（`client_id`）、过期时间（两分钟时钟偏差）、nonce，以及提供方给出的 `at_hash`。拒绝 `alg=none` 和 HMAC。

审阅本次改动不需要连接真实 ADFS。单元测试代替发现文档、令牌端点和 JWKS。

## 代表用户换票

下游调用已经可以通过上面的 `X-User-Token` 拿到用户的访问令牌。这是原样传递，不是新令牌。

`jiuwenswarm.common.auth.oidc.obo` 里的 `exchange_on_behalf_of` 是单独的 RFC 8693 令牌交换钩子。只有 `JIUWENSWARM_OIDC_OBO_ENABLED=true` 时才会请求发行方，目前没有工具调用它。ADFS 的 `requested_token_use=on_behalf_of` 尚未实现。
