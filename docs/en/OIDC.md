# OpenID Connect sign-in

Operators can send browser users through a standard OpenID Connect authorization-code login. The primary target is enterprise ADFS. The same settings work with any issuer that publishes `/.well-known/openid-configuration`.

When the issuer, client id, and redirect URI are all empty, nothing in this path runs. Huawei Account Kit login and unsigned local use stay as they are, and the web UI does not show an SSO control.

## Configure

Environment variables override the `oidc` block in `config.yaml`. Prefer the environment for the client secret so it is not written into a config file.

| Key | Environment variable | Required to turn login on |
| --- | --- | --- |
| `issuer` | `JIUWENSWARM_OIDC_ISSUER` | Yes |
| `client_id` | `JIUWENSWARM_OIDC_CLIENT_ID` | Yes |
| `redirect_uri` | `JIUWENSWARM_OIDC_REDIRECT_URI` | Yes |
| `client_secret` | `JIUWENSWARM_OIDC_CLIENT_SECRET` | No for a public client. ADFS server applications normally need it |
| `scopes` | `JIUWENSWARM_OIDC_SCOPES` | No. Default `openid profile email`. `openid` is added if it is missing |
| `pkce` | `JIUWENSWARM_OIDC_PKCE` | No. Default `true` (S256) |
| `enabled` | `JIUWENSWARM_OIDC_ENABLED` | No. Unset means "on when issuer, client id, and redirect URI are all set". `false` forces the previous behavior |
| `required` | `JIUWENSWARM_OIDC_REQUIRED` | No. Default `false`. `true` sends anonymous browser users to the IdP, but only after the configuration is valid |
| `post_logout_redirect_uri` | `JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI` | No. Used only when the discovery document has `end_session_endpoint` |
| `resource` | `JIUWENSWARM_OIDC_RESOURCE` | No. Sent on the authorize and token requests when ADFS expects a resource identifier |
| `obo_enabled` | `JIUWENSWARM_OIDC_OBO_ENABLED` | No. Default `false`. See the token-exchange note below |
| `cookie_secure` | `JIUWENSWARM_OIDC_COOKIE_SECURE` | No. Default follows `https` redirect URIs and `X-Forwarded-Proto` |
|  | `JIUWENSWARM_OIDC_SESSION_SECRET` | No. HMAC key for the session cookie. If unset, the web process creates `config/oidc_session.key` under the data directory on the first successful login |

Example for a local web server:

```bash
export JIUWENSWARM_OIDC_ISSUER=https://adfs.example.com/adfs
export JIUWENSWARM_OIDC_CLIENT_ID=<application-id>
export JIUWENSWARM_OIDC_CLIENT_SECRET=<secret>
export JIUWENSWARM_OIDC_REDIRECT_URI=http://127.0.0.1:5173/api/v1/auth/oidc/callback
export JIUWENSWARM_OIDC_SCOPES="openid profile email"
```

The issuer must be `https`, except loopback `http` (`localhost`, `127.0.0.1`, `::1`) used by tests. The value must match the `issuer` field in the discovery document, ignoring one trailing slash.

`jiuwenswarm-web` serves these routes itself, before it proxies `/api` to the gateway:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/auth/oidc/status` | `{enabled:false}` when login is off |
| GET | `/api/v1/auth/oidc/login` | Redirect to the IdP with `state`, `nonce`, and PKCE |
| GET | `/api/v1/auth/oidc/callback` | Check `state`, exchange the code, set the session cookie |
| GET | `/api/v1/auth/oidc/session` | Current user. `401` when the cookie is missing or revoked |
| POST | `/api/v1/auth/oidc/logout` | Revoke the server session and clear the cookie |

`npm run dev` proxies `/api` straight to the gateway, so those routes are not on that dev server. Exercise login with `jiuwenswarm-web` (`make start-debug` / the `web` process).

## What the browser gets

- `jiuwenswarm_oidc` is an HttpOnly session cookie. It holds the subject and display claims, not the access token.
- The access token stays in the web process. While that process still has it, proxied `/api` and WebSocket upgrades gain `X-User-Token: Bearer <token>` when the browser did not already send that header. A restarted web process drops the in-memory token; the user signs in again before downstream calls can use it.
- The same-origin page may also copy the access token into the existing `openjiuwen_federation` browser record when the local user id is empty or already equal to the OIDC `sub`. That is the same header path the web client already uses.
- `return_to` after login must be a same-origin path. Anything else becomes `/`.
- With `required=true`, HTML navigations without a session redirect to login. `/api`, `/ws`, and the file/share routes return `401`. Static assets and the OIDC routes stay reachable. A half-configured `required=true` does not lock the instance.

Huawei Account Kit stays on `/api/v1/auth/authorize`, `/callback`, and `/claim`. This feature does not replace those routes.

## ADFS

1. In ADFS, create a Server application (confidential client) in an application group.
2. Copy the client id. Create a client secret and put it in `JIUWENSWARM_OIDC_CLIENT_SECRET`.
3. Register the redirect URI exactly, for example `https://swarm.example.com/api/v1/auth/oidc/callback`. ADFS rejects a mismatch.
4. Set the issuer to `https://<adfs-host>/adfs`. JiuwenSwarm loads `https://<adfs-host>/adfs/.well-known/openid-configuration` and uses the `authorization_endpoint` and `token_endpoint` from that document (typically under `/adfs/oauth2/`).
5. Permit the scopes you set. The default is `openid profile email`. If the ID token has no `email`, `upn` is used when it contains `@`. `preferred_username`, `unique_name`, and `upn` fill the account name.
6. Leave PKCE on for ADFS 2019 and later. If an older farm rejects `code_challenge`, set `JIUWENSWARM_OIDC_PKCE=false`. The client secret is still sent in the token-request body (`client_secret_post`).
7. If the farm expects a resource identifier, set `JIUWENSWARM_OIDC_RESOURCE`.
8. To sign the user out of ADFS as well, register a post-logout redirect URI and set `JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI`. Otherwise logout only clears the JiuwenSwarm session.
9. ID tokens are checked for signature (RS256 or ES256 via the discovery JWKS), issuer, audience (`client_id`), expiry (two minutes of clock skew), nonce, and `at_hash` when the provider sends it. `alg=none` and HMAC algorithms are rejected.

A real ADFS tenant is not required to review this change. Unit tests stand in for discovery, the token endpoint, and JWKS.

## On-behalf-of

Downstream calls can already receive the user's access token through `X-User-Token`, as above. That is passthrough, not a new token.

`exchange_on_behalf_of` in `jiuwenswarm.common.auth.oidc.obo` is a separate RFC 8693 token-exchange hook. It does not run unless `JIUWENSWARM_OIDC_OBO_ENABLED=true`, and no tool calls it yet. ADFS `requested_token_use=on_behalf_of` is not implemented.
