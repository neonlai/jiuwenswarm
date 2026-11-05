# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""HTTP shape of the OIDC login routes, independent of the web server class."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import parse_qs, quote, unquote, urlparse

from jiuwenswarm.common.auth.oidc.config import OidcConfig, load_oidc_config
from jiuwenswarm.common.auth.oidc.protocol import (
    OidcError,
    OidcIdentity,
    Transport,
    complete_login,
    consume_login,
    cookie_secure,
    drop_session,
    end_session_url,
    read_session,
    safe_return_path,
    session_revoked,
    session_secret,
    start_login,
)

logger = logging.getLogger(__name__)

OIDC_PREFIX = "/api/v1/auth/oidc"
SESSION_COOKIE = "jiuwenswarm_oidc"
TX_COOKIE = "jiuwenswarm_oidc_tx"
_HEADER_SAFE_MAX = 8192


@dataclass(frozen=True)
class OidcHttpResult:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def handle_oidc_http(
    method: str,
    target: str,
    headers: Mapping[str, str],
    *,
    transport: Transport | None = None,
    now: float | None = None,
) -> OidcHttpResult | None:
    """Serve an OIDC route, or return ``None`` when ``target`` is unrelated."""
    parsed = urlparse(target)
    if not parsed.path.startswith(OIDC_PREFIX):
        return None
    verb = method.upper()
    if verb not in {"GET", "POST", "HEAD"}:
        return _json(405, {"error": "method_not_allowed"})
    config = load_oidc_config()
    route = parsed.path[len(OIDC_PREFIX):] or "/"
    query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
    header_map = {key.lower(): value for key, value in headers.items()}
    try:
        if route == "/status" and verb in {"GET", "HEAD"}:
            return _json(200, config.public_status(), head=verb == "HEAD")
        if route == "/login" and verb == "GET":
            return _login(config, query.get("return_to", ""), header_map, transport=transport, now=now)
        if route == "/callback" and verb == "GET":
            return _callback(config, query, header_map, transport=transport, now=now)
        if route == "/session" and verb in {"GET", "HEAD"}:
            return _session(config, header_map, head=verb == "HEAD", now=now)
        if route == "/logout" and verb == "POST":
            return _logout(config, header_map, transport=transport, now=now)
        if route == "/logout":
            return _json(405, {"error": "method_not_allowed"})
    except OidcError as exc:
        logger.info("oidc %s failed: %s", route, exc.code)
        status = 503 if exc.code in {"oidc_inactive", "discovery_failed", "crypto_unavailable"} else 400
        if exc.code == "oidc_inactive" and not config.requested:
            status = 404
        return _error(status, exc.code, header_map)
    return _json(404, {"error": "not_found"})


def session_from_cookie(cookie_header: str, *, now: float | None = None) -> OidcIdentity | None:
    raw = _cookie(cookie_header, SESSION_COOKIE)
    identity = _open_session_cookie(raw, now=now)
    if identity is None or session_revoked(identity.sid, now=now):
        return None
    return identity


def proxy_user_token(cookie_header: str, *, now: float | None = None) -> str:
    """Bearer value for ``X-User-Token``, or an empty string when there is none."""
    identity = session_from_cookie(cookie_header, now=now)
    if identity is None:
        return ""
    record = read_session(identity.sid, now=now)
    if record is None or not record.access_token:
        return ""
    token = record.access_token.strip()
    if token.lower().startswith("bearer "):
        header = token
    else:
        header = f"Bearer {token}"
    if not _header_safe(header):
        return ""
    return header


def _login(
    config: OidcConfig,
    return_to: str,
    headers: Mapping[str, str],
    *,
    transport: Transport | None,
    now: float | None,
) -> OidcHttpResult:
    if not config.active:
        code = config.error or "oidc_disabled"
        status = 503 if config.requested else 404
        return _json(status, {"error": code})
    url, state = start_login(config, return_to, transport=transport, now=now)
    secure = cookie_secure(config, headers.get("x-forwarded-proto", ""))
    return OidcHttpResult(
        status=302,
        headers=(
            ("Location", url),
            ("Set-Cookie", _cookie_header(TX_COOKIE, state, max_age=600, secure=secure)),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Length", "0"),
        ),
        body=b"",
    )


def _callback(
    config: OidcConfig,
    query: Mapping[str, str],
    headers: Mapping[str, str],
    *,
    transport: Transport | None,
    now: float | None,
) -> OidcHttpResult:
    if not config.active:
        raise OidcError("oidc_inactive")
    provider_error = query.get("error", "")
    if provider_error:
        raise OidcError(_safe_code(provider_error))
    pending = consume_login(
        query.get("state", ""),
        _cookie(headers.get("cookie", ""), TX_COOKIE),
        now=now,
    )
    identity = complete_login(
        config,
        pending,
        query.get("code", ""),
        transport=transport,
        now=now,
    )
    secure = cookie_secure(config, headers.get("x-forwarded-proto", ""))
    max_age = max(60, identity.expires_at - _now_seconds(now))
    return OidcHttpResult(
        status=302,
        headers=(
            ("Location", pending.return_to or "/"),
            ("Set-Cookie", _cookie_header(SESSION_COOKIE, _seal(identity), max_age=max_age, secure=secure)),
            ("Set-Cookie", _cookie_header(TX_COOKIE, "", max_age=0, secure=secure)),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Length", "0"),
        ),
        body=b"",
    )


def _session(
    config: OidcConfig,
    headers: Mapping[str, str],
    *,
    head: bool,
    now: float | None,
) -> OidcHttpResult:
    if not config.active:
        raise OidcError("oidc_inactive")
    identity = session_from_cookie(headers.get("cookie", ""), now=now)
    if identity is None:
        return _json(401, {"authenticated": False}, head=head)
    record = read_session(identity.sid, now=now)
    access_token = record.access_token if record is not None else ""
    return _json(
        200,
        {
            "authenticated": True,
            "user": _public_user(identity),
            "accessToken": access_token,
            "tokenType": "Bearer" if access_token else "",
        },
        head=head,
    )


def _logout(
    config: OidcConfig,
    headers: Mapping[str, str],
    *,
    transport: Transport | None,
    now: float | None,
) -> OidcHttpResult:
    identity = session_from_cookie(headers.get("cookie", ""), now=now)
    id_token = ""
    if identity is not None:
        record = drop_session(identity.sid)
        if record is not None:
            id_token = record.id_token
    secure = cookie_secure(config, headers.get("x-forwarded-proto", ""))
    end_url = ""
    if config.active and id_token:
        end_url = end_session_url(config, id_token, transport=transport)
    body = {"ok": True, "endSessionUrl": end_url}
    result = _json(200, body)
    return OidcHttpResult(
        status=result.status,
        headers=result.headers + (
            ("Set-Cookie", _cookie_header(SESSION_COOKIE, "", max_age=0, secure=secure)),
            ("Set-Cookie", _cookie_header(TX_COOKIE, "", max_age=0, secure=secure)),
        ),
        body=result.body,
    )


def _public_user(identity: OidcIdentity) -> dict[str, str]:
    return {
        "sub": identity.sub,
        "name": identity.name,
        "preferredUsername": identity.preferred_username,
        "email": identity.email,
    }


def _seal(identity: OidcIdentity) -> str:
    payload = json.dumps(
        {
            "sid": identity.sid,
            "sub": identity.sub,
            "name": identity.name,
            "preferred_username": identity.preferred_username,
            "email": identity.email,
            "iss": identity.issuer,
            "exp": identity.expires_at,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(session_secret(), payload, hashlib.sha256).digest()
    return f"v1.{_b64(payload)}.{_b64(signature)}"


def _open_session_cookie(value: str, *, now: float | None) -> OidcIdentity | None:
    parts = value.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        return None
    try:
        payload = _b64decode(parts[1])
        signature = _b64decode(parts[2])
        claims = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return None
    expected = hmac.new(session_secret(), payload, hashlib.sha256).digest()
    if len(signature) != len(expected) or not hmac.compare_digest(signature, expected):
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp < _now_seconds(now):
        return None
    sub = claims.get("sub")
    sid = claims.get("sid")
    if not isinstance(sub, str) or not sub or not isinstance(sid, str) or not sid:
        return None
    return OidcIdentity(
        sid=sid,
        sub=sub,
        name=str(claims.get("name") or ""),
        preferred_username=str(claims.get("preferred_username") or ""),
        email=str(claims.get("email") or ""),
        issuer=str(claims.get("iss") or ""),
        expires_at=exp,
    )


def _cookie(header: str, name: str) -> str:
    for part in header.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key.strip() == name:
            return unquote(value.strip())
    return ""


def _cookie_header(name: str, value: str, *, max_age: int, secure: bool) -> str:
    pieces = [
        f"{name}={quote(value, safe='')}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={max_age}",
    ]
    if secure:
        pieces.append("Secure")
    return "; ".join(pieces)


def _json(status: int, payload: dict, *, head: bool = False) -> OidcHttpResult:
    body = b"" if head else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return OidcHttpResult(
        status=status,
        headers=(
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ),
        body=body,
    )


def _error(status: int, code: str, headers: Mapping[str, str]) -> OidcHttpResult:
    accept = headers.get("accept", "")
    if "text/html" in accept and "application/json" not in accept:
        text = (
            "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
            f"<p>Sign-in failed ({_escape(code)}). Close this page and try again.</p>"
        ).encode("utf-8")
        return OidcHttpResult(
            status=status,
            headers=(
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(text))),
                ("Cache-Control", "no-store"),
                ("Referrer-Policy", "no-referrer"),
            ),
            body=text,
        )
    return _json(status, {"error": code})


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _safe_code(value: str) -> str:
    if value.isascii() and 0 < len(value) < 64 and value.replace("_", "").isalnum():
        return value
    return "provider_error"


def _header_safe(value: str) -> bool:
    if not value or len(value) > _HEADER_SAFE_MAX:
        return False
    return all(32 <= ord(char) < 127 for char in value)


def _now_seconds(now: float | None) -> int:
    import time

    return int(time.time() if now is None else now)


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    import base64

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def protected_path(path: str) -> bool:
    """True when an anonymous browser must not see this path while OIDC is required."""
    if path.startswith(OIDC_PREFIX):
        return False
    if path.startswith("/oauth/") or path.startswith("/marketplace-oauth/"):
        return False
    if path.startswith("/assets/"):
        return False
    suffix = path.rsplit("/", 1)[-1]
    if "." in suffix:
        ext = suffix.rsplit(".", 1)[-1].lower()
        if ext in {
            "js", "mjs", "css", "map", "svg", "png", "jpg", "jpeg", "ico",
            "webp", "gif", "woff", "woff2", "ttf", "eot", "json", "webmanifest",
        }:
            return False
    return True
