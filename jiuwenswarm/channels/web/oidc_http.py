# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Adapt the OIDC HTTP API to the stdlib web server."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlparse

from jiuwenswarm.common.auth.oidc.config import load_oidc_config
from jiuwenswarm.common.auth.oidc.http_api import (
    handle_oidc_http,
    protected_path,
    proxy_user_token,
    session_from_cookie,
)
from jiuwenswarm.common.auth.oidc.protocol import safe_return_path


def try_handle(handler: Any) -> bool:
    """Write an OIDC response and return True when this request is an OIDC route."""
    result = handle_oidc_http(handler.command, handler.path, handler.headers)
    if result is None:
        return False
    handler.send_response(result.status)
    for key, value in result.headers:
        handler.send_header(key, value)
    handler.end_headers()
    if handler.command != "HEAD" and result.body:
        handler.wfile.write(result.body)
    return True


def block_if_required(handler: Any) -> bool:
    """Reject anonymous requests when OIDC is configured as required."""
    try:
        config = load_oidc_config()
    except Exception:
        return False
    if not config.required:
        return False
    path = urlparse(handler.path).path
    if not protected_path(path):
        return False
    if session_from_cookie(handler.headers.get("Cookie", "")) is not None:
        return False
    if path.startswith(("/api", "/ws", "/file-api/", "/share-api/", "/skill-sync/")):
        body = b'{"error":"oidc_required"}'
        handler.send_response(401)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("WWW-Authenticate", "Bearer")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
        return True
    target = safe_return_path(path if not urlparse(handler.path).query else f"{path}?{urlparse(handler.path).query}")
    location = "/api/v1/auth/oidc/login?return_to=" + quote(target, safe="")
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    return True


def user_token_header(cookie_header: str) -> str:
    """Access token captured at login, formatted for ``X-User-Token``."""
    try:
        return proxy_user_token(cookie_header)
    except Exception:
        return ""
