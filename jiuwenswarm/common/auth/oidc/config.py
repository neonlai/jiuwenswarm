# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""OIDC settings from the environment and the optional ``oidc`` config block.

Environment variables win over ``config.yaml``. An empty configuration leaves
sign-in disabled, so a default install does not contact an identity provider.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

_ENV_PATTERN = re.compile(r"\$\{([^:}]+)(?::-([^}]*))?\}")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", "disabled"})
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

_ENV_NAMES = (
    "JIUWENSWARM_OIDC_ENABLED",
    "JIUWENSWARM_OIDC_REQUIRED",
    "JIUWENSWARM_OIDC_ISSUER",
    "JIUWENSWARM_OIDC_CLIENT_ID",
    "JIUWENSWARM_OIDC_CLIENT_SECRET",
    "JIUWENSWARM_OIDC_REDIRECT_URI",
    "JIUWENSWARM_OIDC_SCOPES",
    "JIUWENSWARM_OIDC_PKCE",
    "JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI",
    "JIUWENSWARM_OIDC_RESOURCE",
    "JIUWENSWARM_OIDC_OBO_ENABLED",
    "JIUWENSWARM_OIDC_COOKIE_SECURE",
    "JIUWENSWARM_OIDC_SESSION_SECRET",
    "JIUWENSWARM_CONFIG_DIR",
    "JIUWENSWARM_DATA_DIR",
    "JIUWENSWARM_HOME",
)

_cached_key: tuple[str, ...] | None = None
_cached_config: OidcConfig | None = None


@dataclass(frozen=True)
class OidcConfig:
    """Resolved OIDC settings. ``active`` is the only switch the login flow uses."""

    active: bool
    requested: bool
    required: bool
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str
    pkce: bool
    post_logout_redirect_uri: str
    resource: str
    obo_enabled: bool
    cookie_secure: bool | None
    error: str

    def public_status(self) -> dict[str, Any]:
        """Status payload safe to return to the browser."""
        return {
            "enabled": self.active,
            "required": self.required if self.active else False,
            "pkce": self.pkce,
            "issuer": self.issuer if self.requested else "",
            "clientId": self.client_id if self.active else "",
            "error": self.error,
        }


def load_oidc_config() -> OidcConfig:
    """Return the process OIDC configuration, cached until the env or file changes."""
    global _cached_key, _cached_config
    key = _cache_key()
    if _cached_config is not None and key == _cached_key:
        return _cached_config
    config = _resolve_config()
    _cached_key = key
    _cached_config = config
    return config


def reset_oidc_config_for_test() -> None:
    """Drop the cached configuration. Tests call this via ``reset_oidc_for_test``."""
    global _cached_key, _cached_config
    _cached_key = None
    _cached_config = None


def _cache_key() -> tuple[str, ...]:
    path = _config_yaml_path()
    mtime = ""
    if path is not None:
        try:
            mtime = str(path.stat().st_mtime_ns)
        except OSError:
            mtime = "missing"
    env = tuple(os.environ.get(name, "") for name in _ENV_NAMES)
    return (*env, str(path or ""), mtime)


def _resolve_config() -> OidcConfig:
    raw = _yaml_oidc_block()
    enabled_text = _pick("JIUWENSWARM_OIDC_ENABLED", raw.get("enabled"))
    required_text = _pick("JIUWENSWARM_OIDC_REQUIRED", raw.get("required"))
    issuer = _pick("JIUWENSWARM_OIDC_ISSUER", raw.get("issuer")).rstrip("/")
    client_id = _pick("JIUWENSWARM_OIDC_CLIENT_ID", raw.get("client_id"))
    client_secret = _pick("JIUWENSWARM_OIDC_CLIENT_SECRET", raw.get("client_secret"))
    redirect_uri = _pick("JIUWENSWARM_OIDC_REDIRECT_URI", raw.get("redirect_uri"))
    scopes = _pick("JIUWENSWARM_OIDC_SCOPES", raw.get("scopes")) or "openid profile email"
    pkce_text = _pick("JIUWENSWARM_OIDC_PKCE", raw.get("pkce"))
    post_logout = _pick(
        "JIUWENSWARM_OIDC_POST_LOGOUT_REDIRECT_URI",
        raw.get("post_logout_redirect_uri"),
    )
    resource = _pick("JIUWENSWARM_OIDC_RESOURCE", raw.get("resource"))
    obo_text = _pick("JIUWENSWARM_OIDC_OBO_ENABLED", raw.get("obo_enabled"))
    secure_text = _pick("JIUWENSWARM_OIDC_COOKIE_SECURE", raw.get("cookie_secure"))

    enabled_flag = _optional_bool(enabled_text)
    required = _optional_bool(required_text) is True
    pkce = True if _optional_bool(pkce_text) is None else bool(_optional_bool(pkce_text))
    obo_enabled = _optional_bool(obo_text) is True
    cookie_secure = _optional_bool(secure_text)
    scopes = _ensure_openid_scope(scopes)

    requested = bool(
        issuer
        or client_id
        or redirect_uri
        or client_secret
        or enabled_flag is True
        or required
        or obo_enabled
        or resource
        or post_logout
    )
    error = ""
    active = False
    if requested:
        error = _validate(
            issuer=issuer,
            client_id=client_id,
            redirect_uri=redirect_uri,
            post_logout=post_logout,
        )
        active = error == "" and enabled_flag is not False
        if enabled_flag is False:
            error = ""
            active = False
    return OidcConfig(
        active=active,
        requested=requested and enabled_flag is not False,
        required=required and active,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=scopes,
        pkce=pkce,
        post_logout_redirect_uri=post_logout,
        resource=resource,
        obo_enabled=obo_enabled and active,
        cookie_secure=cookie_secure,
        error=error if enabled_flag is not False else "",
    )


def _validate(*, issuer: str, client_id: str, redirect_uri: str, post_logout: str) -> str:
    if not issuer or not client_id or not redirect_uri:
        return "incomplete"
    if _issuer_error(issuer):
        return "invalid_issuer"
    if _redirect_error(redirect_uri):
        return "invalid_redirect"
    if post_logout and _redirect_error(post_logout):
        return "invalid_post_logout_redirect"
    return ""


def _issuer_error(issuer: str) -> str:
    parts = urlsplit(issuer)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https" and host and not parts.username and not parts.query and not parts.fragment:
        return ""
    if parts.scheme == "http" and host in _LOOPBACK and not parts.username and not parts.query:
        return ""
    return "invalid_issuer"


def _redirect_error(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "invalid_redirect"
    if parts.username or parts.fragment:
        return "invalid_redirect"
    return ""


def _ensure_openid_scope(scopes: str) -> str:
    parts = [part for part in scopes.split() if part]
    if "openid" not in parts:
        parts.insert(0, "openid")
    return " ".join(parts)


def _optional_bool(value: str) -> bool | None:
    text = value.strip().lower()
    if not text:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _pick(env_name: str, yaml_value: Any) -> str:
    if env_name in os.environ:
        return os.environ[env_name].strip()
    return _as_text(yaml_value).strip()


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return _expand_env(str(value))


def _expand_env(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        current = os.environ.get(match.group(1))
        default = match.group(2)
        if default is not None and not current:
            return default
        return current or ""

    return _ENV_PATTERN.sub(replace, value)


def _yaml_oidc_block() -> dict[str, Any]:
    path = _config_yaml_path()
    if path is None:
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    block = loaded.get("oidc")
    if not isinstance(block, dict):
        return {}
    return block


def _config_yaml_path() -> Path | None:
    config_dir = os.environ.get("JIUWENSWARM_CONFIG_DIR", "").strip()
    if config_dir:
        path = Path(config_dir) / "config.yaml"
        return path if path.is_file() else None
    data_dir = os.environ.get("JIUWENSWARM_DATA_DIR", "").strip()
    if data_dir:
        root = Path(data_dir)
    else:
        home = os.environ.get("JIUWENSWARM_HOME", "").strip()
        root = (Path(home) if home else Path.home()) / ".jiuwenswarm"
    path = root / "config" / "config.yaml"
    return path if path.is_file() else None
