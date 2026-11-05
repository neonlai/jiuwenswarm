# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Authorization Code + PKCE, discovery, and ID token checks.

Network access goes through a replaceable transport so tests can stand in for
ADFS. Tokens and authorization codes are not written to logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

from jiuwenswarm.common.auth.oidc.config import OidcConfig, reset_oidc_config_for_test

logger = logging.getLogger(__name__)

STATE_TTL_S = 600
DISCOVERY_TTL_S = 600
CLOCK_SKEW_S = 120
SESSION_TTL_S = 8 * 60 * 60
_MAX_BODY = 1_000_000
_MAX_PENDING = 256
_MAX_SESSIONS = 1024

Transport = Callable[[str, str, bytes | None, Mapping[str, str]], "HttpResult"]


class OidcError(Exception):
    """Recoverable OIDC failure. ``code`` is safe to show to the operator."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: bytes


@dataclass
class PendingLogin:
    state: str
    verifier: str
    nonce: str
    return_to: str
    expires_at: float


@dataclass(frozen=True)
class OidcIdentity:
    sid: str
    sub: str
    name: str
    preferred_username: str
    email: str
    issuer: str
    expires_at: int


@dataclass
class SessionRecord:
    identity: OidcIdentity
    access_token: str
    id_token: str


_lock = threading.Lock()
_pending: dict[str, PendingLogin] = {}
_sessions: dict[str, SessionRecord] = {}
_revoked: dict[str, int] = {}
_discovery: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks: dict[str, tuple[float, dict[str, Any]]] = {}


def reset_oidc_for_test() -> None:
    """Clear in-memory login state and the configuration cache."""
    with _lock:
        _pending.clear()
        _sessions.clear()
        _revoked.clear()
        _discovery.clear()
        _jwks.clear()
    reset_oidc_config_for_test()


def start_login(
    config: OidcConfig,
    return_to: str,
    *,
    transport: Transport | None = None,
    now: float | None = None,
) -> tuple[str, str]:
    """Create a one-time login and return ``(authorize_url, state)``."""
    if not config.active:
        raise OidcError("oidc_inactive")
    clock = time.time() if now is None else now
    document = discover(config.issuer, transport=transport, now=clock)
    endpoint = provider_url(str(document.get("authorization_endpoint") or ""), "authorization_endpoint")
    verifier = _token(48)
    challenge = _code_challenge(verifier)
    state = _token(32)
    nonce = _token(32)
    pending = PendingLogin(
        state=state,
        verifier=verifier,
        nonce=nonce,
        return_to=safe_return_path(return_to),
        expires_at=clock + STATE_TTL_S,
    )
    with _lock:
        _prune(clock)
        _pending[state] = pending
    query = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": config.scopes,
        "state": state,
        "nonce": nonce,
    }
    if config.pkce:
        query["code_challenge"] = challenge
        query["code_challenge_method"] = "S256"
    if config.resource:
        query["resource"] = config.resource
    return f"{endpoint}?{urlencode(query)}", state


def consume_login(state: str, tx_state: str, *, now: float | None = None) -> PendingLogin:
    """Return the pending login once. A second call is a replay."""
    clock = time.time() if now is None else now
    if not state or not tx_state or len(state) != len(tx_state) or not hmac.compare_digest(state, tx_state):
        raise OidcError("state_mismatch")
    with _lock:
        _prune(clock)
        pending = _pending.pop(state, None)
    if pending is None or pending.expires_at < clock:
        raise OidcError("state_mismatch")
    return pending


def complete_login(
    config: OidcConfig,
    pending: PendingLogin,
    code: str,
    *,
    transport: Transport | None = None,
    now: float | None = None,
) -> OidcIdentity:
    """Exchange the code, verify the ID token, and keep the access token in memory."""
    if not config.active:
        raise OidcError("oidc_inactive")
    if not code or len(code) > 2048:
        raise OidcError("missing_code")
    clock = time.time() if now is None else now
    document = discover(config.issuer, transport=transport, now=clock)
    token_endpoint = provider_url(str(document.get("token_endpoint") or ""), "token_endpoint")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
    }
    if config.pkce:
        form["code_verifier"] = pending.verifier
    if config.client_secret:
        form["client_secret"] = config.client_secret
    if config.resource:
        form["resource"] = config.resource
    payload = _post_form(token_endpoint, form, transport=transport)
    id_token = payload.get("id_token")
    access_token = payload.get("access_token")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("missing_id_token")
    if not isinstance(access_token, str):
        access_token = ""
    claims = verify_id_token(
        config,
        id_token,
        nonce=pending.nonce,
        access_token=access_token,
        document=document,
        transport=transport,
        now=clock,
    )
    identity = _identity_from_claims(claims, fallback_exp=int(clock) + SESSION_TTL_S)
    record = SessionRecord(identity=identity, access_token=access_token, id_token=id_token)
    with _lock:
        _prune(clock)
        _sessions[identity.sid] = record
    return identity


def read_session(sid: str, *, now: float | None = None) -> SessionRecord | None:
    clock = time.time() if now is None else now
    with _lock:
        record = _sessions.get(sid)
        if record is None:
            return None
        if record.identity.expires_at < clock:
            _sessions.pop(sid, None)
            return None
        return record


def drop_session(sid: str) -> SessionRecord | None:
    with _lock:
        record = _sessions.pop(sid, None)
        if record is not None:
            _revoked[sid] = record.identity.expires_at
        return record


def session_revoked(sid: str, *, now: float | None = None) -> bool:
    clock = int(time.time() if now is None else now)
    with _lock:
        expires_at = _revoked.get(sid)
        if expires_at is None:
            return False
        if expires_at < clock:
            _revoked.pop(sid, None)
            return False
        return True


def discover(
    issuer: str,
    *,
    transport: Transport | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Fetch and cache ``{issuer}/.well-known/openid-configuration``."""
    clock = time.time() if now is None else now
    with _lock:
        cached = _discovery.get(issuer)
        if cached is not None and clock - cached[0] < DISCOVERY_TTL_S:
            return cached[1]
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    body = _get_json(url, transport=transport)
    if not isinstance(body, dict):
        raise OidcError("discovery_failed")
    reported = str(body.get("issuer") or "").rstrip("/")
    if reported != issuer.rstrip("/"):
        raise OidcError("issuer_mismatch")
    with _lock:
        _discovery[issuer] = (clock, body)
    return body


def verify_id_token(
    config: OidcConfig,
    token: str,
    *,
    nonce: str,
    access_token: str,
    document: Mapping[str, Any],
    transport: Transport | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate signature, issuer, audience, expiry, and nonce."""
    clock = time.time() if now is None else now
    header, claims, signing_input, signature = _split_jwt(token)
    algorithm = str(header.get("alg") or "")
    if algorithm in {"none", ""} or algorithm.startswith("HS"):
        raise OidcError("unsupported_alg")
    jwks_uri = provider_url(str(document.get("jwks_uri") or ""), "jwks_uri")
    key = _select_jwk(jwks_uri, str(header.get("kid") or ""), transport=transport, now=clock)
    _verify_signature(algorithm, signing_input, signature, key)
    if str(claims.get("iss") or "").rstrip("/") != config.issuer.rstrip("/"):
        raise OidcError("issuer_mismatch")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if config.client_id not in {str(item) for item in audiences}:
        raise OidcError("audience_mismatch")
    authorized = claims.get("azp")
    if isinstance(authorized, str) and authorized and authorized != config.client_id:
        raise OidcError("authorized_party_mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OidcError("missing_subject")
    got_nonce = str(claims.get("nonce") or "")
    if len(got_nonce) != len(nonce) or not hmac.compare_digest(got_nonce, nonce):
        raise OidcError("nonce_mismatch")
    exp = _as_int(claims.get("exp"))
    iat = _as_int(claims.get("iat"))
    if exp is None or exp < clock - CLOCK_SKEW_S:
        raise OidcError("token_expired")
    if iat is not None and iat > clock + CLOCK_SKEW_S:
        raise OidcError("token_not_yet_valid")
    _check_at_hash(claims.get("at_hash"), access_token, algorithm)
    return claims


def end_session_url(config: OidcConfig, id_token: str, *, transport: Transport | None = None) -> str:
    """Return the provider logout URL when a post-logout redirect is registered."""
    if not config.post_logout_redirect_uri:
        return ""
    try:
        document = discover(config.issuer, transport=transport)
    except OidcError:
        return ""
    endpoint = str(document.get("end_session_endpoint") or "")
    if not endpoint:
        return ""
    try:
        endpoint = provider_url(endpoint, "end_session_endpoint")
    except OidcError:
        return ""
    query = {
        "post_logout_redirect_uri": config.post_logout_redirect_uri,
        "client_id": config.client_id,
    }
    if id_token:
        query["id_token_hint"] = id_token
    return f"{endpoint}?{urlencode(query)}"


def safe_return_path(value: str) -> str:
    """Keep post-login navigation on this origin."""
    raw = (value or "").strip()
    if not raw or len(raw) > 512:
        return "/"
    if not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    if "\\" in raw or "\r" in raw or "\n" in raw or "://" in raw:
        return "/"
    return raw


def cookie_secure(config: OidcConfig, forwarded_proto: str) -> bool:
    if config.cookie_secure is not None:
        return config.cookie_secure
    proto = forwarded_proto.split(",")[0].strip().lower()
    return proto == "https" or config.redirect_uri.startswith("https://")


def default_transport(method: str, url: str, body: bytes | None, headers: Mapping[str, str]) -> HttpResult:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return HttpResult(status=response.status, body=response.read(_MAX_BODY))
    except urllib.error.HTTPError as exc:
        return HttpResult(status=exc.code, body=exc.read(_MAX_BODY))
    except OSError as exc:
        logger.warning("oidc transport failed: %s", exc.__class__.__name__)
        raise OidcError("discovery_failed") from exc


def session_secret() -> bytes:
    """HMAC key for the session cookie. Created on first login, not at import."""
    configured = os.environ.get("JIUWENSWARM_OIDC_SESSION_SECRET", "").strip()
    if configured:
        return hashlib.sha256(configured.encode("utf-8")).digest()
    path = _secret_path()
    try:
        existing = path.read_bytes().strip()
        if len(existing) >= 32:
            return existing[:64]
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return path.read_bytes().strip()[:64]
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _secret_path():
    from pathlib import Path

    data_dir = os.environ.get("JIUWENSWARM_DATA_DIR", "").strip()
    if data_dir:
        root = Path(data_dir)
    else:
        home = os.environ.get("JIUWENSWARM_HOME", "").strip()
        root = (Path(home) if home else Path.home()) / ".jiuwenswarm"
    return root / "config" / "oidc_session.key"


def _identity_from_claims(claims: Mapping[str, Any], *, fallback_exp: int) -> OidcIdentity:
    sub = str(claims.get("sub") or "")[:256]
    upn = _claim_text(claims, "upn")
    email = _claim_text(claims, "email") or (upn if "@" in upn else "")
    username = _claim_text(claims, "preferred_username") or _claim_text(claims, "unique_name") or upn or sub
    name = _claim_text(claims, "name") or username
    exp = _as_int(claims.get("exp")) or fallback_exp
    return OidcIdentity(
        sid=_token(24),
        sub=sub,
        name=name[:256],
        preferred_username=username[:256],
        email=email[:256],
        issuer=str(claims.get("iss") or ""),
        expires_at=exp,
    )


def _claim_text(claims: Mapping[str, Any], key: str) -> str:
    value = claims.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _post_form(url: str, form: Mapping[str, str], *, transport: Transport | None) -> dict[str, Any]:
    body = urlencode(form).encode("utf-8")
    send = transport or default_transport
    try:
        result = send(
            "POST",
            url,
            body,
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
    except OidcError:
        raise
    except Exception as exc:
        logger.warning("oidc token endpoint failed: %s", exc.__class__.__name__)
        raise OidcError("token_endpoint_failed") from exc
    if result.status != 200:
        raise OidcError(_safe_oauth_error(result.body))
    try:
        payload = json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise OidcError("token_endpoint_failed") from exc
    if not isinstance(payload, dict):
        raise OidcError("token_endpoint_failed")
    return payload


def _get_json(url: str, *, transport: Transport | None) -> Any:
    send = transport or default_transport
    try:
        result = send("GET", url, None, {"Accept": "application/json"})
    except OidcError:
        raise
    except Exception as exc:
        logger.warning("oidc discovery failed: %s", exc.__class__.__name__)
        raise OidcError("discovery_failed") from exc
    if result.status != 200:
        raise OidcError("discovery_failed")
    try:
        return json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise OidcError("discovery_failed") from exc


def _select_jwk(
    jwks_uri: str,
    kid: str,
    *,
    transport: Transport | None,
    now: float,
) -> dict[str, Any]:
    document = _load_jwks(jwks_uri, transport=transport, now=now, force=False)
    key = _match_jwk(document, kid)
    if key is None:
        document = _load_jwks(jwks_uri, transport=transport, now=now, force=True)
        key = _match_jwk(document, kid)
    if key is None:
        raise OidcError("jwks_key_not_found")
    return key


def _load_jwks(
    jwks_uri: str,
    *,
    transport: Transport | None,
    now: float,
    force: bool,
) -> dict[str, Any]:
    if not force:
        with _lock:
            cached = _jwks.get(jwks_uri)
            if cached is not None and now - cached[0] < DISCOVERY_TTL_S:
                return cached[1]
    body = _get_json(jwks_uri, transport=transport)
    if not isinstance(body, dict):
        raise OidcError("jwks_invalid")
    with _lock:
        _jwks[jwks_uri] = (now, body)
    return body


def _match_jwk(document: Mapping[str, Any], kid: str) -> dict[str, Any] | None:
    keys = document.get("keys")
    if not isinstance(keys, list):
        return None
    usable = [key for key in keys if isinstance(key, dict)]
    if kid:
        for key in usable:
            if str(key.get("kid") or "") == kid:
                return key
        return None
    if len(usable) == 1:
        return usable[0]
    return None


def _split_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("malformed_id_token")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except (json.JSONDecodeError, ValueError) as exc:
        raise OidcError("malformed_id_token") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("malformed_id_token")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, claims, signing_input, signature


def _verify_signature(algorithm: str, signing_input: bytes, signature: bytes, jwk: Mapping[str, Any]) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as exc:
        raise OidcError("crypto_unavailable") from exc
    try:
        if algorithm == "RS256":
            key = _rsa_key(jwk, rsa)
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        if algorithm == "ES256":
            key = _ec_key(jwk, ec)
            if len(signature) != 64:
                raise OidcError("bad_signature")
            raw_r = int.from_bytes(signature[:32], "big")
            raw_s = int.from_bytes(signature[32:], "big")
            der = utils.encode_dss_signature(raw_r, raw_s)
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return
    except OidcError:
        raise
    except InvalidSignature as exc:
        raise OidcError("bad_signature") from exc
    except Exception as exc:
        logger.warning("oidc signature verification failed: %s", exc.__class__.__name__)
        raise OidcError("bad_signature") from exc
    raise OidcError("unsupported_alg")


def _rsa_key(jwk: Mapping[str, Any], rsa: Any) -> Any:
    if jwk.get("kty") != "RSA":
        raise OidcError("jwks_key_type")
    numbers = rsa.RSAPublicNumbers(_b64_int(str(jwk.get("e"))), _b64_int(str(jwk.get("n"))))
    return numbers.public_key()


def _ec_key(jwk: Mapping[str, Any], ec: Any) -> Any:
    if jwk.get("kty") != "EC" or jwk.get("crv") not in {None, "P-256"}:
        raise OidcError("jwks_key_type")
    numbers = ec.EllipticCurvePublicNumbers(
        _b64_int(str(jwk.get("x"))),
        _b64_int(str(jwk.get("y"))),
        ec.SECP256R1(),
    )
    return numbers.public_key()


def _check_at_hash(at_hash: Any, access_token: str, algorithm: str) -> None:
    if not isinstance(at_hash, str) or not at_hash or not access_token:
        return
    if algorithm not in {"RS256", "ES256"}:
        return
    try:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
    except UnicodeEncodeError as exc:
        raise OidcError("at_hash_mismatch") from exc
    expected = _b64url_encode(digest[:16])
    if len(expected) != len(at_hash) or not hmac.compare_digest(expected, at_hash):
        raise OidcError("at_hash_mismatch")


def provider_url(value: str, code: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https" and host and not parts.username:
        return value
    if parts.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"} and not parts.username:
        return value
    raise OidcError(code)


def _safe_oauth_error(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return "token_endpoint_failed"
    code = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(code, str) and code.isascii() and 0 < len(code) < 64 and code.replace("_", "").isalnum():
        return code
    return "token_endpoint_failed"


def _prune(now: float) -> None:
    for state, pending in list(_pending.items()):
        if pending.expires_at < now:
            _pending.pop(state, None)
    for sid, record in list(_sessions.items()):
        if record.identity.expires_at < now:
            _sessions.pop(sid, None)
    for sid, expires_at in list(_revoked.items()):
        if expires_at < now:
            _revoked.pop(sid, None)
    while len(_pending) > _MAX_PENDING:
        _pending.pop(next(iter(_pending)), None)
    while len(_sessions) > _MAX_SESSIONS:
        _sessions.pop(next(iter(_sessions)), None)


def _token(nbytes: int) -> str:
    return secrets.token_urlsafe(nbytes).replace("=", "")


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url_encode(digest)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _b64_int(data: str) -> int:
    return int.from_bytes(_b64url_decode(data), "big")


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)

