# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""OIDC config, Authorization Code + PKCE, callback state, and the OBO stub."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jiuwenswarm.common.auth.oidc.config import load_oidc_config
from jiuwenswarm.common.auth.oidc.http_api import handle_oidc_http, proxy_user_token
from jiuwenswarm.common.auth.oidc.obo import OnBehalfOfRequest, exchange_on_behalf_of
from jiuwenswarm.common.auth.oidc.protocol import HttpResult, reset_oidc_for_test
from jiuwenswarm.channels.web.oidc_http import block_if_required

ISSUER = "http://127.0.0.1:9/adfs"
REDIRECT = "http://127.0.0.1:5173/api/v1/auth/oidc/callback"
ACCESS = "adfs-access-token"
_ENV = (
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
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("JIUWENSWARM_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("JIUWENSWARM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("JIUWENSWARM_OIDC_SESSION_SECRET", "test-secret")
    reset_oidc_for_test()
    yield
    reset_oidc_for_test()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(public_key) -> dict:
    numbers = public_key.public_numbers()

    def enc(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return _b64(raw)

    return {"kty": "RSA", "kid": "adfs-1", "alg": "RS256", "n": enc(numbers.n), "e": enc(numbers.e)}


def _sign(private_key, payload: dict) -> str:
    header = {"alg": "RS256", "kid": "adfs-1", "typ": "JWT"}
    signing = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = private_key.sign(signing.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing}.{_b64(signature)}"


def _at_hash(token: str) -> str:
    return _b64(hashlib.sha256(token.encode("ascii")).digest()[:16])


class FakeIdP:
    def __init__(self, private_key, public_key) -> None:
        self.private_key = private_key
        self.jwk = _jwk(public_key)
        self.calls: list[dict] = []
        self.nonce = ""
        self.claims_override: dict | None = None
        self.access_token = ACCESS
        self.token_status = 200

    def __call__(self, method, url, body, headers):
        self.calls.append({"method": method, "url": url, "body": body or b""})
        if url.endswith("/.well-known/openid-configuration"):
            document = {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/oauth2/authorize",
                "token_endpoint": f"{ISSUER}/oauth2/token",
                "jwks_uri": f"{ISSUER}/jwks",
                "end_session_endpoint": f"{ISSUER}/oauth2/logout",
            }
            return HttpResult(200, json.dumps(document).encode())
        if url.endswith("/jwks"):
            return HttpResult(200, json.dumps({"keys": [self.jwk]}).encode())
        if url.endswith("/oauth2/token"):
            if self.token_status != 200:
                return HttpResult(self.token_status, b'{"error":"invalid_grant"}')
            claims = self.claims_override or {
                "iss": ISSUER,
                "aud": "swarm-web",
                "sub": "user-1",
                "nonce": self.nonce,
                "exp": 4_102_444_800,
                "iat": 1_700_000_000,
                "name": "Ada Admin",
                "upn": "ada@example.com",
                "at_hash": _at_hash(self.access_token),
            }
            payload = {
                "access_token": self.access_token,
                "id_token": _sign(self.private_key, claims),
                "token_type": "Bearer",
            }
            return HttpResult(200, json.dumps(payload).encode())
        raise AssertionError(url)


@pytest.fixture
def idp():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return FakeIdP(private_key, private_key.public_key())


def _enable(monkeypatch, **extra: str) -> None:
    monkeypatch.setenv("JIUWENSWARM_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("JIUWENSWARM_OIDC_CLIENT_ID", "swarm-web")
    monkeypatch.setenv("JIUWENSWARM_OIDC_CLIENT_SECRET", "secret-value")
    monkeypatch.setenv("JIUWENSWARM_OIDC_REDIRECT_URI", REDIRECT)
    for name, value in extra.items():
        monkeypatch.setenv(name, value)
    reset_oidc_for_test()


def _cookie(response, name: str) -> str:
    for key, value in response.headers:
        if key != "Set-Cookie" or not value.startswith(f"{name}="):
            continue
        return value.split(";", 1)[0].split("=", 1)[1]
    return ""


def _query(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    return {key: values[0] for key, values in parse_qs(parsed.query).items()}


def _login(monkeypatch, idp, **extra: str):
    _enable(monkeypatch, **extra)
    response = handle_oidc_http("GET", "/api/v1/auth/oidc/login?return_to=/chat", {}, transport=idp)
    assert response is not None and response.status == 302
    location = dict(response.headers)["Location"]
    query = _query(location)
    idp.nonce = query["nonce"]
    return response, location, query


def test_unconfigured_oidc_stays_disabled():
    config = load_oidc_config()
    assert config.active is False
    assert config.requested is False
    status = handle_oidc_http("GET", "/api/v1/auth/oidc/status", {})
    assert status is not None
    assert json.loads(status.body)["enabled"] is False
    login = handle_oidc_http("GET", "/api/v1/auth/oidc/login", {})
    assert login is not None and login.status == 404
    assert handle_oidc_http("GET", "/api/v1/auth/authorize", {}) is None


def test_shipped_template_does_not_enable_oidc(monkeypatch):
    root = Path(__file__).resolve().parents[3]
    monkeypatch.setenv("JIUWENSWARM_CONFIG_DIR", str(root / "jiuwenswarm" / "resources"))
    reset_oidc_for_test()
    text = (root / "jiuwenswarm" / "resources" / "config.yaml").read_text(encoding="utf-8")
    assert "\noidc:\n" in text
    config = load_oidc_config()
    assert config.active is False
    assert config.requested is False
    assert "secret" not in json.dumps(config.public_status())


def test_yaml_enables_oidc_when_env_is_unset(monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(
        "oidc:\n"
        f"  issuer: {ISSUER}\n"
        "  client_id: swarm-web\n"
        f"  redirect_uri: {REDIRECT}\n"
        "  pkce: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("JIUWENSWARM_CONFIG_DIR", str(tmp_path))
    reset_oidc_for_test()
    config = load_oidc_config()
    assert config.active is True
    assert config.pkce is False
    assert config.client_secret == ""


def test_explicit_disable_wins_over_issuer(monkeypatch):
    _enable(monkeypatch, JIUWENSWARM_OIDC_ENABLED="false")
    config = load_oidc_config()
    assert config.active is False
    login = handle_oidc_http("GET", "/api/v1/auth/oidc/login", {})
    assert login is not None and login.status == 404


def test_incomplete_configuration_is_not_active(monkeypatch):
    monkeypatch.setenv("JIUWENSWARM_OIDC_ENABLED", "true")
    monkeypatch.setenv("JIUWENSWARM_OIDC_CLIENT_ID", "swarm-web")
    reset_oidc_for_test()
    config = load_oidc_config()
    assert config.active is False
    assert config.error == "incomplete"
    login = handle_oidc_http("GET", "/api/v1/auth/oidc/login", {})
    assert login is not None and login.status == 503
    assert json.loads(login.body)["error"] == "incomplete"


def test_non_loopback_http_issuer_is_rejected(monkeypatch):
    _enable(monkeypatch, JIUWENSWARM_OIDC_ISSUER="http://adfs.example.com/adfs")
    config = load_oidc_config()
    assert config.active is False
    assert config.error == "invalid_issuer"


def test_login_uses_discovery_and_pkce_and_hides_the_secret(monkeypatch, idp):
    _response, location, query = _login(monkeypatch, idp, JIUWENSWARM_OIDC_RESOURCE="api://graph")
    assert location.startswith(f"{ISSUER}/oauth2/authorize?")
    assert query["response_type"] == "code"
    assert query["code_challenge_method"] == "S256"
    assert query["resource"] == "api://graph"
    assert "openid" in query["scope"].split()
    assert "secret-value" not in location
    assert "code_verifier" not in location
    assert query["code_challenge"] and "=" not in query["code_challenge"]


def test_callback_rejects_missing_and_replayed_state(monkeypatch, idp):
    response, _location, query = _login(monkeypatch, idp)
    tx = _cookie(response, "jiuwenswarm_oidc_tx")
    missing = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {},
        transport=idp,
    )
    assert missing is not None and json.loads(missing.body)["error"] == "state_mismatch"
    ok = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={tx}"},
        transport=idp,
    )
    assert ok is not None and ok.status == 302
    replay = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={tx}"},
        transport=idp,
    )
    assert replay is not None and json.loads(replay.body)["error"] == "state_mismatch"


def test_full_login_session_logout_and_user_token(monkeypatch, idp):
    response, _location, query = _login(monkeypatch, idp)
    tx = _cookie(response, "jiuwenswarm_oidc_tx")
    callback = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=auth-code&state={query['state']}&return_to=https://evil.example",
        {"Cookie": f"jiuwenswarm_oidc_tx={tx}", "Accept": "application/json"},
        transport=idp,
    )
    assert callback is not None and callback.status == 302
    assert dict(callback.headers)["Location"] == "/chat"
    session_cookie = _cookie(callback, "jiuwenswarm_oidc")
    token_call = next(call for call in idp.calls if call["url"].endswith("/oauth2/token"))
    form = {key: values[0] for key, values in parse_qs(token_call["body"].decode()).items()}
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code"
    assert form["client_secret"] == "secret-value"
    assert form["redirect_uri"] == REDIRECT
    assert hashlib.sha256(form["code_verifier"].encode()).digest()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert challenge == query["code_challenge"]

    session = handle_oidc_http(
        "GET",
        "/api/v1/auth/oidc/session",
        {"Cookie": f"jiuwenswarm_oidc={session_cookie}"},
    )
    assert session is not None
    body = json.loads(session.body)
    assert body["user"]["sub"] == "user-1"
    assert body["user"]["email"] == "ada@example.com"
    assert body["user"]["name"] == "Ada Admin"
    assert body["accessToken"] == ACCESS
    assert proxy_user_token(f"jiuwenswarm_oidc={session_cookie}") == f"Bearer {ACCESS}"

    logout = handle_oidc_http(
        "POST",
        "/api/v1/auth/oidc/logout",
        {"Cookie": f"jiuwenswarm_oidc={session_cookie}"},
        transport=idp,
    )
    assert logout is not None and json.loads(logout.body)["ok"] is True
    assert proxy_user_token(f"jiuwenswarm_oidc={session_cookie}") == ""
    anonymous = handle_oidc_http(
        "GET",
        "/api/v1/auth/oidc/session",
        {"Cookie": f"jiuwenswarm_oidc={session_cookie}"},
    )
    assert anonymous is not None and anonymous.status == 401


def test_open_redirect_is_dropped(monkeypatch, idp):
    _enable(monkeypatch)
    response = handle_oidc_http(
        "GET",
        "/api/v1/auth/oidc/login?return_to=https://evil.example/phish",
        {},
        transport=idp,
    )
    assert response is not None
    query = _query(dict(response.headers)["Location"])
    idp.nonce = query["nonce"]
    callback = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={_cookie(response, 'jiuwenswarm_oidc_tx')}"},
        transport=idp,
    )
    assert callback is not None
    assert dict(callback.headers)["Location"] == "/"


def test_bad_signature_and_nonce_are_rejected(monkeypatch, idp):
    response, _location, query = _login(monkeypatch, idp)
    tx = _cookie(response, "jiuwenswarm_oidc_tx")
    idp.nonce = "wrong-nonce-value-not-equal"
    bad_nonce = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={tx}"},
        transport=idp,
    )
    assert bad_nonce is not None and json.loads(bad_nonce.body)["error"] == "nonce_mismatch"

    response, _location, query = _login(monkeypatch, idp)
    tx = _cookie(response, "jiuwenswarm_oidc_tx")
    idp.nonce = query["nonce"]
    from jiuwenswarm.common.auth.oidc import protocol as protocol_mod

    protocol_mod._jwks.clear()
    idp.jwk = {**idp.jwk, "n": _b64(b"\x01" * 256)}
    bad_sig = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={tx}"},
        transport=idp,
    )
    assert bad_sig is not None and json.loads(bad_sig.body)["error"] == "bad_signature"


def test_unsafe_access_token_is_not_forwarded(monkeypatch, idp):
    response, _location, query = _login(monkeypatch, idp)
    idp.access_token = "good\r\nX-Evil: 1"
    idp.claims_override = {
        "iss": ISSUER,
        "aud": "swarm-web",
        "sub": "user-1",
        "nonce": query["nonce"],
        "exp": 4_102_444_800,
        "iat": 1_700_000_000,
        "name": "Ada",
    }
    callback = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?code=abc&state={query['state']}",
        {"Cookie": f"jiuwenswarm_oidc_tx={_cookie(response, 'jiuwenswarm_oidc_tx')}"},
        transport=idp,
    )
    assert callback is not None and callback.status == 302
    assert proxy_user_token(f"jiuwenswarm_oidc={_cookie(callback, 'jiuwenswarm_oidc')}") == ""


def test_required_gate_allows_anonymous_until_configured(monkeypatch):
    handler = SimpleNamespace(
        command="GET",
        path="/",
        headers={"Cookie": ""},
        status=None,
        sent=[],
        body=b"",
    )

    def send_response(status):
        handler.status = status

    def send_header(key, value):
        handler.sent.append((key, value))

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = lambda: None
    handler.wfile = handler
    handler.write = lambda data: None
    assert block_if_required(handler) is False

    _enable(monkeypatch, JIUWENSWARM_OIDC_REQUIRED="true")
    assert block_if_required(handler) is True
    assert handler.status == 302
    assert handler.sent[-1][0] == "Location" or any(item[0] == "Location" for item in handler.sent)


def test_obo_is_disabled_unless_configured(monkeypatch, idp):
    called = False

    def transport(*_args):
        nonlocal called
        called = True
        raise AssertionError("provider contacted")

    result = exchange_on_behalf_of(
        OnBehalfOfRequest(subject_token="user-token", resource="api://graph"),
        transport=transport,
    )
    assert result.status == "disabled"
    assert called is False

    _enable(monkeypatch, JIUWENSWARM_OIDC_OBO_ENABLED="true")
    exchanged = exchange_on_behalf_of(
        OnBehalfOfRequest(subject_token="user-token", resource="api://graph", scope="user.read"),
        transport=idp,
    )
    assert exchanged.status == "exchanged"
    assert exchanged.access_token == ACCESS
    form = parse_qs(idp.calls[-1]["body"].decode())
    assert form["grant_type"][0] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert "requested_token_use" not in form


def test_provider_error_page_does_not_echo_the_code(monkeypatch, idp):
    response, _location, query = _login(monkeypatch, idp)
    failed = handle_oidc_http(
        "GET",
        f"/api/v1/auth/oidc/callback?error=access_denied&state={query['state']}&code=secret-code",
        {
            "Cookie": f"jiuwenswarm_oidc_tx={_cookie(response, 'jiuwenswarm_oidc_tx')}",
            "Accept": "text/html",
        },
        transport=idp,
    )
    assert failed is not None and failed.status == 400
    assert b"secret-code" not in failed.body
    assert b"access_denied" in failed.body


def test_web_server_calls_the_oidc_preface():
    source = Path("jiuwenswarm/channels/web/app_web.py").read_text(encoding="utf-8")
    assert "def _oidc_preface" in source
    assert "def _attach_oidc_user_token" in source
    assert source.count("if self._oidc_preface():") >= 6
