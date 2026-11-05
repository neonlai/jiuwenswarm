# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Optional RFC 8693 token-exchange hook.

This is not ADFS on-behalf-of. ADFS ``requested_token_use=on_behalf_of`` stays
a follow-up. The hook does nothing unless ``JIUWENSWARM_OIDC_OBO_ENABLED`` is
set, and nothing in the tool path calls it yet. Passing the user's access
token downstream still uses the existing ``X-User-Token`` header.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlencode

from jiuwenswarm.common.auth.oidc.config import OidcConfig, load_oidc_config
from jiuwenswarm.common.auth.oidc.protocol import OidcError, Transport, discover

logger = logging.getLogger(__name__)

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


@dataclass(frozen=True)
class OnBehalfOfRequest:
    subject_token: str
    resource: str = ""
    scope: str = ""
    audience: str = ""


@dataclass(frozen=True)
class OnBehalfOfResult:
    status: str
    access_token: str = ""
    token_type: str = ""
    error: str = ""


def exchange_on_behalf_of(
    request: OnBehalfOfRequest,
    *,
    config: OidcConfig | None = None,
    transport: Transport | None = None,
) -> OnBehalfOfResult:
    """Exchange a user access token when the operator explicitly enables OBO.

    Returns ``status="disabled"`` without contacting the provider otherwise.
    """
    resolved = config if config is not None else load_oidc_config()
    if not resolved.obo_enabled:
        return OnBehalfOfResult(status="disabled")
    if not resolved.active:
        return OnBehalfOfResult(status="not_configured", error="oidc_inactive")
    subject = request.subject_token.strip()
    if not subject or not (request.resource or request.audience):
        return OnBehalfOfResult(status="error", error="incomplete_request")
    try:
        document = discover(resolved.issuer, transport=transport)
        endpoint = str(document.get("token_endpoint") or "")
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "client_id": resolved.client_id,
        }
        if resolved.client_secret:
            form["client_secret"] = resolved.client_secret
        if request.resource:
            form["resource"] = request.resource
        if request.audience:
            form["audience"] = request.audience
        if request.scope:
            form["scope"] = request.scope
        payload = _post(endpoint, form, transport=transport)
    except OidcError as exc:
        logger.info("oidc token exchange failed: %s", exc.code)
        return OnBehalfOfResult(status="error", error=exc.code)
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return OnBehalfOfResult(status="error", error="missing_access_token")
    token_type = payload.get("token_type")
    return OnBehalfOfResult(
        status="exchanged",
        access_token=access_token,
        token_type=token_type if isinstance(token_type, str) else "Bearer",
    )


def _post(url: str, form: Mapping[str, str], *, transport: Transport | None) -> dict:
    from jiuwenswarm.common.auth.oidc.protocol import default_transport, provider_url

    endpoint = provider_url(url, "token_endpoint")
    send = transport or default_transport
    result = send(
        "POST",
        endpoint,
        urlencode(form).encode("utf-8"),
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    if result.status != 200:
        raise OidcError("token_exchange_failed")
    try:
        payload = json.loads(result.body)
    except json.JSONDecodeError as exc:
        raise OidcError("token_exchange_failed") from exc
    if not isinstance(payload, dict):
        raise OidcError("token_exchange_failed")
    return payload
