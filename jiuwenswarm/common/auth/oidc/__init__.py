# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Generic OpenID Connect sign-in for the web channel.

The flow stays inactive until an issuer, client id, and redirect URI are
configured. Huawei Account Kit login and unsigned local use are unchanged
when this package is left unconfigured.
"""

from jiuwenswarm.common.auth.oidc.config import OidcConfig, load_oidc_config
from jiuwenswarm.common.auth.oidc.obo import (
    OnBehalfOfRequest,
    OnBehalfOfResult,
    exchange_on_behalf_of,
)
from jiuwenswarm.common.auth.oidc.protocol import reset_oidc_for_test

__all__ = [
    "OidcConfig",
    "OnBehalfOfRequest",
    "OnBehalfOfResult",
    "exchange_on_behalf_of",
    "load_oidc_config",
    "reset_oidc_for_test",
]
