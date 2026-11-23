# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Sign in with Google, shared by the Search Console and Google Analytics loaders.

When the server has a Google OAuth client (``GOOGLE_OAUTH_CLIENT_ID`` and
``GOOGLE_OAUTH_CLIENT_SECRET``), users sign in with their own Google account in
a popup run by ``auth/gateways/google_oauth_gateway.py``, and the loaders read
with that account's access. google-auth refreshes the access token with the
refresh token.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials

TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = {
    "search_console": "https://www.googleapis.com/auth/webmasters.readonly",
    "google_analytics": "https://www.googleapis.com/auth/analytics.readonly",
}
AUTH_PATH_ID = "google_sign_in"
SIGN_IN_EXPIRED = "Your Google sign-in session expired or was revoked; connect again and sign in with Google."
_LABEL = "Sign in with Google"


def oauth_client_id() -> str:
    return os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()


def oauth_client_secret() -> str:
    return os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()


def configured() -> bool:
    # google-auth refreshes user credentials only with the client secret, so sign-in needs both.
    return bool(oauth_client_id() and oauth_client_secret())


def sign_in_path(description: str) -> dict[str, Any]:
    return {"id": AUTH_PATH_ID, "label": _LABEL, "description": description,
            "fields": [], "required_fields": [], "kind": "delegated_login", "default": True}


def delegated_login_config(product: str) -> dict[str, Any] | None:
    if not configured():
        return None
    # No connection params go to the login: the account's own access decides what is listed.
    return {"login_url": f"/api/auth/google/login?product={product}", "label": _LABEL, "params": []}


def _needs_new_sign_in(error: RefreshError) -> bool:
    """invalid_grant: the user revoked access, the refresh token expired, or a Workspace session limit was reached."""
    details = error.args[1] if len(error.args) > 1 else None
    if isinstance(details, dict):
        return details.get("error") == "invalid_grant"
    # google-auth reports a Workspace reauthentication request (also invalid_grant) without the response.
    return str(error).startswith("Reauthentication is needed")


class _SignedInCredentials(Credentials):
    """Asks the user to sign in again when the sign-in can no longer be refreshed.

    Other refresh failures, such as Google being briefly unavailable, keep
    google-auth's message and retryable flag.
    """

    def refresh(self, request: Any) -> None:
        if not self.refresh_token:
            raise RefreshError(SIGN_IN_EXPIRED)
        try:
            super().refresh(request)
        except RefreshError as exc:
            if _needs_new_sign_in(exc):
                raise RefreshError(SIGN_IN_EXPIRED) from exc
            raise


def user_credentials(params: dict[str, Any], scope: str) -> Credentials:
    """Credentials for the signed-in user from the tokens the sign-in popup returned."""
    if not params.get("access_token"):
        raise RefreshError(SIGN_IN_EXPIRED)
    expires_at = float(params.get("token_expires_at") or 0)
    return _SignedInCredentials(
        token=params["access_token"],
        refresh_token=params.get("refresh_token") or None,
        token_uri=TOKEN_URL,
        client_id=oauth_client_id() or None,
        client_secret=oauth_client_secret() or None,
        scopes=[scope],
        # google-auth compares expiry against naive UTC.
        expiry=datetime.fromtimestamp(expires_at, timezone.utc).replace(tzinfo=None) if expires_at else None,
    )
