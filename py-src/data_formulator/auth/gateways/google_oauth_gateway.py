# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Google delegated OAuth flow (Authorization Code + PKCE) for the Search Console and Google Analytics connectors."""

from __future__ import annotations

import os
import secrets
import time
import urllib.parse
from typing import Any

import requests as http
from flask import Blueprint, Response, request, session

from data_formulator.auth.gateways.kusto_oauth_gateway import _frontend_origin, _pkce_challenge, _popup_response
from data_formulator.data_loader.google_sign_in import (
    SCOPES,
    TOKEN_URL,
    configured,
    oauth_client_id,
    oauth_client_secret,
)
from data_formulator.errors import AppError, ErrorCode

google_oauth_bp = Blueprint("google_oauth", __name__, url_prefix="/api/auth/google")

_STATE_KEY = "google_oauth_state"
_STATE_TTL_SECONDS = 600
_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"


def _callback_url() -> str:
    return os.environ.get(
        "GOOGLE_OAUTH_REDIRECT_URI",
        request.url_root.rstrip("/") + "/api/auth/google/callback",
    )


def _popup(origin: str, payload: dict[str, Any]) -> Response:
    return _popup_response(origin, {"type": "df-sso-auth", **payload}, title="Google sign-in")


@google_oauth_bp.route("/login")
def google_login():
    """Start sign-in with the read-only scope of the requested Google product."""
    if not configured():
        raise AppError(ErrorCode.SERVICE_UNAVAILABLE, "Google sign-in is not configured")
    scope = SCOPES.get(request.args.get("product", ""))
    if not scope:
        raise AppError(ErrorCode.INVALID_REQUEST, "Unknown Google product")

    origin = _frontend_origin(request.args.get("df_origin", ""), "GOOGLE_OAUTH_ALLOWED_ORIGINS")
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    states = {
        key: value
        for key, value in session.get(_STATE_KEY, {}).items()
        if time.time() - value.get("created_at", 0) <= _STATE_TTL_SECONDS
    }
    states[state] = {"verifier": verifier, "origin": origin, "scope": scope, "created_at": time.time()}
    session[_STATE_KEY] = states

    params = {
        "client_id": oauth_client_id(),
        "redirect_uri": _callback_url(),
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
        # Google returns a refresh token only for an offline grant, and only on a consent screen.
        "access_type": "offline",
        "prompt": "select_account consent",
    }
    response = Response(status=302)
    response.headers["Location"] = f"{_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    return response


@google_oauth_bp.route("/callback")
def google_callback():
    """Exchange the authorization code and hand the tokens to the opener window."""
    state = request.args.get("state", "")
    states = session.get(_STATE_KEY, {})
    pending = states.pop(state, None)
    session[_STATE_KEY] = states
    if not pending or time.time() - pending.get("created_at", 0) > _STATE_TTL_SECONDS:
        raise AppError(ErrorCode.INVALID_REQUEST, "Invalid or expired Google OAuth state")

    origin = pending["origin"]
    if request.args.get("error"):
        return _popup(origin, {"error": "Google sign-in failed"})
    code = request.args.get("code")
    if not code:
        return _popup(origin, {"error": "Google did not return an authorization code"})

    token_data = {
        "client_id": oauth_client_id(),
        "client_secret": oauth_client_secret(),
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _callback_url(),
        "code_verifier": pending["verifier"],
    }
    try:
        token_response = http.post(TOKEN_URL, data=token_data, timeout=15)
        tokens = token_response.json() if token_response.ok else {}
    except (http.RequestException, ValueError):
        tokens = {}
    if not isinstance(tokens, dict) or not tokens.get("access_token"):
        return _popup(origin, {"error": "Google token exchange failed"})

    # Google lets users untick a permission on its consent screen; without it every query would fail.
    # OAuth 2.0 lets the response leave out scope only when it equals the requested one.
    if "scope" in tokens and pending["scope"] not in str(tokens["scope"]).split():
        return _popup(origin, {"error": "Google sign-in did not grant read access; sign in again and allow it"})

    return _popup(origin, {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expires_in": tokens.get("expires_in", 3600),
    })
