# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import json
import re
import urllib.parse

import flask
import pytest
import requests

from data_formulator.auth.gateways import google_oauth_gateway as gateway
from data_formulator.auth.gateways.kusto_oauth_gateway import _pkce_challenge
from data_formulator.data_loader.google_sign_in import SCOPES, TOKEN_URL
from data_formulator.error_handler import register_error_handlers

pytestmark = [pytest.mark.backend, pytest.mark.auth]

_ORIGIN = "http://localhost:5173"
_SC_SCOPE = SCOPES["search_console"]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "web-client.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "web-secret")
    monkeypatch.delenv("GOOGLE_OAUTH_REDIRECT_URI", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_ALLOWED_ORIGINS", raising=False)
    app = flask.Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-secret"
    app.register_blueprint(gateway.google_oauth_bp)
    register_error_handlers(app)
    return app.test_client()


class _TokenResponse:
    def __init__(self, payload, ok=True):
        self._payload = payload
        self.ok = ok

    def json(self):
        return self._payload


def _login(client, product="search_console"):
    response = client.get("/api/auth/google/login", query_string={"product": product, "df_origin": _ORIGIN})
    assert response.status_code == 302
    location = urllib.parse.urlparse(response.headers["Location"])
    return location, {key: values[0] for key, values in urllib.parse.parse_qs(location.query).items()}


def _token_exchange(monkeypatch, payload=None, ok=True):
    """Stub Google's token endpoint and record what was posted to it."""
    posted = []

    def post(url, data, timeout):
        posted.append((url, data))
        return _TokenResponse(payload if payload is not None else {
            "access_token": "ya29.access", "refresh_token": "1//refresh",
            "expires_in": 3599, "scope": _SC_SCOPE, "token_type": "Bearer",
        }, ok=ok)

    monkeypatch.setattr(gateway.http, "post", post)
    return posted


def _popup_message(response):
    """Return the (payload, target origin) the popup page posts to its opener."""
    body = response.get_data(as_text=True)
    match = re.search(r"window\.opener\.postMessage\((\{.*\}), (\".*\")\);", body)
    assert match, body
    return json.loads(match[1]), json.loads(match[2])


@pytest.mark.parametrize("product", ["search_console", "google_analytics"])
def test_login_asks_google_for_an_offline_read_only_grant_with_pkce(client, product) -> None:
    location, query = _login(client, product)

    assert f"{location.scheme}://{location.netloc}{location.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
    assert query["client_id"] == "web-client.apps.googleusercontent.com"
    assert query["redirect_uri"] == "http://localhost/api/auth/google/callback"
    assert query["response_type"] == "code"
    assert query["scope"] == SCOPES[product]
    assert query["code_challenge_method"] == "S256"
    assert query["access_type"] == "offline"
    assert query["prompt"] == "select_account consent"
    assert query["state"] and query["code_challenge"]


def test_login_uses_the_configured_redirect_uri(client, monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_OAUTH_REDIRECT_URI", "https://df.example.com/api/auth/google/callback")

    _, query = _login(client)

    assert query["redirect_uri"] == "https://df.example.com/api/auth/google/callback"


@pytest.mark.parametrize(("query", "code"), [
    ({"product": "drive", "df_origin": _ORIGIN}, "INVALID_REQUEST"),
    ({"df_origin": _ORIGIN}, "INVALID_REQUEST"),
    ({"product": "search_console", "df_origin": "https://evil.example"}, "INVALID_REQUEST"),
])
def test_login_rejects_unknown_products_and_foreign_origins(client, query, code) -> None:
    body = client.get("/api/auth/google/login", query_string=query).get_json()

    assert body["status"] == "error"
    assert body["error"]["code"] == code


@pytest.mark.parametrize("missing", ["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"])
def test_login_requires_a_configured_client_and_secret(client, monkeypatch, missing) -> None:
    monkeypatch.delenv(missing)

    body = client.get("/api/auth/google/login",
                      query_string={"product": "search_console", "df_origin": _ORIGIN}).get_json()

    assert body["error"]["code"] == "SERVICE_UNAVAILABLE"


def test_callback_exchanges_the_code_and_posts_the_tokens_to_the_opener(client, monkeypatch) -> None:
    _, login = _login(client)
    posted = _token_exchange(monkeypatch)

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    [(url, data)] = posted
    assert url == TOKEN_URL
    assert data["grant_type"] == "authorization_code"
    assert data["code"] == "4/code"
    assert data["redirect_uri"] == login["redirect_uri"]
    assert data["client_id"] == "web-client.apps.googleusercontent.com"
    assert data["client_secret"] == "web-secret"
    assert _pkce_challenge(data["code_verifier"]) == login["code_challenge"]
    payload, target = _popup_message(response)
    assert target == _ORIGIN
    assert payload == {"type": "df-sso-auth", "access_token": "ya29.access",
                       "refresh_token": "1//refresh", "expires_in": 3599}
    assert "<title>Google sign-in</title>" in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_a_state_works_once(client, monkeypatch) -> None:
    _, login = _login(client)
    _token_exchange(monkeypatch)
    client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    body = client.get("/api/auth/google/callback",
                      query_string={"state": login["state"], "code": "4/code"}).get_json()

    assert body["error"]["code"] == "INVALID_REQUEST"


def test_callback_rejects_an_unknown_state(client, monkeypatch) -> None:
    posted = _token_exchange(monkeypatch)

    body = client.get("/api/auth/google/callback", query_string={"state": "forged", "code": "4/code"}).get_json()

    assert body["error"]["code"] == "INVALID_REQUEST"
    assert posted == []


def test_callback_rejects_an_expired_state(client, monkeypatch) -> None:
    _, login = _login(client)
    posted = _token_exchange(monkeypatch)
    later = gateway.time.time() + 601
    monkeypatch.setattr(gateway.time, "time", lambda: later)

    body = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"}).get_json()

    assert body["error"]["code"] == "INVALID_REQUEST"
    assert posted == []


@pytest.mark.parametrize(("query", "message"), [
    ({"error": "access_denied"}, "Google sign-in failed"),
    ({}, "Google did not return an authorization code"),
])
def test_callback_reports_a_cancelled_or_incomplete_sign_in(client, monkeypatch, query, message) -> None:
    _, login = _login(client)
    posted = _token_exchange(monkeypatch)

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], **query})

    assert _popup_message(response) == ({"type": "df-sso-auth", "error": message}, _ORIGIN)
    assert posted == []


@pytest.mark.parametrize(("payload", "ok"), [
    ({"error": "invalid_grant"}, False),
    ({"token_type": "Bearer"}, True),
    (["not", "an", "object"], True),
])
def test_callback_reports_a_failed_token_exchange(client, monkeypatch, payload, ok) -> None:
    _, login = _login(client)
    _token_exchange(monkeypatch, payload, ok=ok)

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    assert _popup_message(response) == ({"type": "df-sso-auth", "error": "Google token exchange failed"}, _ORIGIN)


class _GarbledResponse:
    ok = True

    def json(self):
        raise requests.JSONDecodeError("Expecting value", "<html>", 0)


@pytest.mark.parametrize("outcome", [requests.ConnectionError("down"), _GarbledResponse()])
def test_callback_reports_an_unreachable_or_garbled_token_endpoint(client, monkeypatch, outcome) -> None:
    _, login = _login(client)

    def post(url, data, timeout):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(gateway.http, "post", post)

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    assert _popup_message(response) == ({"type": "df-sso-auth", "error": "Google token exchange failed"}, _ORIGIN)


@pytest.mark.parametrize("granted", ["openid", "", None])
def test_callback_rejects_a_grant_without_the_read_scope(client, monkeypatch, granted) -> None:
    _, login = _login(client)
    _token_exchange(monkeypatch, {"access_token": "ya29.access", "expires_in": 3599, "scope": granted})

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    payload, _ = _popup_message(response)
    assert "access_token" not in payload
    assert payload["error"] == "Google sign-in did not grant read access; sign in again and allow it"


def test_callback_accepts_a_response_that_omits_the_scope(client, monkeypatch) -> None:
    # OAuth 2.0 lets the token response leave out scope when it equals the requested one.
    _, login = _login(client)
    _token_exchange(monkeypatch, {"access_token": "ya29.access", "expires_in": 3599})

    response = client.get("/api/auth/google/callback", query_string={"state": login["state"], "code": "4/code"})

    payload, _ = _popup_message(response)
    assert payload["access_token"] == "ya29.access"
    assert payload["refresh_token"] is None
