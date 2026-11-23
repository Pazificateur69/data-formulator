# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Sign in with Google, as the Search Console and Google Analytics loaders use it."""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from unittest.mock import patch

import flask
import pytest
from google.auth.credentials import AnonymousCredentials
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials

from data_formulator import data_connector
from data_formulator.data_connector import DATA_CONNECTORS, DataConnector, connectors_bp
from data_formulator.data_loader.connector_errors import classify_connector_error
from data_formulator.data_loader.google_analytics_data_loader import GoogleAnalyticsDataLoader
from data_formulator.data_loader.google_sign_in import SCOPES, SIGN_IN_EXPIRED, TOKEN_URL, user_credentials
from data_formulator.data_loader.search_console_data_loader import SearchConsoleDataLoader
from data_formulator.error_handler import register_error_handlers
from data_formulator.errors import ErrorCode

pytestmark = [pytest.mark.backend]

_LOADERS = [(SearchConsoleDataLoader, "search_console"), (GoogleAnalyticsDataLoader, "google_analytics")]
_EXPIRES_AT = datetime(2026, 11, 19, 8, 0, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "web-client.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "web-secret")


def _signed_in(**overrides):
    return {"access_token": "ya29.access", "refresh_token": "1//refresh", "token_expires_at": _EXPIRES_AT, **overrides}


# -- Offering the sign-in -----------------------------------------------------

@pytest.mark.parametrize(("loader", "product"), _LOADERS)
@pytest.mark.parametrize("env", [{}, {"GOOGLE_OAUTH_CLIENT_ID": "id"}, {"GOOGLE_OAUTH_CLIENT_SECRET": "secret"}])
def test_sign_in_is_hidden_until_the_server_has_a_client_id_and_secret(loader, product, env, monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    paths = loader.auth_paths()

    assert [path["id"] for path in paths] == ["default_credentials", "service_account_file"]
    assert paths[0]["default"] is True
    assert loader.delegated_login_config() is None


@pytest.mark.parametrize(("loader", "product"), _LOADERS)
def test_sign_in_is_the_default_once_configured(loader, product, configured) -> None:
    paths = loader.auth_paths()

    assert [path["id"] for path in paths] == ["google_sign_in", "default_credentials", "service_account_file"]
    assert paths[0]["kind"] == "delegated_login"
    assert [path["id"] for path in paths if path.get("default")] == ["google_sign_in"]
    assert loader.delegated_login_config() == {
        "login_url": f"/api/auth/google/login?product={product}", "label": "Sign in with Google", "params": [],
    }


# -- Reading with the user's credentials --------------------------------------

@pytest.mark.parametrize(("loader", "product"), _LOADERS)
def test_signed_in_loaders_read_with_the_users_own_credentials(loader, product, configured) -> None:
    credentials = loader(_signed_in())._session.credentials

    assert loader.infer_auth_path(_signed_in()) == "google_sign_in"
    assert isinstance(credentials, Credentials)
    assert credentials.token == "ya29.access"
    assert credentials.refresh_token == "1//refresh"
    assert credentials.token_uri == TOKEN_URL
    assert credentials.client_id == "web-client.apps.googleusercontent.com"
    assert credentials.client_secret == "web-secret"
    assert credentials.scopes == [SCOPES[product]]
    assert credentials.expiry == datetime(2026, 11, 19, 8, 0)  # naive UTC, as google-auth expects


@pytest.mark.parametrize(("loader", "product"), _LOADERS)
def test_a_chosen_sign_in_never_falls_back_to_the_servers_credentials(loader, product, configured) -> None:
    with patch("google.auth.default", return_value=(AnonymousCredentials(), "server-project")) as ambient:
        with pytest.raises(RefreshError, match="sign in with Google"):
            loader({"_auth_path": "google_sign_in"})

    ambient.assert_not_called()


@pytest.mark.parametrize(("loader", "product"), _LOADERS)
def test_tokens_never_leave_the_server_as_connection_params(loader, product, configured) -> None:
    safe = loader(_signed_in()).get_safe_params()

    assert "access_token" not in safe
    assert "refresh_token" not in safe


def test_credentials_without_an_expiry_are_left_to_google_to_refresh(configured) -> None:
    credentials = user_credentials({"access_token": "ya29.access"}, SCOPES["search_console"])

    assert credentials.expiry is None
    assert credentials.refresh_token is None


# -- Refreshing ---------------------------------------------------------------

class _GoogleResponse:
    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self.headers = {"content-type": "application/json"}
        self.data = json.dumps(payload).encode()


def test_an_expired_access_token_is_refreshed_with_the_refresh_token(configured) -> None:
    sent = []

    def google(url, method="GET", body=None, headers=None, **kwargs):
        sent.append((url, method, urllib.parse.parse_qs(body.decode())))
        return _GoogleResponse(200, {"access_token": "ya29.fresh", "expires_in": 3599,
                                     "scope": SCOPES["search_console"], "token_type": "Bearer"})

    credentials = user_credentials(_signed_in(), SCOPES["search_console"])
    credentials.refresh(google)

    [(url, method, form)] = sent
    assert (url, method) == (TOKEN_URL, "POST")
    assert form["grant_type"] == ["refresh_token"]
    assert form["refresh_token"] == ["1//refresh"]
    assert form["client_id"] == ["web-client.apps.googleusercontent.com"]
    assert form["client_secret"] == ["web-secret"]
    assert credentials.token == "ya29.fresh"


def _revoked(url, method="GET", body=None, headers=None, **kwargs):
    return _GoogleResponse(400, {"error": "invalid_grant", "error_description": "Token has been expired or revoked."})


@pytest.mark.parametrize(("params", "transport"), [
    (_signed_in(), _revoked),               # the user revoked access, or the refresh token expired
    (_signed_in(refresh_token=""), None),   # nothing to refresh with
])
def test_a_lapsed_sign_in_asks_the_user_to_sign_in_again(configured, params, transport) -> None:
    credentials = user_credentials(params, SCOPES["search_console"])

    with pytest.raises(RefreshError) as error:
        credentials.refresh(transport)

    assert str(error.value) == SIGN_IN_EXPIRED
    assert classify_connector_error(error.value).code == ErrorCode.AUTH_EXPIRED


def test_a_workspace_reauthentication_asks_the_user_to_sign_in_again(configured, monkeypatch) -> None:
    def reauth_needed(self, request):
        raise RefreshError("Reauthentication is needed. Please run `gcloud auth application-default login` "
                           "to reauthenticate.")

    monkeypatch.setattr(Credentials, "refresh", reauth_needed)

    with pytest.raises(RefreshError, match="sign in with Google"):
        user_credentials(_signed_in(), SCOPES["search_console"]).refresh(None)


@pytest.mark.parametrize("failure", [
    RefreshError("temporarily_unavailable: try later", {"error": "temporarily_unavailable"}, retryable=True),
    RefreshError("invalid_client: Unauthorized", {"error": "invalid_client"}),
])
def test_other_refresh_failures_keep_googles_error(configured, monkeypatch, failure) -> None:
    def failing(self, request):
        raise failure

    monkeypatch.setattr(Credentials, "refresh", failing)

    with pytest.raises(RefreshError) as error:
        user_credentials(_signed_in(), SCOPES["search_console"]).refresh(None)

    assert error.value is failure
    assert error.value.retryable is failure.retryable


@pytest.mark.parametrize(("loader", "product"), _LOADERS)
def test_a_lapsed_sign_in_surfaces_before_any_request_leaves(loader, product, configured) -> None:
    instance = loader(_signed_in(refresh_token="", token_expires_at=1.0))

    with pytest.raises(RefreshError, match="sign in with Google"):
        instance._session.request("GET", "https://example.invalid/")
    with pytest.raises(RefreshError, match="sign in with Google"):
        instance.test_connection()


# -- Through the connect route --------------------------------------------------

@pytest.fixture
def connect(configured, monkeypatch):
    """POST a token connect for a Search Console connector, the way the sign-in popup's opener does."""
    # Keep the route away from the shared vault and the loaded-identity cache other tests rely on.
    monkeypatch.setattr(DataConnector, "_get_vault", staticmethod(lambda: None))
    monkeypatch.setattr(data_connector, "_LOADED_USER_IDENTITIES", set())
    monkeypatch.setattr(DataConnector, "_get_identity", staticmethod(lambda: "google-sign-in-test-user"))
    monkeypatch.setitem(DATA_CONNECTORS, "search_console_test", DataConnector.from_loader(
        SearchConsoleDataLoader, source_id="search_console_test", display_name="Search Console"))
    app = flask.Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-secret"
    app.register_blueprint(connectors_bp)
    register_error_handlers(app)
    client = app.test_client()

    def post(**tokens):
        return client.post("/api/connectors/connect", json={
            "connector_id": "search_console_test", "mode": "token", "persist": False,
            "params": {"_auth_path": "google_sign_in", "site_url": ""}, **tokens,
        }).get_json()

    return post


def test_signing_in_connects_without_returning_the_tokens(connect, monkeypatch) -> None:
    monkeypatch.setattr(SearchConsoleDataLoader, "_sites", lambda self: ["sc-domain:example.com"])

    body = connect(access_token="ya29.access", refresh_token="1//refresh", expires_in=3599)

    assert body["data"]["status"] == "connected"
    assert "ya29.access" not in json.dumps(body)
    assert "1//refresh" not in json.dumps(body)


def test_an_expired_sign_in_is_reported_as_expired(connect) -> None:
    body = connect(access_token="ya29.stale", refresh_token="", expires_in=-60)

    assert body["status"] == "error"
    assert body["error"]["code"] == ErrorCode.AUTH_EXPIRED
