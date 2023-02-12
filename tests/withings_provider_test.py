from __future__ import annotations

import os
import time
from collections.abc import Generator
from json import JSONDecodeError
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from egg_stats import withings_provider
from egg_stats.withings_provider import _AuthClient
from egg_stats.withings_provider import _AuthedUser
from egg_stats.withings_provider import HTTPResponse
from egg_stats.withings_provider import WithingsProvider


MOCK_AUTH_USER: Any = {
    "userid": "mockuserid",
    "access_token": "mock_access_token",
    "refresh_token": "mock_refresh_token",
    "scope": "user.activity,user.metrics",
    "expiry": time.time() + 1000,
    "token_type": "Bearer",
}
MOCK_AUTH_RESPONSE: Any = {
    "status": 0,
    "body": {
        "userid": "mockuserid",
        "access_token": "mock_access_token",
        "refresh_token": "mock_refresh_token",
        "scope": "user.activity,user.metrics",
        "expires_in": time.time() + 1000,
        "token_type": "Bearer",
    },
}


@pytest.fixture(autouse=True)
def mock_env() -> Generator[None, None, None]:
    """Mock the environment variables."""
    mask_env = {
        "WITHINGS_CLIENT_ID": "",
        "WITHINGS_CLIENT_SECRET": "",
    }

    with patch.dict(os.environ, mask_env):
        yield None


@pytest.fixture
def auth_client() -> _AuthClient:
    return _AuthClient("mock", "mock", MagicMock())


@pytest.fixture
def provider(auth_client: _AuthClient) -> WithingsProvider:
    withing_provider = WithingsProvider("mock", "mock")
    withing_provider._auth_client = auth_client
    return withing_provider


def test_HTTPResponse_handles_empty_json() -> None:
    """Test the HTTPResponse class."""
    response = MagicMock()
    response.json.side_effect = JSONDecodeError("msg", "doc", 0)
    response.status_code = 204
    response.url = "https://example.com"
    response.is_success = False

    http_response = HTTPResponse(response)

    assert http_response.json() == {}
    assert http_response.status_code == 204
    assert http_response.url == "https://example.com"
    assert http_response.is_success is False


def test_HTTPResponse_handles_200() -> None:
    """Test the HTTPResponse class."""
    response = MagicMock()
    response.json.return_value = {"status": 0}
    response.status_code = 200
    response.url = "https://example.com"
    response.is_success = True

    http_response = HTTPResponse(response)

    assert http_response.json() == {"status": 0}
    assert http_response.status_code == 200
    assert http_response.url == "https://example.com"
    assert http_response.is_success is True


def test_AuthedUser_from_dict() -> None:
    body = MOCK_AUTH_RESPONSE["body"]
    authed_user = _AuthedUser.from_dict(body)

    assert authed_user.userid == body["userid"]
    assert authed_user.access_token == body["access_token"]
    assert authed_user.refresh_token == body["refresh_token"]
    assert authed_user.scope == body["scope"]
    # Less than due to the expiry buffer being subtracted
    assert authed_user.expiry < time.time() + body["expires_in"]
    assert authed_user.token_type == body["token_type"]


def test_AuthClient_raises_ValueError_if_no_client_id() -> None:
    from egg_stats.withings_provider import _AuthClient

    with pytest.raises(ValueError):
        _AuthClient()


def test_AuthClient_reads_secrets_from_env() -> None:
    os.environ["WITHINGS_CLIENT_ID"] = "foo"
    os.environ["WITHINGS_CLIENT_SECRET"] = "bar"

    auth_client = _AuthClient()

    assert auth_client.client_id == "foo"
    assert auth_client.client_secret == "bar"


def test_AuthClient_reads_secrets_from_args() -> None:
    os.environ["WITHINGS_CLIENT_ID"] = "foo"
    os.environ["WITHINGS_CLIENT_SECRET"] = "bar"

    auth_client = _AuthClient("high", "low")

    assert auth_client.client_id == "high"
    assert auth_client.client_secret == "low"


def test_get_state_code(auth_client: _AuthClient) -> None:
    result01 = auth_client.create_state_code()
    result02 = auth_client.create_state_code()

    assert result01 != result02


def test_get_authorization_url(auth_client: _AuthClient) -> None:
    resp = HTTPResponse(MagicMock())
    resp.url = "https://account.withings.com/oauth2_user/authorize2"
    state = "mock_challenge"
    rd_url = "https://mock_redirect_url.com/mock"
    scope = "mock_scope"
    expected_params = {
        "response_type": "code",
        "client_id": "mock",
        "scope": scope,
        "state": state,
        "redirect_uri": rd_url,
    }
    url = withings_provider.AUTH_URL

    with patch.object(auth_client, "_handle_http", return_value=resp) as mock_http:
        result = auth_client.get_authorization_url(rd_url, scope, state)

    assert result == resp.url
    mock_http.assert_called_once_with("GET", url, params=expected_params)


def test_authenticate(auth_client: _AuthClient) -> None:
    mockresp = HTTPResponse(MagicMock())
    mockresp._json = MOCK_AUTH_RESPONSE
    code = "mockcode"
    redirect_uri = "https://mock_redirect_url.com/mock"
    expected_params = {
        "action": "requesttoken",
        "client_id": "mock",
        "client_secret": "mock",
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    url = f"{withings_provider.BASE_URL}/v2/oauth2"

    with patch.object(auth_client, "_handle_http", return_value=mockresp) as mock_http:
        auth_client.authenticate(code, redirect_uri)

    assert auth_client._authed_user is not None
    assert auth_client._authed_user.userid == MOCK_AUTH_RESPONSE["body"]["userid"]
    mock_http.assert_called_once_with("POST", url, params=expected_params)


def test_get_bearer_token_with_existing(auth_client: _AuthClient) -> None:
    auth_client._authed_user = _AuthedUser(**MOCK_AUTH_USER)

    result = auth_client._get_bearer_token()

    assert result == auth_client._authed_user.access_token


def test_get_bearer_token_refresh(auth_client: _AuthClient) -> None:
    auth_client._authed_user = _AuthedUser(**MOCK_AUTH_USER)
    auth_client._authed_user.expiry = 0

    with patch.object(auth_client, "_refresh_access_token") as mock_refresh:
        mock_refresh.return_value = _AuthedUser(**MOCK_AUTH_USER)
        result = auth_client._get_bearer_token()

    mock_refresh.assert_called_once()
    assert result == MOCK_AUTH_RESPONSE["body"]["access_token"]


def test_get_bearer_token_no_authed_user(auth_client: _AuthClient) -> None:
    with pytest.raises(ValueError, match="^Expected authenticated user.$"):
        auth_client._get_bearer_token()


def test_get_headers(auth_client: _AuthClient) -> None:
    with patch.object(auth_client, "_get_bearer_token") as mock_token:
        mock_token.return_value = "mocktoken"
        result = auth_client.get_headers()

    mock_token.assert_called_once()
    assert result["Authorization"] == "Bearer mocktoken"


def test_refresh_access_token(auth_client: _AuthClient) -> None:
    mockresp = HTTPResponse(MagicMock())
    mockresp._json = MOCK_AUTH_RESPONSE
    expected_params = {
        "action": "requesttoken",
        "client_id": "mock",
        "client_secret": "mock",
        "grant_type": "refresh_token",
        "refresh_token": "mock_refresh_token",
    }
    url = f"{withings_provider.BASE_URL}/v2/oauth2"

    with patch.object(auth_client, "_handle_http", return_value=mockresp) as mock_http:
        result = auth_client._refresh_access_token(_AuthedUser(**MOCK_AUTH_USER))

    assert result.userid == MOCK_AUTH_USER["userid"]
    mock_http.assert_called_once_with("POST", url, params=expected_params)


def test_create_signature(auth_client: _AuthClient) -> None:
    result = auth_client.get_signature("mockdata", "12345")
    # This is the expected result of the above data and timestamp
    assert result == "8b3db37b7c80908b944b7fc5164c42b235da89772cf56c745a734bf74dac287a"


def test_get_nonce(auth_client: _AuthClient) -> None:
    mockresp = HTTPResponse(MagicMock())
    mockresp._json = {"status": 0, "body": {"nonce": "mock"}}
    set_timestamp = 12345
    expected_params = {
        "action": "getnonce",
        "client_id": "mock",
        "signature": auth_client.get_signature("getnonce", str(set_timestamp)),
        "timestamp": str(set_timestamp),
    }
    url = f"{withings_provider.BASE_URL}/v2/signature"

    with patch("time.time", return_value=set_timestamp):
        with patch.object(auth_client, "_handle_http", return_value=mockresp) as mock:
            result = auth_client.get_nonce()

    assert result == "mock"
    mock.assert_called_once_with("POST", url, params=expected_params)


def test_revoke_access_token(auth_client: _AuthClient) -> None:
    auth_client._authed_user = _AuthedUser(**MOCK_AUTH_USER)
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 0, "body": {}}
    set_nonce = "mocknonce"
    expected_params = {
        "action": "revoke",
        "client_id": "mock",
        "nonce": set_nonce,
        "signature": auth_client.get_signature("revoke", set_nonce),
        "userid": "mockuserid",
    }
    url = f"{withings_provider.BASE_URL}/v2/oauth2"

    with patch.object(auth_client._http, "request", return_value=mock_resp) as mockhttp:
        with patch.object(auth_client, "get_nonce", return_value=set_nonce):
            auth_client._revoke_access_token()

    mockhttp.assert_called_once_with("POST", url, params=expected_params)


def test_auth_client_handle_http(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 0, "body": {"mock": "body"}}
    url = "https://mockurl.com"
    params = {"mock": "params"}
    verb = "GET"

    with patch.object(auth_client._http, "request", return_value=mock_resp) as mock:
        resp = auth_client._handle_http(verb, url, params)

    mock.assert_called_once_with(verb, url, params=params)
    assert resp.is_success is True
    assert resp.json() == {"status": 0, "body": {"mock": "body"}}


def test_auth_client_handle_http_failure(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 1, "body": {"mock": "body"}}

    with patch.object(auth_client, "get_headers", return_value={}):
        with patch.object(auth_client._http, "request", return_value=mock_resp):
            with pytest.raises(ValueError, match="^Failed"):
                auth_client._handle_http("GET", "mock", {})


def test_withings_provider_handle_http(provider: WithingsProvider) -> None:
    mock_headers = {"Authorization": "Bearer mocktoken"}
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 0, "body": {"mock": "body"}}
    url = "https://mockurl.com"
    params = {"mock": "params"}
    verb = "GET"

    with patch.object(provider._auth_client, "get_headers", return_value=mock_headers):
        with patch.object(provider._http, "request", return_value=mock_resp) as mock:
            resp = provider._handle_http(verb, url, params)

    mock.assert_called_once_with(verb, url, headers=mock_headers, params=params)
    assert resp.is_success is True
    assert resp.json() == {"status": 0, "body": {"mock": "body"}}


def test_withings_provider_handle_http_failure(provider: WithingsProvider) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 1, "body": {"mock": "body"}}

    with patch.object(provider._auth_client, "get_headers", return_value={}):
        with patch.object(provider._http, "request", return_value=mock_resp):
            with pytest.raises(ValueError, match="^Failed"):
                provider._handle_http("GET", "mock", {})


def test_withings_provider_activity_list(provider: WithingsProvider) -> None:
    # NOTE: This will fail if run between 23:59:59 and 00:00:00
    resp = [{"mock": "resp"}]
    url = f"{withings_provider.BASE_URL}/v2/measure"
    days = 12
    starttime = int(time.time()) - (days * 24 * 60 * 60)

    params = {
        "action": "getactivity",
        "startdateymd": time.strftime("%Y-%m-%d", time.localtime(starttime)),
        "enddateymd": time.strftime("%Y-%m-%d", time.localtime()),
        "data_fields": ",".join(withings_provider.DATA_FIELDS),
    }

    with patch.object(provider, "_handle_paginated", return_value=resp) as mock_http:
        result = provider.activity_list(days)

    assert result == resp
    mock_http.assert_called_once_with("activities", "POST", url, params)


def test_withings_provider_handle_paginated(provider: WithingsProvider) -> None:
    side_effect = [
        MagicMock(status_code=200, json=MagicMock()),
        MagicMock(status_code=200, json=MagicMock()),
    ]
    side_effect[0].json.return_value = {
        "status": 0,
        "body": {"more": True, "offset": 1, "series": [1]},
    }
    side_effect[1].json.return_value = {
        "status": 0,
        "body": {"more": False, "offset": 2, "series": [2]},
    }
    expected = [1, 2]

    with patch.object(provider, "_handle_http", side_effect=side_effect) as mock_http:
        result = provider._handle_paginated(
            label="series",
            verb="POST",
            url="mockurl",
            params={"mock": "params"},
        )

    assert result == expected
    assert mock_http.call_count == 2


def test_withings_provider_user(provider: WithingsProvider) -> None:
    mock_user = _AuthedUser.from_dict(MOCK_AUTH_RESPONSE["body"])
    provider._auth_client._authed_user = mock_user

    user = provider.user

    assert user.userid == mock_user.userid
    assert user.refresh_token == mock_user.refresh_token


def test_withings_provider_user_no_auth(provider: WithingsProvider) -> None:
    provider._auth_client._authed_user = None

    with pytest.raises(ValueError, match="^Not authenticated"):
        provider.user


def test_withings_provider_get_authentication_url(provider: WithingsProvider) -> None:
    state = "mockstate"
    redirect_uri = "https://mockurl.com"
    scope = "mockscope"

    with patch.object(provider._auth_client, "create_state_code", return_value=state):
        with patch.object(provider._auth_client, "get_authorization_url") as mock:
            url = provider.get_authentication_url(redirect_uri, scope)

    mock.assert_called_once_with(redirect_uri, scope, state)
    assert url == mock.return_value
    assert provider._last_state == state


def test_withings_provider_authenticate(provider: WithingsProvider) -> None:
    code = "mockcode"
    state = "mockstate"
    redirect_uri = "https://mockurl.com"
    provider._last_state = state

    with patch.object(provider._auth_client, "authenticate") as mock:
        provider.authenticate(code, state, redirect_uri)

    mock.assert_called_once_with(code, redirect_uri)


def test_withings_provider_authenticate_bad_state(provider: WithingsProvider) -> None:
    code = "mockcode"
    state = "mockstate"
    redirect_uri = "https://mockurl.com"
    provider._last_state = "badstate"

    with pytest.raises(ValueError, match="^Invalid state"):
        provider.authenticate(code, state, redirect_uri)


# TODO: Move to where authentication happens
def test_split_response() -> None:
    response = "https://localhost:8080/?code=foo&state=bar"
    expected = ("foo", "bar")
    result = withings_provider.split_response(response)

    assert result == expected


# TODO: Move to where authentication happens
def test_get_response_url() -> None:
    url = "https://account.withings.com/oauth2_user/authorize2"
    expected = "https://localhost:8080/?code=foo&state=bar"

    with patch("builtins.input", return_value=expected):
        result = withings_provider.get_response_url(url)

    assert result == expected
