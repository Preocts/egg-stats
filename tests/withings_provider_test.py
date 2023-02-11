from __future__ import annotations

import os
import time
from collections.abc import Generator
from json import JSONDecodeError
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from egg_stats.withings_provider import _AuthClient
from egg_stats.withings_provider import _AuthedUser
from egg_stats.withings_provider import HTTPResponse

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
        "EGGSTATS_CLIENT_ID": "",
        "EGGSTATS_CLIENT_SECRET": "",
    }

    with patch.dict(os.environ, mask_env):
        yield None


@pytest.fixture
def auth_client() -> _AuthClient:
    return _AuthClient("mock", "mock")


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


def test_AuthClient_raises_ValueError_if_no_client_id() -> None:
    from egg_stats.withings_provider import _AuthClient

    with pytest.raises(ValueError):
        _AuthClient()


def test_AuthClient_reads_secrets_from_env() -> None:
    os.environ["EGGSTATS_CLIENT_ID"] = "foo"
    os.environ["EGGSTATS_CLIENT_SECRET"] = "bar"

    auth_client = _AuthClient()

    assert auth_client.client_id == "foo"
    assert auth_client.client_secret == "bar"


def test_AuthClient_reads_secrets_from_args() -> None:
    os.environ["EGGSTATS_CLIENT_ID"] = "foo"
    os.environ["EGGSTATS_CLIENT_SECRET"] = "bar"

    auth_client = _AuthClient("high", "low")

    assert auth_client.client_id == "high"
    assert auth_client.client_secret == "low"


def test_code_verifier(auth_client: _AuthClient) -> None:
    result = auth_client._code_verifier()

    assert isinstance(result, str)


def test_code_challenge(auth_client: _AuthClient) -> None:
    verifier = "happy go lucky"
    expected = "F9i_m3bYeE8Wrw_rHubiV4coAXzx9eDbRxK_1dVnfX0"
    result = auth_client._code_challenge(verifier)

    assert result == expected


def test_split_response(auth_client: _AuthClient) -> None:
    response = "https://localhost:8080/?code=foo&state=bar"
    expected = ("foo", "bar")
    result = auth_client._split_response(response)

    assert result == expected


def test_get_response_url(auth_client: _AuthClient) -> None:
    url = "https://account.withings.com/oauth2_user/authorize2"
    expected = "https://localhost:8080/?code=foo&state=bar"

    with patch("builtins.input", return_value=expected):
        result = auth_client._get_response_url(url)

    assert result == expected


def test_get_auth_code(auth_client: _AuthClient) -> None:
    challenge = "mock_challenge"
    auth_url = "https://account.withings.com/oauth2_user/authorize2"
    rd_url = f"https://localhost:8080/?code=foo&state={challenge}"
    expected = "foo"
    mock_get_response = MagicMock(status_code=302, json=MagicMock(), url=auth_url)
    mock_get_response.json.return_value = {"status": 0, "body": {"test": "test"}}

    with patch.object(auth_client, "_code_challenge", return_value=challenge):
        with patch.object(auth_client._http, "request", return_value=mock_get_response):
            with patch.object(auth_client, "_get_response_url") as mock_input:
                mock_input.return_value = rd_url
                result = auth_client._get_auth_code()

    mock_input.assert_called_once_with(auth_url)
    assert result == expected


def test_get_auth_code_invalid_response(auth_client: _AuthClient) -> None:
    auth_url = "https://account.withings.com/oauth2_user/authorize2"
    mock_get_response = MagicMock(status_code=403, url=auth_url)

    with patch.object(auth_client._http, "request", return_value=mock_get_response):
        with pytest.raises(ValueError, match="^Failed"):
            auth_client._get_auth_code()


def test_get_auth_code_challenge_mismatch(auth_client: _AuthClient) -> None:
    challenge = "mock_challenge"
    auth_url = "https://account.withings.com/oauth2_user/authorize2"
    rd_url = "https://localhost:8080/?code=foo&state=bar"
    mock_get_response = MagicMock(status_code=302, json=MagicMock(), url=auth_url)
    mock_get_response.json.return_value = {"status": 0, "body": {"test": "test"}}

    with patch.object(auth_client, "_code_challenge", return_value=challenge):
        with patch.object(auth_client._http, "request", return_value=mock_get_response):
            with patch.object(auth_client, "_get_response_url") as mock_input:
                mock_input.return_value = rd_url
                with pytest.raises(ValueError, match="^Challenge"):
                    auth_client._get_auth_code()


def test_get_access_token(auth_client: _AuthClient) -> None:
    mockresp = MagicMock(status_code=200, json=MagicMock())
    mockresp.json.return_value = {
        "status": 0,
        "body": {
            "userid": "30588767",
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "scope": "user.activity,user.metrics",
            "expires_in": 10800,
            "token_type": "Bearer",
        },
    }

    with patch.object(auth_client._http, "request", return_value=mockresp):
        result = auth_client._get_access_token("mockcode")

    assert result.userid == "30588767"
    assert result.access_token == "mock_access_token"
    assert result.refresh_token == "mock_refresh_token"
    assert result.scope == "user.activity,user.metrics"
    assert result.expiry > time.time()
    assert result.token_type == "Bearer"


def test_get_access_token_invalid_response(auth_client: _AuthClient) -> None:
    mockresp = MagicMock(status_code=200, json=MagicMock())
    mockresp.json.return_value = MagicMock(return_value={"status": 1})

    with patch.object(auth_client._http, "request", return_value=mockresp):
        with pytest.raises(ValueError):
            auth_client._get_access_token("mockcode")


def test_get_bearer_token_with_existing(auth_client: _AuthClient) -> None:
    auth_client._authed_user = _AuthedUser(**MOCK_AUTH_USER)

    result = auth_client._get_bearer_token()

    assert result == auth_client._authed_user.access_token


def test_get_bearer_token_full_process(auth_client: _AuthClient) -> None:
    with patch.object(auth_client, "_get_auth_code") as mock_code:
        mock_code.return_value = "mockcode"
        with patch.object(auth_client, "_get_access_token") as mock_token:
            mock_token.return_value = _AuthedUser(**MOCK_AUTH_USER)
            result = auth_client._get_bearer_token()

    mock_code.assert_called_once()
    mock_token.assert_called_once_with("mockcode")
    assert result == MOCK_AUTH_RESPONSE["body"]["access_token"]


def test_get_bearer_token_refresh(auth_client: _AuthClient) -> None:
    auth_client._authed_user = _AuthedUser(**MOCK_AUTH_USER)
    auth_client._authed_user.expiry = 0

    with patch.object(auth_client, "_refresh_access_token") as mock_refresh:
        mock_refresh.return_value = _AuthedUser(**MOCK_AUTH_USER)
        result = auth_client._get_bearer_token()

    mock_refresh.assert_called_once()
    assert result == MOCK_AUTH_RESPONSE["body"]["access_token"]


def test_get_headers(auth_client: _AuthClient) -> None:
    with patch.object(auth_client, "_get_bearer_token") as mock_token:
        mock_token.return_value = "mocktoken"
        result = auth_client.get_headers()

    mock_token.assert_called_once()
    assert result["Authorization"] == "Bearer mocktoken"


def test_refresh_access_token(auth_client: _AuthClient) -> None:
    mock_post_resp = MagicMock(status_code=200, json=MagicMock())
    mock_post_resp.json.return_value = MOCK_AUTH_RESPONSE

    with patch.object(auth_client._http, "request", return_value=mock_post_resp):
        result = auth_client._refresh_access_token(_AuthedUser(**MOCK_AUTH_USER))

    assert result.userid == MOCK_AUTH_USER["userid"]
    assert result.access_token == MOCK_AUTH_USER["access_token"]


def test_refresh_access_token_invalid_response(auth_client: _AuthClient) -> None:
    mock_post_resp = MagicMock(
        status_code=200,
        json=MagicMock(return_value={"status": 1}),
    )

    with patch.object(auth_client._http, "request", return_value=mock_post_resp):
        with pytest.raises(ValueError):
            auth_client._refresh_access_token(_AuthedUser(**MOCK_AUTH_USER))


def test_create_signature(auth_client: _AuthClient) -> None:
    result = auth_client._create_signature("mockdata", "12345")
    # This is the expected result of the above data and timestamp
    assert result == "8b3db37b7c80908b944b7fc5164c42b235da89772cf56c745a734bf74dac287a"


def test_get_nonce(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(
        status_code=200,
        json=MagicMock(
            return_value={"status": 0, "body": {"nonce": "mock"}},
        ),
    )

    with patch.object(auth_client._http, "request", return_value=mock_resp):
        result = auth_client._get_nonce()

    assert result == "mock"


def test_get_nonce_invalid_response(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp._json = {"status": 503, "body": {"nonce": "mock"}}

    with patch.object(auth_client._http, "request", return_value=mock_resp):
        with pytest.raises(ValueError):
            auth_client._get_nonce()


def test_revoke_access_token(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 0, "body": {}}

    with patch.object(auth_client._http, "request", return_value=mock_resp):
        with patch.object(auth_client, "_get_nonce", return_value="mocknonce"):
            auth_client._revoke_access_token()


def test_revoke_access_token_invalid_response(auth_client: _AuthClient) -> None:
    mock_resp = MagicMock(status_code=200, json=MagicMock())
    mock_resp.json.return_value = {"status": 1, "body": {}}

    with patch.object(auth_client._http, "request", return_value=mock_resp):
        with patch.object(auth_client, "_get_nonce", return_value="mocknonce"):
            with pytest.raises(ValueError):
                auth_client._revoke_access_token()
