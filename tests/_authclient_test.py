from __future__ import annotations

import os
from collections.abc import Generator
from json import JSONDecodeError
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from egg_stats._authclient import _AuthClient
from egg_stats._authclient import HTTPResponse


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


def test_HTTPResponse_handles_204() -> None:
    """Test the HTTPResponse class."""
    response = MagicMock()
    response.json.side_effect = JSONDecodeError("msg", "doc", 0)
    response.status_code = 204
    response.url = "https://example.com"
    response.is_success = True

    http_response = HTTPResponse(response)

    assert http_response.json == {}
    assert http_response.status_code == 204
    assert http_response.url == "https://example.com"
    assert http_response.is_success is True


def test_HTTPResponse_handles_200() -> None:
    """Test the HTTPResponse class."""
    response = MagicMock()
    response.json.return_value = {"foo": "bar"}
    response.status_code = 200
    response.url = "https://example.com"
    response.is_success = True

    http_response = HTTPResponse(response)

    assert http_response.json == {"foo": "bar"}
    assert http_response.status_code == 200
    assert http_response.url == "https://example.com"
    assert http_response.is_success is True


def test_AuthClient_raises_ValueError_if_no_client_id() -> None:
    from egg_stats._authclient import _AuthClient

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
