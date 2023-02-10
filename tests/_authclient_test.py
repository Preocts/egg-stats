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
