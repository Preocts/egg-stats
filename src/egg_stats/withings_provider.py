"""Connect to and interact with the Withings API."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

EXPIRY_BUFFER = 60  # seconds
TIMEOUT = 30  # seconds

SCOPES = "user.activity,user.metrics"
REDIRECT_URI = "https://localhost:8080"

AUTH_URL = "https://account.withings.com/oauth2_user/authorize2"
BASE_URL = "https://wbsapi.withings.net"
VALID_RESP_CODES = [200, 302]
VALID_STATUS_CODES = [0, 200, 204]

DATA_FIELDS = [
    "steps",
    "distance",
    "elevation",
    "soft",
    "moderate",
    "intense",
    "active",
    "calories",
    "totalcalories",
    "hr_average",
    "hr_min",
    "hr_max",
    "hr_zone_0",
    "hr_zone_1",
    "hr_zone_3",
]


class HTTPResponse:
    def __init__(self, response: httpx.Response) -> None:
        """Representation for the HTTP response from the API."""
        try:
            self._json = response.json()
        except json.JSONDecodeError:
            self._json = {}

        self.text = response.text
        self.status_code = response.status_code
        self.url = str(response.url)
        self.is_success = self.status_code in VALID_RESP_CODES and (
            self._json.get("status") in VALID_STATUS_CODES or not self._json
        )

    def json(self) -> dict[str, Any]:
        """Return the JSON response."""
        return self._json


@dataclass
class AuthedUser:
    userid: str
    refresh_token: str


@dataclass
class _AuthedUser:
    userid: str
    access_token: str
    refresh_token: str
    expiry: float
    scope: str
    token_type: str
    csrf_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> _AuthedUser:
        """Create an instance from a dictionary."""
        return cls(
            userid=data["userid"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expiry=time.time() + data["expires_in"] - EXPIRY_BUFFER,
            scope=data["scope"],
            token_type=data["token_type"],
            csrf_token=data.get("csrf_token"),
        )


@dataclass(frozen=True)
class Activity:
    steps: int
    distance: float
    elevation: float
    soft: float
    moderate: float
    intense: float
    active: float
    calories: float
    totalcalories: float
    hr_average: int
    hr_min: int
    hr_max: int
    hr_zone_0: int
    hr_zone_1: int
    hr_zone_3: int
    deviceid: None
    hash_deviceid: None
    timezone: str
    date: str
    modified: int
    brand: int
    is_tracker: bool


class WithingsProvider:
    """Representation for the Withings API."""

    logger = logging.getLogger(__name__)

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        """Initialize the Withings API."""
        self._http = httpx.Client(timeout=TIMEOUT)
        self._auth_client = _AuthClient(client_id, client_secret, self._http)
        self._last_state: str | None = None

    @property
    def user(self) -> AuthedUser:
        """Return the authenticated user id with refresh token."""
        if not self._auth_client._authed_user:
            raise ValueError("Not authenticated, call authenticate() first.")

        return AuthedUser(
            userid=self._auth_client._authed_user.userid,
            refresh_token=self._auth_client._authed_user.refresh_token,
        )

    def get_authentication_url(
        self,
        redirect_uri: str,
        scope: str | None = None,
    ) -> str:
        """
        Get the URL to redirect the user to for authentication.

        The calling application must redirect the user to the returned URL. Once
        the user accepts the request the redirect URL will contain both a code
        and a state with are used to authenticate the user.

        Args:
            redirect_uri: The URL to redirect the user to after authentication.
            scope: The scope of access request. (default: user.activity,user.metrics)

        Returns:
            The URL to redirect the user to.

        Raises:
            ValueError
        """
        scope = scope or SCOPES
        state = self._auth_client.create_state_code()
        self._last_state = state

        uri = self._auth_client.get_authorization_url(redirect_uri, scope, state)

        return uri

    def authenticate(self, code: str, state: str, redirect_uri: str) -> None:
        """
        Authenticate with the API.

        Args:
            code: The code returned by the authentication URL.
            state: The state returned by the authentication URL.
            redirect_uri: The redirect URI used when requesting the code.

        Raises:
            ValueError
        """
        if not self._last_state or self._last_state != state:
            raise ValueError("Invalid state code.")

        self._auth_client.authenticate(code, redirect_uri)

    def activity_list(self, number_of_days: int = 7) -> list[Activity]:
        """
        Get aggregated activity data for a given period of time.

        Args:
            number_of_days: The number of days to get data for.

        Returns:
            A list of activity data.

        Raises:
            ValueError: If not authenticated.
        """
        self.logger.debug("Getting activity range for %s days", number_of_days)
        starttime = int(time.time()) - number_of_days * 24 * 60 * 60
        startdateymd = time.strftime("%Y-%m-%d", time.localtime(starttime))
        enddateymd = time.strftime("%Y-%m-%d", time.localtime())
        params = {
            "action": "getactivity",
            "startdateymd": startdateymd,
            "enddateymd": enddateymd,
            "data_fields": ",".join(DATA_FIELDS),
        }
        url = f"{BASE_URL}/v2/measure"
        activities = self._handle_paginated("activities", "POST", url, params)

        return [Activity(**activity) for activity in activities]

    def _handle_paginated(
        self,
        label: str,
        verb: str,
        url: str,
        params: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Handle paginated API calls."""
        more = True
        records: list[dict[str, Any]] = []
        while more:
            resp = self._handle_http(verb, url, params)

            records.extend(resp.json()["body"].get(label, []))
            more = resp.json()["body"].get("more", False)
            params["offset"] = resp.json()["body"].get("offset", 0)

            self.logger.debug(
                "Discovered %s %s records (more: %s)", len(records), label, more
            )

        return records

    def _handle_http(self, verb: str, url: str, params: dict[str, Any]) -> HTTPResponse:
        """Handle HTTPS request, raise ValueError on failure."""
        headers = self._auth_client.get_headers()
        resp = HTTPResponse(
            self._http.request(
                verb.upper(),
                url,
                params=params,
                headers=headers,
            )
        )
        if not resp.is_success:
            raise ValueError(f"Failed {verb.upper()} to {url}: {resp.text}")

        return resp


class _AuthClient:
    """Auth client with client secret is available."""

    logger = logging.getLogger(__name__)

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        """
        Representation for the client that interacts with the API.

        client_id and client_secret are required for the API to work. They
        can be provided as arguments or as environment variables.

        Optional environment variables:
            WITHINGS_CLIENT_ID: The client ID.
            WITHINGS_CLIENT_SECRET: The client secret.

        Args:
            client_id: The client ID. Defaults to None.
            client_secret: The client secret. Defaults to None.

        Raises:
            ValueError: If the client ID or client secret is not provided.
        """
        self.client_id = client_id or os.environ.get("WITHINGS_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("WITHINGS_CLIENT_SECRET")
        self._http = http or httpx.Client(timeout=TIMEOUT)
        self._authed_user: _AuthedUser | None = None

        if not self.client_id or not self.client_secret:
            raise ValueError("client_id and client_secret are required.")

    @property
    def authed_user(self) -> _AuthedUser:
        """Return the authenticated user."""
        if not self._authed_user:
            raise ValueError("Expected authenticated user.")
        return self._authed_user

    def get_headers(self) -> dict[str, str]:
        """Return the headers for the API."""
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._get_bearer_token()}",
        }

    def _get_bearer_token(self) -> str:
        """Get the bearer token."""
        if not self._authed_user:
            raise ValueError("Expected authenticated user.")

        if self._authed_user.expiry < time.time():
            self._refresh_access_token()

        return self._authed_user.access_token

    def get_authorization_url(self, redirect_uri: str, scope: str, state: str) -> str:
        """
        Get the authorization url.

        Args:
            redirect_uri: The URL to redirect the user to after authentication.
            scope: The scope of access request.
            state: The state to use for the request.

        Returns:
            The authorization URL.
        """
        self.logger.debug(
            "Getting authorization uri with scope %s and redirect uri %s",
            scope,
            redirect_uri,
        )

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "scope": scope,
            "state": state,
            "redirect_uri": redirect_uri,
        }

        resp = self._handle_http("GET", AUTH_URL, params=params)

        return resp.url

    def authenticate(self, code: str, redirect_uri: str) -> None:
        """Authenticate the user."""
        self.logger.debug("Authenticating user with code ...%s", code[-6:])
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        resp = self._handle_http("POST", f"{BASE_URL}/v2/oauth2", params=params)
        self._authed_user = _AuthedUser.from_dict(resp.json()["body"])

    def _refresh_access_token(self) -> None:
        """Refresh the access token."""
        self.logger.debug("Refreshing access token for client_id %s", self.client_id)
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.authed_user.refresh_token,
        }
        resp = self._handle_http("POST", f"{BASE_URL}/v2/oauth2", params=params)
        self._authed_user = _AuthedUser.from_dict(resp.json()["body"])

    def _revoke_access_token(self) -> None:
        """Revoke the access token."""
        self.logger.debug("Revoking access token for user %s", self.authed_user.userid)
        nonce = self.get_nonce()
        params = {
            "action": "revoke",
            "client_id": self.client_id,
            "nonce": nonce,
            "signature": self.get_signature("revoke", nonce),
            "userid": self.authed_user.userid,
        }
        self._handle_http("POST", f"{BASE_URL}/v2/oauth2", params=params)

    def get_nonce(self) -> str:
        """Get a nonce."""
        self.logger.debug("Getting nonce for client_id %s", self.client_id)
        timestamp = str(int(time.time()))
        params = {
            "action": "getnonce",
            "client_id": self.client_id,
            "signature": self.get_signature("getnonce", timestamp),
            "timestamp": timestamp,
        }
        resp = self._handle_http("POST", f"{BASE_URL}/v2/signature", params=params)
        return resp.json()["body"]["nonce"]

    def get_signature(self, action: str, unique: str) -> str:
        """Create a signature for action using a unique timestamp or nonce."""
        hash_string = f"{action},{self.client_id},{unique}".encode()
        secret = self.client_secret or ""
        return hmac.digest(secret.encode("utf-8"), hash_string, hashlib.sha256).hex()

    def _handle_http(self, verb: str, url: str, params: dict[str, Any]) -> HTTPResponse:
        """Handle HTTPS request, raise ValueError on failure."""
        resp = HTTPResponse(self._http.request(verb.upper(), url, params=params))
        if not resp.is_success:
            raise ValueError(f"Failed {verb.upper()} to {url}: {resp.text}")

        return resp

    @staticmethod
    def create_state_code() -> str:
        """Create a state code used for the authorization request."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

        code_byte = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_byte).decode("utf-8")
        return code_challenge.replace("=", "")


def get_response_url(url: str) -> str:
    """Get the response URL."""
    # Extracted from _get_auth_code to allow inserting a local api server easily.
    print("Please visit the following URL to authorize the app:")
    print(url, end="\n\n")
    print("Authorize the app, then copy the URL you are redirected to.")
    print(f"It should look like {REDIRECT_URI}/?code=...&state=...", end="\n\n")
    return input("Enter the URL: ")


def split_response(response: str) -> tuple[str, str]:
    """Split the response into the code and state."""
    code = response.split("code=")[1].split("&")[0]
    state = response.split("state=")[1].split("&")[0]
    return code, state


if __name__ == "__main__":
    from secretbox import SecretBox

    SecretBox(auto_load=True)
    logging.basicConfig(level=logging.DEBUG)

    withings_provider = WithingsProvider()

    auth_url = withings_provider.get_authentication_url(REDIRECT_URI, SCOPES)

    response = get_response_url(auth_url)
    code, state = split_response(response)

    withings_provider.authenticate(code, state, REDIRECT_URI)

    print(withings_provider._auth_client.get_headers())

    print(withings_provider.activity_list())
