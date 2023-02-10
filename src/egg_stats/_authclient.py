from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime

import httpx

EXPIRY_BUFFER = 60  # seconds
TIMEOUT = 30  # seconds

SCOPES = "user.activity,user.metrics"
REDIRECT_URI = "https://localhost:8080"

AUTH_URL = "https://account.withings.com/oauth2_user/authorize2"
ACCESS_URL = "https://wbsapi.withings.net/v2/oauth2"
VALID_CODES = [302]


class HTTPResponse:
    def __init__(self, response: httpx.Response) -> None:
        """Representation for the HTTP response from the API."""
        try:
            self.json = response.json()
        except json.JSONDecodeError:
            self.json = {}

        self.text = response.text
        self.status_code = response.status_code
        self.url = str(response.url)
        self.is_success = response.is_success


@dataclass
class _AuthedUser:
    userid: str
    access_token: str
    refresh_token: str
    expiry: float
    scope: str
    token_type: str
    csrf_token: str | None = None


class _AuthClient:
    """Auth client with client secret is available."""

    logger = logging.getLogger(__name__)

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        """
        Representation for the client that interacts with the API.

        client_id and client_secret are required for the API to work. They
        can be provided as arguments or as environment variables.

        Optional environment variables:
            EGGSTATS_CLIENT_ID: The client ID.
            EGGSTATS_CLIENT_SECRET: The client secret.

        Args:
            client_id: The client ID. Defaults to None.
            client_secret: The client secret. Defaults to None.

        Raises:
            ValueError: If the client ID or client secret is not provided.
        """
        self.client_id = client_id or os.environ.get("EGGSTATS_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("EGGSTATS_CLIENT_SECRET")
        self._authed_user: _AuthedUser | None = None
        self._http = httpx.Client(timeout=TIMEOUT)

        if not self.client_id or not self.client_secret:
            raise ValueError("client_id and client_secret are required.")

    def get_headers(self) -> dict[str, str]:
        """Return the headers for the API."""
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._get_bearer_token()}",
        }

    def _get_bearer_token(self) -> str:
        """Get the bearer token."""
        if self._authed_user is None:
            auth_code = self._get_auth_code()
            self._authed_user = self._get_access_token(auth_code)
        elif self._authed_user.expiry < datetime.utcnow().timestamp():
            self._authed_user = self._refresh_access_token(self._authed_user)
        return self._authed_user.access_token

    def _get_auth_code(self) -> str:
        """Get the authorization code."""
        code_verifier = self._code_verifier()
        code_challenge = self._code_challenge(code_verifier)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "scope": SCOPES,
            "state": code_challenge,
            "redirect_uri": REDIRECT_URI,
        }

        resp = HTTPResponse(self._http.get(AUTH_URL, params=params))

        if resp.status_code not in VALID_CODES:
            raise ValueError(f"Failed to get auth code: {resp.text}")

        response_url = self._get_response_url(resp.url)
        code, state = self._split_response(response_url)

        if code_challenge != state:
            raise ValueError("Code challenge does not match state.")

        return code

    def _get_access_token(self, code: str) -> _AuthedUser:
        """Get the access token given the authorization code."""
        print("Getting access token...")
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        resp = HTTPResponse(self._http.post(ACCESS_URL, params=params))

        if not resp.is_success:
            raise ValueError(f"Failed to get access token: {resp.text}")

        return _AuthedUser(
            userid=resp.json["body"]["userid"],
            access_token=resp.json["body"]["access_token"],
            refresh_token=resp.json["body"]["refresh_token"],
            expiry=datetime.utcnow().timestamp()
            + resp.json["body"]["expires_in"]
            - EXPIRY_BUFFER,
            scope=resp.json["body"]["scope"],
            token_type=resp.json["body"]["token_type"],
            csrf_token=resp.json["body"].get("csrf_token"),
        )

    def _refresh_access_token(self, authed_user: _AuthedUser) -> _AuthedUser:
        """Refresh the access token."""
        print("Refreshing access token...")
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": authed_user.refresh_token,
        }
        resp = HTTPResponse(self._http.post(ACCESS_URL, params=params))

        if not resp.is_success:
            raise ValueError(f"Failed to refresh access token: {resp.text}")

        return _AuthedUser(
            userid=resp.json["body"]["userid"],
            access_token=resp.json["body"]["access_token"],
            refresh_token=resp.json["body"]["refresh_token"],
            expiry=datetime.utcnow().timestamp()
            + resp.json["body"]["expires_in"]
            - EXPIRY_BUFFER,
            scope=resp.json["body"]["scope"],
            token_type=resp.json["body"]["token_type"],
            csrf_token=resp.json["body"].get("csrf_token"),
        )

    @staticmethod
    def _get_response_url(url: str) -> str:
        """Get the response URL."""
        # Extracted from _get_auth_code to allow inserting a local api server easily.
        print("Please visit the following URL to authorize the app:")
        print(url, end="\n\n")
        print("Authorize the app, then copy the URL you are redirected to.")
        print(f"It should look like {REDIRECT_URI}/?code=...&state=...", end="\n\n")
        return input("Enter the URL: ")

    @staticmethod
    def _split_response(response: str) -> tuple[str, str]:
        """Split the response into the code and state."""
        code = response.split("code=")[1].split("&")[0]
        state = response.split("state=")[1].split("&")[0]
        return code, state

    @staticmethod
    def _code_verifier() -> str:
        """Create a code verifier."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
        return re.sub("[^a-zA-Z0-9]+", "", code_verifier)

    @staticmethod
    def _code_challenge(code_verifier: str) -> str:
        """Create a code challenge."""
        code_byte = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_byte).decode("utf-8")
        return code_challenge.replace("=", "")
