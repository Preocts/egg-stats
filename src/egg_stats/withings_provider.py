"""Connect to and interact with the Withings API."""
from __future__ import annotations

import base64
import hashlib
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
ACCESS_URL = "https://wbsapi.withings.net/v2/oauth2"
NONCE_URL = "https://wbsapi.withings.net/v2/signature"
VALID_RESP_CODES = [200, 302]
VALID_STATUS_CODES = [0, 200, 204]


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
        self.is_success = (
            self.status_code in VALID_RESP_CODES
            and self._json.get("status") in VALID_STATUS_CODES
        )

    def json(self) -> dict[str, Any]:
        """Return the JSON response."""
        return self._json


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
        self._http = http or httpx.Client(timeout=TIMEOUT)
        self._authed_user: _AuthedUser | None = None

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
        elif self._authed_user.expiry < time.time():
            self._authed_user = self._refresh_access_token(self._authed_user)
        return self._authed_user.access_token

    def _get_auth_code(self) -> str:
        """Get the authorization code."""
        self.logger.debug("Getting auth code for client_id %s", self.client_id)
        code_verifier = self._code_verifier()
        code_challenge = self._code_challenge(code_verifier)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "scope": SCOPES,
            "state": code_challenge,
            "redirect_uri": REDIRECT_URI,
        }

        resp = self._handle_http("GET", AUTH_URL, params=params)

        # User needs to authorize the app
        self.logger.debug("User needs to authorize the app...")
        response_url = self._get_response_url(resp.url)
        code, state = self._split_response(response_url)

        if code_challenge != state:
            raise ValueError(
                f"Challenge ({code_challenge}) does not match state ({state})."
            )

        return code

    def _get_access_token(self, code: str) -> _AuthedUser:
        """Get the access token given the authorization code."""
        self.logger.debug("Getting access token for client_id %s", self.client_id)
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        resp = self._handle_http("POST", ACCESS_URL, params=params)
        return _AuthedUser.from_dict(resp.json()["body"])

    def _refresh_access_token(self, authed_user: _AuthedUser) -> _AuthedUser:
        """Refresh the access token."""
        self.logger.debug("Refreshing access token for client_id %s", self.client_id)
        params = {
            "action": "requesttoken",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": authed_user.refresh_token,
        }
        resp = self._handle_http("POST", ACCESS_URL, params=params)
        return _AuthedUser.from_dict(resp.json()["body"])

    def _revoke_access_token(self) -> bool:
        """Revoke the access token."""
        userid = self._authed_user.userid if self._authed_user else ""
        self.logger.debug("Revoking access token for user %s", userid)
        nonce = self._get_nonce()
        params = {
            "action": "revoke",
            "client_id": self.client_id,
            "nonce": nonce,
            "signature": self._create_signature("revoke", nonce),
            "userid": userid,
        }
        self._handle_http("POST", ACCESS_URL, params=params)
        return True

    def _get_nonce(self) -> str:
        """Get a nonce."""
        self.logger.debug("Getting nonce for client_id %s", self.client_id)
        timestamp = str(int(time.time()))
        params = {
            "action": "getnonce",
            "client_id": self.client_id,
            "signature": self._create_signature("getnonce", timestamp),
            "timestamp": timestamp,
        }
        resp = self._handle_http("POST", NONCE_URL, params=params)
        return resp.json()["body"]["nonce"]

    def _create_signature(self, action: str, timestamp: str) -> str:
        """Create the signature for a nonce request."""
        import hmac

        hash_string = f"{action},{self.client_id},{timestamp}".encode()
        secret = self.client_secret or ""
        return hmac.digest(secret.encode("utf-8"), hash_string, hashlib.sha256).hex()

    def _handle_http(self, verb: str, url: str, params: dict[str, Any]) -> HTTPResponse:
        """Handle HTTPS request, raise ValueError on failure."""
        resp = HTTPResponse(self._http.request(verb.upper(), url, params=params))
        if not resp.is_success:
            raise ValueError(f"Failed {verb.upper()} to {url}: {resp.text}")

        return resp

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
