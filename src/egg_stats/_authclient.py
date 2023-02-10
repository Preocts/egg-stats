from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime

import httpx

TS_NOW = datetime.utcnow().timestamp
EXPIRY_BUFFER = 60  # seconds

GRANT_TYPE = "authorization_code"
SCOPES = "user.activity, user.metrics"
REDIRECT_URI = "https://localhost:8080"


class HTTPResponse:
    def __init__(self, response: httpx.Response) -> None:
        """Representation for the HTTP response from the API."""
        try:
            self.json = response.json()
        except json.JSONDecodeError:
            self.json = {}

        self.status_code = response.status_code
        self.url = response.url
        self.is_success = response.is_success


class _AuthClient:
    """Auth client with client secret is available."""

    logger = logging.getLogger(__name__)

    def __init__(
        self, client_id: str | None = None, client_secret: str | None = None
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
        if not self.client_id or not self.client_secret:
            raise ValueError("client_id and client_secret are required.")

        self._http = httpx.Client()
        self._bearer: str | None = None
        self._expiry: float | None = None

    def _headers(self) -> dict[str, str]:
        """Return the headers for the API."""
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.client_secret}",
        }

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
