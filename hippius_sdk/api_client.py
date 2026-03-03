"""
Hippius API Client for token validation and billing operations.

This module provides an HTTP-based client for authenticating API tokens
and checking account balances via the Hippius API.

API Documentation: https://api.hippius.com/?format=openapi
"""

import logging
from typing import Any, Dict, Optional

from pydantic import BaseModel

from hippius_sdk.config import get_api_token
from hippius_sdk.errors import HippiusAPIError
from hippius_sdk.http_utils import create_http_client, retry_on_error

logger = logging.getLogger(__name__)


class TokenAuthResponse(BaseModel):
    valid: bool
    status: str
    account_address: str
    token_type: str


class HippiusApiClient:
    """
    HTTP API client for Hippius platform.

    Used for token validation and billing operations only.
    File operations are handled by ArionClient.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
        api_token_password: Optional[str] = None,
        account_name: Optional[str] = None,
    ):
        """
        Initialize the Hippius API client.

        Args:
            api_url: Base URL for the Hippius API (default: https://api.hippius.com/api)
            api_token: API token for authentication
            api_token_password: Password to decrypt the api_token if encrypted
            account_name: Name of the account to use (uses active account if None)
        """
        self.api_url = api_url or "https://api.hippius.com/api"
        self._api_token = api_token
        self._api_token_password = api_token_password
        self._account_name = account_name

        # Initialize httpx client with timeout
        self._client = create_http_client(self.api_url)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    def _get_api_token(self, api_token: Optional[str] = None) -> str:
        """
        Get the API token for authentication.

        Args:
            api_token: Optional api_token to use (uses config if None)

        Returns:
            str: The API token

        Raises:
            ValueError: If no api_token is available
        """
        # Use provided key first
        if api_token:
            return api_token

        # Use instance key if set
        if self._api_token:
            return self._api_token

        # Try to get from config
        config_key = get_api_token(self._api_token_password, self._account_name)
        if config_key:
            return config_key

        raise ValueError(
            "No API token available. Please provide an API token or configure it using 'hippius account login'"
        )

    def _get_headers(self, api_token: Optional[str] = None) -> Dict[str, str]:
        """
        Get HTTP headers with authentication.

        Args:
            api_token: Optional api_token to use

        Returns:
            Dict[str, str]: Headers with authentication token
        """
        key = self._get_api_token(api_token)
        return {
            "Authorization": f"Token {key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusAPIError)
    async def validate_token(
        self,
        api_token: str,
    ) -> TokenAuthResponse:
        """
        Validate an API token and get the associated account address.

        Maps to: POST /objectstore/tokens/auth/

        Args:
            api_token: The API token to validate

        Returns:
            TokenAuthResponse: Validation result with account_address

        Raises:
            HippiusAPIError: If the API request fails
            HippiusAuthenticationError: If the token is invalid
        """
        response = await self._client.post(
            "/objectstore/tokens/auth/",
            json={"accessKeyId": api_token},
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

        response.raise_for_status()
        return TokenAuthResponse.model_validate(response.json())

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusAPIError)
    async def get_account_balance(
        self,
        api_token: Optional[str] = None,
    ) -> Dict[str, float]:
        """Get the credit balance for the authenticated account.

        Maps to: GET /billing/credits/balance/

        Args:
            api_token: Optional API token (uses config if None)

        Returns:
            float: Credit balance (1 credit = 1 USD)

        Raises:
            HippiusAPIError: If the API request fails
            HippiusAuthenticationError: If authentication fails (401/403)
        """
        headers = self._get_headers(api_token)

        response = await self._client.get(
            "/billing/credits/balance/",
            headers=headers,
        )

        response.raise_for_status()
        return response.json()
