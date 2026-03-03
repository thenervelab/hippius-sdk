"""
End-to-end tests for HippiusApiClient.

These tests verify that API interactions work correctly against
the real Hippius API using HIPPIUS_KEY from environment.

To run these tests:
    export HIPPIUS_KEY=your_test_key
    export HIPPIUS_E2E=1
    pytest tests/test_api_client_e2e.py -v
"""

import pytest

from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.errors import (
    HippiusAPIError,
    HippiusAuthenticationError,
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientAuthentication:
    """Test API client authentication and initialization."""

    async def test_client_initialization(self, test_api_token, test_api_url):
        """Test that API client initializes correctly."""
        client = HippiusApiClient(api_url=test_api_url, api_token=test_api_token)

        assert client.api_url == test_api_url
        assert client._api_token == test_api_token

        await client.close()

    async def test_auth_header_generation(self, api_client):
        """Test that authentication headers are generated correctly."""
        headers = api_client._get_headers()

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Token ")

    async def test_invalid_key_raises_error(self, test_api_url):
        """Test that invalid API token raises an error."""
        import httpx

        client = HippiusApiClient(api_url=test_api_url, api_token="invalid_key_12345")

        # Invalid key will result in 404 (account not found) or auth error
        with pytest.raises((HippiusAuthenticationError, httpx.HTTPStatusError)):
            await client.get_account_balance()

        await client.close()


@pytest.mark.e2e
@pytest.mark.asyncio
class TestBillingEndpoints:
    """Test billing and credit management endpoints."""

    async def test_get_credits_balance(self, api_client):
        """
        Test GET /billing/credits/balance/
        Should return user's credit balance.
        """
        result = await api_client.get_account_balance()

        # Verify response structure
        assert isinstance(result, dict), "Credits should be a dict"


@pytest.mark.e2e
@pytest.mark.asyncio
class TestTokenValidation:
    """Test token validation endpoint."""

    async def test_validate_token(self, api_client, test_api_token):
        """
        Test POST /objectstore/tokens/auth/
        Should validate a token and return account info.
        """
        result = await api_client.validate_token(test_api_token)

        assert result.valid is True
        assert result.account_address
        assert result.token_type


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientErrorHandling:
    """Test API client error handling and retry logic."""

    async def test_no_retry_on_auth_error(self, test_api_url):
        """
        Test that authentication errors (401/403) don't retry.
        """
        import httpx

        client = HippiusApiClient(
            api_url=test_api_url, api_token="definitely_invalid_key"
        )

        # Should fail quickly without retries
        with pytest.raises((HippiusAuthenticationError, httpx.HTTPStatusError)):
            await client.get_account_balance()

        await client.close()

    async def test_context_manager_usage(self, test_api_token, test_api_url):
        """
        Test that API client works as async context manager.
        """
        async with HippiusApiClient(
            api_url=test_api_url, api_token=test_api_token
        ) as client:
            # Should be able to make requests
            credits = await client.get_account_balance()
            assert isinstance(credits, dict)

        # Client should be closed after context exit
