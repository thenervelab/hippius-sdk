"""
Pytest configuration and fixtures for Hippius SDK tests.

This module provides shared fixtures for testing the Hippius SDK,
including API client setup, test data generation, and cleanup utilities.
"""

import asyncio
import os
import tempfile
from typing import AsyncGenerator, Dict
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from dotenv import load_dotenv

from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.arion import ArionClient
from tests.mock_arion import MockArionClient

# Load environment variables from .env first, then .env.test (which can override)
load_dotenv(".env")
load_dotenv(".env.test", override=True)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_api_token() -> str:
    """
    Get API token from environment (.env.test).

    Only runs when HIPPIUS_E2E=1 is set. Unit tests don't need this.

    Returns:
        The test API token

    Raises:
        RuntimeError: If HIPPIUS_KEY is not set
    """
    if not os.getenv("HIPPIUS_E2E"):
        pytest.skip("Set HIPPIUS_E2E=1 to run tests requiring API token")
    key = os.getenv("HIPPIUS_KEY")
    if not key:
        raise RuntimeError(
            "HIPPIUS_KEY not set in .env.test! "
            "E2E tests require a valid API token. "
            "Set it in .env.test or as an environment variable."
        )
    return key


@pytest.fixture(scope="session")
def test_api_url() -> str:
    """
    Get API URL for testing.

    Returns:
        API URL (defaults to production)
    """
    return os.getenv("API_URL", "https://api.hippius.com/api")


@pytest_asyncio.fixture
async def api_client(
    test_api_token: str, test_api_url: str
) -> AsyncGenerator[HippiusApiClient, None]:
    """
    Create an authenticated API client for testing.

    Args:
        test_api_token: Test API token from environment
        test_api_url: API URL for testing

    Yields:
        Configured HippiusApiClient instance
    """
    client = HippiusApiClient(
        api_url=test_api_url,
        api_token=test_api_token,
    )

    yield client

    # Cleanup
    await client.close()


@pytest_asyncio.fixture
async def hippius_client(
    test_api_token: str,
) -> AsyncGenerator[ArionClient, None]:
    """
    Create an ArionClient for integration testing.

    Args:
        test_api_token: Test API token from environment

    Yields:
        Configured ArionClient instance
    """
    client = ArionClient(
        api_token=test_api_token,
        account_address="5TestAddress",
    )

    yield client


@pytest.fixture
def temp_test_file():
    """
    Create a temporary test file for upload tests.

    Yields:
        Path to temporary file
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
        # Write test content
        test_content = b"This is a test file for Hippius SDK e2e tests.\n" * 100
        f.write(test_content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def mock_api_response() -> Dict:
    """
    Mock API response data for unit tests.

    Returns:
        Dictionary with mock response data
    """
    return {
        "credits": {"balance": 100.50, "currency": "USD"},
        "upload": {
            "upload_id": "test-upload-id-456",
            "file_id": "abc123def456",
            "timestamp": 1234567890,
            "size_bytes": 1024,
        },
    }


@pytest.fixture
def mock_httpx_client():
    """
    Mock httpx client for unit testing API client without network calls.

    Returns:
        Mock AsyncClient
    """
    mock_client = AsyncMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success"}
    mock_client.get.return_value.__aenter__.return_value = mock_response
    mock_client.post.return_value.__aenter__.return_value = mock_response
    return mock_client


@pytest.fixture
def mock_arion():
    """
    Create a MockArionClient for deterministic handler tests.

    Returns:
        MockArionClient instance with sensible defaults
    """
    return MockArionClient(
        api_token="test-token",
        account_address="5TestAddress",
    )


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end test requiring API access"
    )
    config.addinivalue_line("markers", "slow: mark test as slow running")
