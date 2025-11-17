"""
Pytest configuration and fixtures for Hippius SDK tests.

This module provides shared fixtures for testing the Hippius SDK,
including API client setup, test data generation, and cleanup utilities.
"""

import asyncio
import os
import subprocess
import tempfile
import time
from typing import AsyncGenerator, Dict, Optional
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from dotenv import load_dotenv

from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.client import HippiusClient
from hippius_sdk.config import get_hippius_key

# Load test environment variables from .env.test
load_dotenv('.env.test', override=True)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def docker_ipfs_node():
    """
    Start a Docker IPFS node for testing and tear it down after tests complete.

    This fixture automatically starts at the beginning of the test session,
    ensuring IPFS is available for all tests.

    This fixture:
    - Starts IPFS Kubo container via docker-compose.test.yml
    - Waits for the node to be healthy (up to 30s)
    - Yields the IPFS API URL
    - Tears down the container after all tests

    Yields:
        str: IPFS API URL (http://localhost:5001)
    """
    compose_file = "docker-compose.test.yml"
    ipfs_api_url = "http://localhost:5001"

    # Start the IPFS node
    print("\n🐳 Starting Docker IPFS node for tests...")
    subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d"],
        check=True,
        capture_output=True
    )

    # Wait for IPFS to be healthy (max 30 seconds)
    max_wait = 30
    wait_interval = 1
    elapsed = 0

    while elapsed < max_wait:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "ps", "--format", "json"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and '"Health":"healthy"' in result.stdout:
            print(f"✅ IPFS node is healthy ({ipfs_api_url})")
            break

        time.sleep(wait_interval)
        elapsed += wait_interval
    else:
        subprocess.run(["docker", "compose", "-f", compose_file, "down", "-v"])
        raise RuntimeError(f"IPFS node failed to become healthy within {max_wait}s")

    yield ipfs_api_url

    # Teardown: stop and remove the container
    print("\n🧹 Stopping Docker IPFS node...")
    subprocess.run(
        ["docker", "compose", "-f", compose_file, "down", "-v"],
        check=True,
        capture_output=True
    )
    print("✅ Docker IPFS node stopped")


@pytest.fixture(scope="session")
def test_hippius_key() -> str:
    """
    Get HIPPIUS_KEY from environment (.env.test).

    Returns:
        The test HIPPIUS_KEY

    Raises:
        RuntimeError: If HIPPIUS_KEY is not set
    """
    key = os.getenv("HIPPIUS_KEY")
    if not key:
        raise RuntimeError(
            "HIPPIUS_KEY not set in .env.test! "
            "E2E tests require a valid HIPPIUS_KEY. "
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
async def api_client(test_hippius_key: str, test_api_url: str) -> AsyncGenerator[HippiusApiClient, None]:
    """
    Create an authenticated API client for testing.

    Args:
        test_hippius_key: Test HIPPIUS_KEY from environment
        test_api_url: API URL for testing

    Yields:
        Configured HippiusApiClient instance
    """
    client = HippiusApiClient(
        api_url=test_api_url,
        hippius_key=test_hippius_key,
    )

    yield client

    # Cleanup
    await client.close()


@pytest_asyncio.fixture
async def hippius_client(test_hippius_key: str, test_api_url: str, docker_ipfs_node: str) -> AsyncGenerator[HippiusClient, None]:
    """
    Create a full HippiusClient for integration testing.

    Args:
        test_hippius_key: Test HIPPIUS_KEY from environment
        test_api_url: API URL for testing
        docker_ipfs_node: Docker IPFS API URL from fixture

    Yields:
        Configured HippiusClient instance
    """
    client = HippiusClient(
        hippius_key=test_hippius_key,
        api_url=test_api_url,
        ipfs_api_url=docker_ipfs_node,
        ipfs_gateway=docker_ipfs_node,
    )

    yield client

    # Cleanup
    if hasattr(client.api_client, 'close'):
        await client.api_client.close()


@pytest.fixture
def temp_test_file():
    """
    Create a temporary test file for upload tests.

    Yields:
        Path to temporary file
    """
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
        # Write test content
        test_content = b"This is a test file for Hippius SDK e2e tests.\n" * 100
        f.write(test_content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_test_dir():
    """
    Create a temporary directory with test files.

    Yields:
        Path to temporary directory
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create some test files
        for i in range(3):
            file_path = os.path.join(temp_dir, f"test_file_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Test file {i} content\n" * 50)

        yield temp_dir


@pytest.fixture
def sample_cid() -> str:
    """
    Sample CID for testing (a valid but non-existent CID).

    Returns:
        Sample CID string
    """
    return "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"


@pytest.fixture
def mock_api_response() -> Dict:
    """
    Mock API response data for unit tests.

    Returns:
        Dictionary with mock response data
    """
    return {
        "credits": {
            "balance": 100.50,
            "currency": "USD"
        },
        "file": {
            "id": "test-file-id-123",
            "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "name": "test_file.txt",
            "size": 1024,
            "created_at": "2025-01-01T00:00:00Z"
        },
        "upload": {
            "id": "test-upload-id-456",
            "status": "completed",
            "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        },
        "storage_request": {
            "id": "test-request-id-789",
            "type": "Pin",
            "status": "pending",
            "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        }
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


# Marker for tests that require IPFS (now always available via Docker)
pytest.mark.requires_ipfs = pytest.mark.usefixtures("docker_ipfs_node")


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end test requiring API access"
    )
    config.addinivalue_line(
        "markers", "requires_ipfs: mark test as requiring local IPFS node"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
