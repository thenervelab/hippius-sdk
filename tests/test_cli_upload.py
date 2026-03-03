"""
Unit tests for CLI store handler.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_store


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.upload_file = AsyncMock()
    return client


# ---- handle_store ----


@pytest.mark.asyncio
async def test_store_file_not_found(mock_client):
    """Returns 1 for nonexistent path."""
    result = await handle_store(mock_client, "/nonexistent/file.txt")
    assert result == 1


@pytest.mark.asyncio
async def test_store_not_a_file(mock_client, tmp_path):
    """Returns 1 for directory path."""
    result = await handle_store(mock_client, str(tmp_path))
    assert result == 1


@pytest.mark.asyncio
async def test_store_success(mock_client, tmp_path):
    """Returns 0, calls upload_file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")

    mock_client.upload_file.return_value = {
        "file_id": "abc123def456",
        "size_bytes": 11,
        "size_formatted": "11 bytes",
        "filename": "test.txt",
        "upload_id": "upload-123",
        "timestamp": 1234567890,
    }

    result = await handle_store(mock_client, str(test_file))
    assert result == 0
    mock_client.upload_file.assert_awaited_once()
