"""
Unit tests for CLI download handler.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_download


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.download_file = AsyncMock()
    return client


# ---- handle_download ----


@pytest.mark.asyncio
async def test_download_success(mock_client):
    """Returns 0 with valid result dict."""
    mock_client.download_file.return_value = {
        "output_path": "/tmp/output.txt",
        "size_bytes": 2048,
        "size_formatted": "2.00 KB",
        "file_id": "abc123",
    }

    result = await handle_download(mock_client, "abc123", "/tmp/output.txt")
    assert result == 0
    mock_client.download_file.assert_awaited_once_with("abc123", "/tmp/output.txt")
