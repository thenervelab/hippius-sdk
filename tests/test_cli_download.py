"""
Unit tests for CLI download, exists, and cat handlers.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_cat, handle_download, handle_exists


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.download_file = AsyncMock()
    client.exists = AsyncMock()
    return client


# ---- handle_download ----


@pytest.mark.asyncio
async def test_download_success(mock_client):
    """Returns 0 with valid result dict."""
    mock_client.download_file.return_value = {
        "elapsed_seconds": 1.23,
        "output_path": "/tmp/output.txt",
        "size_bytes": 2048,
        "size_formatted": "2.00 KB",
        "is_directory": False,
        "decrypted": False,
    }

    result = await handle_download(mock_client, "QmTestCid123", "/tmp/output.txt")
    assert result == 0
    mock_client.download_file.assert_awaited_once_with(
        "QmTestCid123", "/tmp/output.txt", decrypt=None
    )


@pytest.mark.asyncio
async def test_download_with_decrypt(mock_client):
    """Passes decrypt=True through."""
    mock_client.download_file.return_value = {
        "elapsed_seconds": 0.5,
        "output_path": "/tmp/out.txt",
        "size_bytes": 100,
        "size_formatted": "100 B",
        "is_directory": False,
        "decrypted": True,
    }

    result = await handle_download(
        mock_client, "QmTestCid", "/tmp/out.txt", decrypt=True
    )
    assert result == 0
    mock_client.download_file.assert_awaited_once_with(
        "QmTestCid", "/tmp/out.txt", decrypt=True
    )


@pytest.mark.asyncio
async def test_download_directory(mock_client):
    """is_directory=True branch covered."""
    mock_client.download_file.return_value = {
        "elapsed_seconds": 2.0,
        "output_path": "/tmp/mydir",
        "size_bytes": 4096,
        "size_formatted": "4.00 KB",
        "is_directory": True,
        "decrypted": False,
    }

    result = await handle_download(mock_client, "QmDirCid", "/tmp/mydir")
    assert result == 0


# ---- handle_exists ----


@pytest.mark.asyncio
async def test_exists_found(mock_client):
    """exists=True returns 0."""
    mock_client.exists.return_value = {
        "formatted_cid": "QmTestCid123",
        "exists": True,
    }

    result = await handle_exists(mock_client, "QmTestCid123")
    assert result == 0


@pytest.mark.asyncio
async def test_exists_not_found(mock_client):
    """exists=False returns 0."""
    mock_client.exists.return_value = {
        "formatted_cid": "QmMissing",
        "exists": False,
    }

    result = await handle_exists(mock_client, "QmMissing")
    assert result == 0


# ---- handle_cat ----


@pytest.mark.asyncio
async def test_cat_text_content(mock_client, capsys):
    """Displays UTF-8 content from temp file."""

    async def _write_text(cid, path, decrypt=None):
        with open(path, "wb") as f:
            f.write(b"Hello, Hippius!")
        return {"size_formatted": "14 B", "decrypted": False}

    mock_client.download_file.side_effect = _write_text

    result = await handle_cat(mock_client, "QmTextCid", max_size=1024)
    assert result is None  # handle_cat doesn't explicitly return for text path

    captured = capsys.readouterr()
    assert "Hello, Hippius!" in captured.out


@pytest.mark.asyncio
async def test_cat_binary_content(mock_client):
    """Handles binary (non-UTF-8) content without crash."""

    async def _write_binary(cid, path, decrypt=None):
        with open(path, "wb") as f:
            f.write(bytes(range(256)))
        return {"size_formatted": "256 B", "decrypted": False}

    mock_client.download_file.side_effect = _write_binary

    # Should not raise
    result = await handle_cat(mock_client, "QmBinaryCid", max_size=1024)
    # handle_cat doesn't explicitly return for binary path either
    assert result is None
