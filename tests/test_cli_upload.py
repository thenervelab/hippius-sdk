"""
Unit tests for CLI store and store-dir handlers.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_store, handle_store_dir


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.upload_file = AsyncMock()
    client.api_client = MagicMock()
    client.api_client.pin_file = AsyncMock()
    client.ipfs_client = MagicMock()
    client.ipfs_client.upload_directory = AsyncMock()
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
    """Returns 0, calls upload_file + pin_file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")

    mock_client.upload_file.return_value = {
        "cid": "QmUploadedCid123",
        "encrypted": False,
    }
    mock_client.api_client.pin_file.return_value = {"status": "ok"}

    result = await handle_store(mock_client, str(test_file))
    assert result == 0
    mock_client.upload_file.assert_awaited_once()
    mock_client.api_client.pin_file.assert_awaited_once()


@pytest.mark.asyncio
async def test_store_no_publish(mock_client, tmp_path):
    """publish=False skips pin_file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")

    mock_client.upload_file.return_value = {
        "cid": "QmUploadedCid456",
        "encrypted": False,
    }

    result = await handle_store(mock_client, str(test_file), publish=False)
    assert result == 0
    mock_client.upload_file.assert_awaited_once()
    mock_client.api_client.pin_file.assert_not_awaited()


# ---- handle_store_dir ----


@pytest.mark.asyncio
async def test_store_dir_not_found(mock_client):
    """Returns 1 for nonexistent dir."""
    result = await handle_store_dir(mock_client, "/nonexistent/dir")
    assert result == 1


@pytest.mark.asyncio
async def test_store_dir_not_a_dir(mock_client, tmp_path):
    """Returns 1 for file path."""
    test_file = tmp_path / "file.txt"
    test_file.write_text("not a dir")

    result = await handle_store_dir(mock_client, str(test_file))
    assert result == 1


@pytest.mark.asyncio
async def test_store_dir_success(mock_client, tmp_path):
    """Returns 0, calls upload_directory + pin_file."""
    # Create some files in the dir
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")

    mock_client.ipfs_client.upload_directory.return_value = {
        "cid": "QmDirCid789",
        "encrypted": False,
        "files": [
            {"name": "a.txt", "cid": "QmFileCidA"},
            {"name": "b.txt", "cid": "QmFileCidB"},
        ],
    }
    mock_client.api_client.pin_file.return_value = {"status": "ok"}

    result = await handle_store_dir(mock_client, str(tmp_path))
    assert result == 0
    mock_client.ipfs_client.upload_directory.assert_awaited_once()
    mock_client.api_client.pin_file.assert_awaited_once()
