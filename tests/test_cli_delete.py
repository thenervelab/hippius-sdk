"""
Unit tests for CLI delete, pin, and ec-delete handlers.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_delete, handle_ec_delete, handle_pin


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.exists = AsyncMock()
    client.delete_file = AsyncMock()
    client.delete_ec_file = AsyncMock()
    client.ipfs_client = MagicMock()
    client.ipfs_client.pin = AsyncMock()
    return client


# ---- handle_delete ----


@pytest.mark.asyncio
async def test_delete_forced(mock_client):
    """force=True skips confirmation, returns 0."""
    mock_client.exists.return_value = {"exists": True, "formatted_cid": "QmTestCid"}
    mock_client.delete_file.return_value = {
        "is_directory": False,
        "child_files": [],
        "timing": {"duration_seconds": 0.5},
    }

    result = await handle_delete(mock_client, "QmTestCid", force=True)
    assert result == 0
    mock_client.delete_file.assert_awaited_once_with("QmTestCid")


@pytest.mark.asyncio
async def test_delete_not_found(mock_client):
    """exists=False returns 1."""
    mock_client.exists.return_value = {"exists": False, "formatted_cid": "QmMissing"}

    result = await handle_delete(mock_client, "QmMissing", force=True)
    assert result == 1
    mock_client.delete_file.assert_not_awaited()


@pytest.mark.asyncio
@patch("builtins.input", return_value="n")
async def test_delete_cancelled(mock_input, mock_client):
    """User inputs 'n', returns 0."""
    mock_client.exists.return_value = {"exists": True, "formatted_cid": "QmTestCid"}

    result = await handle_delete(mock_client, "QmTestCid", force=False)
    assert result == 0
    mock_client.delete_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_directory(mock_client):
    """is_directory=True with child_files."""
    mock_client.exists.return_value = {"exists": True, "formatted_cid": "QmDirCid"}
    mock_client.delete_file.return_value = {
        "is_directory": True,
        "child_files": [
            {"name": "file1.txt", "cid": "QmChild1"},
            {"name": "file2.txt", "cid": "QmChild2"},
        ],
        "timing": {"duration_seconds": 1.2},
    }

    result = await handle_delete(mock_client, "QmDirCid", force=True)
    assert result == 0


# ---- handle_pin ----


@pytest.mark.asyncio
async def test_pin_success(mock_client):
    """Returns 0 when CID exists and pin succeeds."""
    mock_client.exists.return_value = {"exists": True, "formatted_cid": "QmTestCid"}
    mock_client.ipfs_client.pin.return_value = {"success": True}

    result = await handle_pin(mock_client, "QmTestCid")
    assert result == 0


@pytest.mark.asyncio
async def test_pin_not_found(mock_client):
    """Returns 1 when CID not found."""
    mock_client.exists.return_value = {"exists": False, "formatted_cid": "QmMissing"}

    result = await handle_pin(mock_client, "QmMissing")
    assert result == 1


@pytest.mark.asyncio
async def test_pin_failure(mock_client):
    """Returns 1 when exists check raises exception."""
    mock_client.exists.side_effect = Exception("connection error")

    result = await handle_pin(mock_client, "QmBadCid")
    assert result == 1


# ---- handle_ec_delete ----


@pytest.mark.asyncio
async def test_ec_delete_forced(mock_client):
    """force=True returns 0."""
    mock_client.delete_ec_file.return_value = None

    result = await handle_ec_delete(mock_client, "QmMetaCid", force=True)
    assert result == 0
    mock_client.delete_ec_file.assert_awaited_once_with("QmMetaCid")


@pytest.mark.asyncio
@patch("builtins.input", return_value="n")
async def test_ec_delete_cancelled(mock_input, mock_client):
    """User inputs 'n', returns 0."""
    result = await handle_ec_delete(mock_client, "QmMetaCid", force=False)
    assert result == 0
    mock_client.delete_ec_file.assert_not_awaited()
