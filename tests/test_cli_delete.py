"""
Unit tests for CLI delete handler.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_delete


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.delete_file = AsyncMock()
    return client


# ---- handle_delete ----


@pytest.mark.asyncio
async def test_delete_forced(mock_client):
    """force=True skips confirmation, returns 0."""
    mock_client.delete_file.return_value = {
        "status": "deleted",
        "file_id": "abc123",
    }

    result = await handle_delete(mock_client, "abc123", force=True)
    assert result == 0
    mock_client.delete_file.assert_awaited_once_with("abc123")


@pytest.mark.asyncio
@patch("hippius_sdk.cli_handlers_file.click.confirm", return_value=False)
async def test_delete_cancelled(mock_confirm, mock_client):
    """User declines, returns 0."""
    result = await handle_delete(mock_client, "abc123", force=False)
    assert result == 0
    mock_client.delete_file.assert_not_awaited()
