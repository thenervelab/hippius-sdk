"""
Unit tests for CLI files and credits handlers.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from hippius_sdk.cli_handlers import handle_credits, handle_files


@pytest.fixture
def mock_client():
    client = MagicMock()
    return client


# ---- handle_files tests ----


@pytest.mark.asyncio
async def test_files_stub(mock_client):
    """Files command returns 0 (stub)."""
    result = await handle_files(mock_client)
    assert result == 0


# ---- handle_credits tests ----


@pytest.mark.asyncio
@patch(
    "hippius_sdk.cli_handlers_file.get_config_value",
    return_value="https://api.hippius.com/api",
)
@patch("hippius_sdk.config.get_api_token", return_value="test_token")
@patch("hippius_sdk.cli_handlers_file.HippiusApiClient")
async def test_credits_success(
    mock_api_class, mock_get_token, mock_get_config, mock_client
):
    """handle_credits returns 0 and formats balance."""
    mock_api_instance = MagicMock()
    mock_api_instance.get_account_balance = AsyncMock(return_value={"balance": 42.50})
    mock_api_instance.close = AsyncMock()
    mock_api_class.return_value = mock_api_instance

    result = await handle_credits(mock_client)
    assert result == 0
    mock_api_instance.get_account_balance.assert_awaited_once()


@pytest.mark.asyncio
@patch(
    "hippius_sdk.cli_handlers_file.get_config_value",
    return_value="https://api.hippius.com/api",
)
@patch("hippius_sdk.config.get_api_token", return_value="test_token")
@patch("hippius_sdk.cli_handlers_file.HippiusApiClient")
async def test_credits_string_balance(
    mock_api_class, mock_get_token, mock_get_config, mock_client
):
    """Balance as string is handled without error."""
    mock_api_instance = MagicMock()
    mock_api_instance.get_account_balance = AsyncMock(return_value={"balance": "99.99"})
    mock_api_instance.close = AsyncMock()
    mock_api_class.return_value = mock_api_instance

    result = await handle_credits(mock_client)
    assert result == 0
