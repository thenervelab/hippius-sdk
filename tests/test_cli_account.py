"""
Unit tests for the CLI account management commands.

Updated for Arion migration - API token authentication.
"""
from unittest.mock import MagicMock, mock_open, patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_account_export,
    handle_account_import,
    handle_account_list,
)


class TestCLIAccountCommands:
    """Tests for the CLI account management commands."""

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("hippius_sdk.cli_handlers_account.load_config")
    @patch("hippius_sdk.cli_handlers_account.get_active_account")
    def test_handle_account_export(
        self, mock_get_active, mock_load_config, mock_json_dump, mock_file
    ):
        """Test the handle_account_export function with API token."""
        mock_client = MagicMock()

        # Mock configuration (new format)
        mock_config = {
            "accounts": {
                "active_account": "test_account",
                "accounts": {
                    "test_account": {
                        "api_token": "test_token_123",
                        "api_token_encoded": False,
                        "api_token_salt": None,
                        "account_address": "5TestAddr",
                    }
                },
            }
        }
        mock_load_config.return_value = mock_config
        mock_get_active.return_value = "test_account"

        # Test exporting account
        result = handle_account_export(
            mock_client, name="test_account", file_path="test_export.json"
        )

        # Verify success
        assert result == 0
        mock_json_dump.assert_called_once()

        # Verify exported data structure
        exported_data = mock_json_dump.call_args[0][0]
        assert exported_data["name"] == "test_account"
        assert exported_data["api_token"] == "test_token_123"
        assert exported_data["api_token_encoded"] is False

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"name":"test_account","api_token":"test_token_123","api_token_encoded":false,"account_address":"5TestAddr"}',
    )
    @patch("os.path.exists", return_value=True)
    @patch("hippius_sdk.cli_handlers_account.list_accounts")
    @patch("hippius_sdk.cli_handlers_account.load_config")
    @patch("hippius_sdk.cli_handlers_account.save_config")
    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=True)
    def test_handle_account_import(
        self,
        mock_confirm,
        mock_save_config,
        mock_load_config,
        mock_list_accounts,
        mock_exists,
        mock_file,
    ):
        """Test the handle_account_import function with API token."""
        mock_client = MagicMock()

        # Mock existing accounts (account exists, will prompt for overwrite)
        mock_list_accounts.return_value = {"test_account": {}}

        # Mock configuration (new format)
        mock_config = {
            "accounts": {
                "active_account": None,
                "accounts": {},
            }
        }
        mock_load_config.return_value = mock_config

        # Test importing account
        result = handle_account_import(
            mock_client, file_path="test_import.json", encrypt=False
        )

        # Verify success
        assert result == 0
        mock_save_config.assert_called_once()

        # Verify account was added to config with API token
        saved_config = mock_save_config.call_args[0][0]
        assert "test_account" in saved_config["accounts"]["accounts"]
        account_data = saved_config["accounts"]["accounts"]["test_account"]
        assert account_data["api_token"] == "test_token_123"
        assert account_data["api_token_encoded"] is False

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"name":"new_account","api_token":"new_token_456","api_token_encoded":false,"account_address":"5NewAddr"}',
    )
    @patch("os.path.exists", return_value=True)
    @patch("hippius_sdk.cli_handlers_account.list_accounts")
    @patch("hippius_sdk.cli_handlers_account.load_config")
    @patch("hippius_sdk.cli_handlers_account.save_config")
    def test_handle_account_import_new_account(
        self,
        mock_save_config,
        mock_load_config,
        mock_list_accounts,
        mock_exists,
        mock_file,
    ):
        """Test importing a new account (no overwrite prompt)."""
        mock_client = MagicMock()

        # Mock no existing accounts
        mock_list_accounts.return_value = {}

        # Mock configuration (new format)
        mock_config = {
            "accounts": {
                "active_account": None,
                "accounts": {},
            }
        }
        mock_load_config.return_value = mock_config

        # Test importing new account
        result = handle_account_import(
            mock_client, file_path="new_import.json", encrypt=False
        )

        # Verify success
        assert result == 0
        mock_save_config.assert_called_once()

    @patch("hippius_sdk.cli_handlers_account.list_accounts")
    @patch("hippius_sdk.cli_handlers_account.get_active_account")
    @patch("hippius_sdk.cli_handlers_account.load_config")
    def test_handle_account_list(
        self, mock_load_config, mock_get_active, mock_list_accounts
    ):
        """Test the handle_account_list function."""
        # Mock accounts
        mock_list_accounts.return_value = {"account1": {}, "account2": {}}
        mock_get_active.return_value = "account1"

        # Mock config with account details (new format)
        mock_config = {
            "accounts": {
                "active_account": "account1",
                "accounts": {
                    "account1": {
                        "api_token": "token1",
                        "api_token_encoded": False,
                        "account_address": "5Addr1",
                    },
                    "account2": {
                        "api_token": "token2",
                        "api_token_encoded": True,
                        "account_address": "5Addr2",
                    },
                },
            }
        }
        mock_load_config.return_value = mock_config

        # Test listing accounts
        result = handle_account_list()

        # Verify success
        assert result == 0

    @patch("hippius_sdk.cli_handlers_account.list_accounts")
    def test_handle_account_list_no_accounts(self, mock_list_accounts):
        """Test the handle_account_list function with no accounts."""
        # Mock no accounts
        mock_list_accounts.return_value = {}

        # Test listing accounts
        result = handle_account_list()

        # Verify success (empty list is valid)
        assert result == 0
