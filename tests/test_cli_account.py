"""
Unit tests for the CLI account management commands.

Updated for v0.3.0 - HIPPIUS_KEY authentication only.
"""
from unittest.mock import MagicMock, mock_open, patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_account_create,
    handle_account_export,
    handle_account_import,
    handle_account_list,
)


class TestCLIAccountCommands:
    """Tests for the CLI account management commands."""

    def test_handle_account_create_deprecated(self):
        """Test that handle_account_create returns deprecation error."""
        mock_client = MagicMock()

        # handle_account_create should now return 1 (error) with deprecation message
        result = handle_account_create(mock_client, "test_account", encrypt=False)

        # Should return error code
        assert result == 1

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("hippius_sdk.cli_handlers.load_config")
    @patch("hippius_sdk.cli_handlers.get_active_account")
    def test_handle_account_export(self, mock_get_active, mock_load_config, mock_json_dump, mock_file):
        """Test the handle_account_export function with HIPPIUS_KEY."""
        mock_client = MagicMock()

        # Mock configuration
        mock_config = {
            "substrate": {
                "accounts": {
                    "test_account": {
                        "hippius_key": "test_key_123",
                        "hippius_key_encoded": False,
                        "hippius_key_salt": None,
                    }
                }
            }
        }
        mock_load_config.return_value = mock_config
        mock_get_active.return_value = "test_account"

        # Test exporting account
        result = handle_account_export(mock_client, name="test_account", file_path="test_export.json")

        # Verify success
        assert result == 0
        mock_json_dump.assert_called_once()

        # Verify exported data structure (HIPPIUS_KEY format)
        exported_data = mock_json_dump.call_args[0][0]
        assert exported_data["name"] == "test_account"
        assert exported_data["hippius_key"] == "test_key_123"
        assert exported_data["hippius_key_encoded"] is False

    @patch("builtins.open", new_callable=mock_open, read_data='{"name":"test_account","hippius_key":"test_key_123","hippius_key_encoded":false}')
    @patch("os.path.exists", return_value=True)
    @patch("hippius_sdk.cli_handlers.list_accounts")
    @patch("hippius_sdk.cli_handlers.load_config")
    @patch("hippius_sdk.cli_handlers.save_config")
    @patch("builtins.input", return_value="y")
    def test_handle_account_import(
        self, mock_input, mock_save_config, mock_load_config, mock_list_accounts, mock_exists, mock_file
    ):
        """Test the handle_account_import function with HIPPIUS_KEY."""
        mock_client = MagicMock()

        # Mock existing accounts (account exists, will prompt for overwrite)
        mock_list_accounts.return_value = {"test_account": {}}

        # Mock configuration
        mock_config = {
            "substrate": {
                "accounts": {}
            }
        }
        mock_load_config.return_value = mock_config

        # Test importing account
        result = handle_account_import(mock_client, file_path="test_import.json", encrypt=False)

        # Verify success
        assert result == 0
        mock_save_config.assert_called_once()

        # Verify account was added to config with HIPPIUS_KEY
        saved_config = mock_save_config.call_args[0][0]
        assert "test_account" in saved_config["substrate"]["accounts"]
        account_data = saved_config["substrate"]["accounts"]["test_account"]
        assert account_data["hippius_key"] == "test_key_123"
        assert account_data["hippius_key_encoded"] is False

    @patch("builtins.open", new_callable=mock_open, read_data='{"name":"new_account","hippius_key":"new_key_456","hippius_key_encoded":false}')
    @patch("os.path.exists", return_value=True)
    @patch("hippius_sdk.cli_handlers.list_accounts")
    @patch("hippius_sdk.cli_handlers.load_config")
    @patch("hippius_sdk.cli_handlers.save_config")
    def test_handle_account_import_new_account(
        self, mock_save_config, mock_load_config, mock_list_accounts, mock_exists, mock_file
    ):
        """Test importing a new account (no overwrite prompt)."""
        mock_client = MagicMock()

        # Mock no existing accounts
        mock_list_accounts.return_value = {}

        # Mock configuration
        mock_config = {
            "substrate": {
                "accounts": {}
            }
        }
        mock_load_config.return_value = mock_config

        # Test importing new account
        result = handle_account_import(mock_client, file_path="new_import.json", encrypt=False)

        # Verify success
        assert result == 0
        mock_save_config.assert_called_once()

    @patch("hippius_sdk.cli_handlers.list_accounts")
    @patch("hippius_sdk.cli_handlers.get_active_account")
    @patch("hippius_sdk.cli_handlers.load_config")
    def test_handle_account_list(self, mock_load_config, mock_get_active, mock_list_accounts):
        """Test the handle_account_list function."""
        # Mock accounts
        mock_list_accounts.return_value = {"account1": {}, "account2": {}}
        mock_get_active.return_value = "account1"

        # Mock config with account details
        mock_config = {
            "substrate": {
                "accounts": {
                    "account1": {
                        "hippius_key": "key1",
                        "hippius_key_encoded": False
                    },
                    "account2": {
                        "hippius_key": "key2",
                        "hippius_key_encoded": True
                    }
                }
            }
        }
        mock_load_config.return_value = mock_config

        # Test listing accounts
        result = handle_account_list()

        # Verify success
        assert result == 0

    @patch("hippius_sdk.cli_handlers.list_accounts")
    def test_handle_account_list_no_accounts(self, mock_list_accounts):
        """Test the handle_account_list function with no accounts."""
        # Mock no accounts
        mock_list_accounts.return_value = {}

        # Test listing accounts
        result = handle_account_list()

        # Verify success (empty list is valid)
        assert result == 0
