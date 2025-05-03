"""
Unit tests for the CLI account management commands.
"""
from unittest.mock import MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_account_create,
    handle_account_export,
    handle_account_import,
    handle_account_list,
)


class TestCLIAccountCommands:
    """Tests for the CLI account management commands."""

    @patch("hippius_sdk.cli_handlers.getpass.getpass")
    @patch("hippius_sdk.cli_handlers.list_accounts")
    def test_handle_account_create(self, mock_list_accounts, mock_getpass):
        """Test the handle_account_create function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client
        
        # Set up mock response for list_accounts to return empty list (no existing accounts)
        mock_list_accounts.return_value = {}

        # Set up mock response from create_account
        mock_substrate_client.create_account.return_value = {
            "name": "test_account",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "mnemonic": "test word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
            "is_active": True,
        }
        
        # Mock the client's generate_seed_phrase method
        mock_substrate_client.generate_seed_phrase.return_value = "test word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"

        # Test creating an account without encryption
        with patch("hippius_sdk.cli_handlers.set_seed_phrase"), patch("hippius_sdk.cli_handlers.set_active_account"), patch("hippius_sdk.cli_handlers.get_account_address", return_value="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"):
            result = handle_account_create(mock_client, "test_account")

            # Verify the function returns successfully
            assert result == 0

    @patch("hippius_sdk.cli_handlers.getpass.getpass")
    @patch("hippius_sdk.cli_handlers.list_accounts")
    @patch("hippius_sdk.cli_handlers.HippiusClient")
    def test_handle_account_create_with_encryption(self, mock_HippiusClient, mock_list_accounts, mock_getpass):
        """Test the handle_account_create function with encryption."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client
        
        # Set up mock response for list_accounts to return empty list (no existing accounts)
        mock_list_accounts.return_value = {}

        # Set up mock password prompts
        mock_getpass.side_effect = ["password123", "password123"]

        # Set up mock response from generate_seed_phrase method
        mock_substrate_client.generate_seed_phrase.return_value = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
        
        # Set up mock for temporary client creation
        mock_temp_client = MagicMock()
        mock_temp_substrate = MagicMock()
        mock_temp_client.substrate_client = mock_temp_substrate
        mock_temp_substrate.get_account_address.return_value = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        mock_HippiusClient.return_value = mock_temp_client

        # Test creating an account with encryption
        with patch("hippius_sdk.cli_handlers.set_seed_phrase"), patch("hippius_sdk.cli_handlers.set_active_account"):
            result = handle_account_create(mock_client, "test_account", encrypt=True)

            # Verify the function returns successfully
            assert result == 0

            # Verify getpass was called twice
            assert mock_getpass.call_count == 2

    @patch("hippius_sdk.cli_handlers.getpass.getpass")
    def test_handle_account_create_password_mismatch(self, mock_getpass):
        """Test handle_account_create with password mismatch."""
        # Create mock client
        mock_client = MagicMock()

        # Set up password mismatch
        mock_getpass.side_effect = ["password123", "differentpassword"]

        # Test creating an account with encryption
        result = handle_account_create(mock_client, "test_account", encrypt=True)

        # Verify the function returns error code
        assert result == 1

        # Verify create_account was not called
        mock_client.substrate_client.create_account.assert_not_called()

    @patch("hippius_sdk.cli_handlers.load_config")
    @patch("hippius_sdk.cli_handlers.open")
    @patch("hippius_sdk.cli_handlers.json.dump")
    def test_handle_account_export(self, mock_json_dump, mock_open, mock_load_config):
        """Test the handle_account_export function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Mock the config data with a test account
        mock_load_config.return_value = {
            "substrate": {
                "accounts": {
                    "test_account": {
                        "seed_phrase": "test seed phrase",
                        "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                        "encrypted": False
                    }
                }
            }
        }

        # Test exporting an account
        result = handle_account_export(
            mock_client, name="test_account", file_path="test_export.json"
        )

        # Verify the function returns successfully
        assert result == 0
        
        # Verify the file was written with correct data
        mock_open.assert_called_once_with("test_export.json", "w")
        # Verify json.dump was called
        assert mock_json_dump.called

    @patch("hippius_sdk.cli_handlers.getpass.getpass")
    @patch("hippius_sdk.cli_handlers.os.path.exists")
    @patch("hippius_sdk.cli_handlers.open")
    @patch("hippius_sdk.cli_handlers.json.load")
    @patch("hippius_sdk.cli_handlers.set_seed_phrase")
    @patch("hippius_sdk.cli_handlers.set_active_account")
    @patch("hippius_sdk.cli_handlers.get_account_address")
    def test_handle_account_import(self, mock_get_address, mock_set_active, mock_set_seed, mock_json_load, mock_open, mock_exists, mock_getpass):
        """Test the handle_account_import function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client
        
        # Mock file operations
        mock_exists.return_value = True
        
        # Mock json load to return account data
        mock_json_load.return_value = {
            "name": "imported_account",
            "encrypted": False,
            "seed_phrase": "test seed phrase",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        }
        
        # Mock get_account_address
        mock_get_address.return_value = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

        # Test importing an account without encryption
        result = handle_account_import(mock_client, "test_import.json")

        # Verify the function returns successfully
        assert result == 0
        
        # Verify set_seed_phrase was called
        mock_set_seed.assert_called_once_with("test seed phrase", None, "imported_account")
        
        # Verify set_active_account was called
        mock_set_active.assert_called_once_with("imported_account")

    @patch("hippius_sdk.cli_handlers.getpass.getpass")
    @patch("hippius_sdk.cli_handlers.os.path.exists")
    @patch("hippius_sdk.cli_handlers.open")
    @patch("hippius_sdk.cli_handlers.json.load")
    @patch("hippius_sdk.cli_handlers.set_seed_phrase")
    @patch("hippius_sdk.cli_handlers.set_active_account")
    @patch("hippius_sdk.cli_handlers.get_account_address")
    def test_handle_account_import_with_encryption(self, mock_get_address, mock_set_active, mock_set_seed, mock_json_load, mock_open, mock_exists, mock_getpass):
        """Test the handle_account_import function with encryption."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock password prompts
        mock_getpass.side_effect = ["password123", "password123"]
        
        # Mock file operations
        mock_exists.return_value = True
        
        # Mock json load to return account data
        mock_json_load.return_value = {
            "name": "imported_account",
            "encrypted": False,
            "seed_phrase": "test seed phrase",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        }
        
        # Mock get_account_address
        mock_get_address.return_value = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

        # Test importing an account with encryption
        result = handle_account_import(mock_client, "test_import.json", encrypt=True)

        # Verify the function returns successfully
        assert result == 0

        # Verify getpass was called twice
        assert mock_getpass.call_count == 2
        
        # Verify set_seed_phrase was called with password
        mock_set_seed.assert_called_once_with("test seed phrase", "password123", "imported_account")
        
        # Verify set_active_account was called
        mock_set_active.assert_called_once_with("imported_account")

    @patch("hippius_sdk.cli_handlers.list_accounts")
    def test_handle_account_list(self, mock_list_accounts):
        """Test the handle_account_list function."""
        # Set up mock response from list_accounts
        mock_list_accounts.return_value = {
            "account1": {
                "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                "seed_phrase_encoded": True,
                "is_active": True,
            },
            "account2": {
                "ss58_address": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
                "seed_phrase_encoded": False,
            },
        }

        # Test listing accounts
        result = handle_account_list()

        # Verify the function returns successfully
        assert result == 0

        # Verify list_accounts was called
        mock_list_accounts.assert_called_once()

    @patch("hippius_sdk.cli_handlers.list_accounts")
    def test_handle_account_list_no_accounts(self, mock_list_accounts):
        """Test handle_account_list with no accounts."""
        # Set up mock response from list_accounts
        mock_list_accounts.return_value = {}

        # Test listing accounts when none exist
        result = handle_account_list()

        # Verify the function returns successfully
        assert result == 0

        # Verify list_accounts was called
        mock_list_accounts.assert_called_once()


if __name__ == "__main__":
    pytest.main()
