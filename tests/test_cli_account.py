"""
Unit tests for the CLI account management commands.
"""
from unittest.mock import MagicMock, patch

import pytest

from hippius_sdk.cli import (
    handle_account_create,
    handle_account_export,
    handle_account_import,
    handle_account_list,
)


class TestCLIAccountCommands:
    """Tests for the CLI account management commands."""

    @patch("hippius_sdk.cli.getpass.getpass")
    def test_handle_account_create(self, mock_getpass):
        """Test the handle_account_create function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock response from create_account
        mock_substrate_client.create_account.return_value = {
            "name": "test_account",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "mnemonic": "test word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
            "is_active": True,
        }

        # Test creating an account without encryption
        result = handle_account_create(mock_client, "test_account")

        # Verify the function returns successfully
        assert result == 0

        # Verify create_account was called with correct arguments
        mock_substrate_client.create_account.assert_called_once_with(
            "test_account", encode=False, password=None
        )

    @patch("hippius_sdk.cli.getpass.getpass")
    def test_handle_account_create_with_encryption(self, mock_getpass):
        """Test the handle_account_create function with encryption."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock password prompts
        mock_getpass.side_effect = ["password123", "password123"]

        # Set up mock response from create_account
        mock_substrate_client.create_account.return_value = {
            "name": "test_account",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "mnemonic": "test word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
            "is_active": True,
        }

        # Test creating an account with encryption
        result = handle_account_create(mock_client, "test_account", encrypt=True)

        # Verify the function returns successfully
        assert result == 0

        # Verify getpass was called twice
        assert mock_getpass.call_count == 2

        # Verify create_account was called with correct arguments
        mock_substrate_client.create_account.assert_called_once_with(
            "test_account", encode=True, password="password123"
        )

    @patch("hippius_sdk.cli.getpass.getpass")
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

    def test_handle_account_export(self):
        """Test the handle_account_export function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock response from export_account
        mock_substrate_client.export_account.return_value = "test_export.json"

        # Test exporting an account
        result = handle_account_export(
            mock_client, name="test_account", file_path="test_export.json"
        )

        # Verify the function returns successfully
        assert result == 0

        # Verify export_account was called with correct arguments
        mock_substrate_client.export_account.assert_called_once_with(
            account_name="test_account", file_path="test_export.json"
        )

    @patch("hippius_sdk.cli.getpass.getpass")
    def test_handle_account_import(self, mock_getpass):
        """Test the handle_account_import function."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock response from import_account
        mock_substrate_client.import_account.return_value = {
            "name": "imported_account",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "is_active": True,
        }

        # Test importing an account without encryption
        result = handle_account_import(mock_client, "test_import.json")

        # Verify the function returns successfully
        assert result == 0

        # Verify import_account was called with correct arguments
        mock_substrate_client.import_account.assert_called_once_with(
            "test_import.json", password=None
        )

    @patch("hippius_sdk.cli.getpass.getpass")
    def test_handle_account_import_with_encryption(self, mock_getpass):
        """Test the handle_account_import function with encryption."""
        # Create mock client
        mock_client = MagicMock()
        mock_substrate_client = MagicMock()
        mock_client.substrate_client = mock_substrate_client

        # Set up mock password prompts
        mock_getpass.side_effect = ["password123", "password123"]

        # Set up mock response from import_account
        mock_substrate_client.import_account.return_value = {
            "name": "imported_account",
            "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "is_active": True,
        }

        # Test importing an account with encryption
        result = handle_account_import(mock_client, "test_import.json", encrypt=True)

        # Verify the function returns successfully
        assert result == 0

        # Verify getpass was called twice
        assert mock_getpass.call_count == 2

        # Verify import_account was called with correct arguments
        mock_substrate_client.import_account.assert_called_once_with(
            "test_import.json", password="password123"
        )

    @patch("hippius_sdk.cli.list_accounts")
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

    @patch("hippius_sdk.cli.list_accounts")
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
