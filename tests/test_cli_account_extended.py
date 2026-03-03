"""
Unit tests for remaining CLI account handlers not covered in test_cli_account.py.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_account_balance,
    handle_account_delete,
    handle_account_info,
    handle_account_login,
    handle_account_switch,
)


# ---- handle_account_info ----


class TestAccountInfo:
    @patch(
        "hippius_sdk.cli_handlers_account.get_active_account", return_value="myaccount"
    )
    @patch(
        "hippius_sdk.cli_handlers_account.load_config",
        return_value={
            "accounts": {
                "active_account": "myaccount",
                "accounts": {
                    "myaccount": {
                        "api_token": "abc123xyz789",
                        "api_token_encoded": False,
                        "account_address": "5TestAddress",
                    }
                },
            }
        },
    )
    def test_account_info_success(self, mock_load, mock_active):
        result = handle_account_info()
        assert result == 0

    @patch(
        "hippius_sdk.cli_handlers_account.load_config",
        return_value={"accounts": {}},
    )
    def test_account_info_no_account(self, mock_load):
        """Returns 1 when no active account and none specified."""
        result = handle_account_info()
        assert result == 1

    @patch(
        "hippius_sdk.cli_handlers_account.get_active_account", return_value="myaccount"
    )
    @patch(
        "hippius_sdk.cli_handlers_account.load_config",
        return_value={
            "accounts": {
                "active_account": "myaccount",
                "accounts": {
                    "myaccount": {
                        "api_token": "abc123xyz789",
                        "api_token_encoded": False,
                        "account_address": "5TestAddress",
                    }
                },
            }
        },
    )
    def test_account_info_by_name(self, mock_load, mock_active):
        """Returns 0 when account name is specified explicitly."""
        result = handle_account_info(account_name="myaccount")
        assert result == 0

    @patch(
        "hippius_sdk.cli_handlers_account.load_config",
        return_value={
            "accounts": {
                "active_account": "myaccount",
                "accounts": {},
            }
        },
    )
    def test_account_info_not_found(self, mock_load):
        """Returns 1 when specified account not in accounts dict."""
        result = handle_account_info(account_name="nonexistent")
        assert result == 1


# ---- handle_account_switch ----


class TestAccountSwitch:
    @patch(
        "hippius_sdk.cli_handlers_account.get_account_address",
        return_value="5SomeAddress",
    )
    @patch("hippius_sdk.cli_handlers_account.set_active_account")
    @patch(
        "hippius_sdk.cli_handlers_account.list_accounts",
        return_value={"acct1": {}, "acct2": {}},
    )
    def test_account_switch_success(self, mock_list, mock_set, mock_addr):
        result = handle_account_switch("acct1")
        assert result == 0
        mock_set.assert_called_once_with("acct1")

    @patch(
        "hippius_sdk.cli_handlers_account.list_accounts",
        return_value={"acct1": {}},
    )
    def test_account_switch_not_found(self, mock_list):
        result = handle_account_switch("nonexistent")
        assert result == 1


# ---- handle_account_delete ----


class TestAccountDelete:
    @patch("hippius_sdk.cli_handlers_account.get_active_account", return_value="other")
    @patch("hippius_sdk.cli_handlers_account.delete_account")
    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=True)
    @patch(
        "hippius_sdk.cli_handlers_account.list_accounts",
        return_value={"myaccount": {}, "other": {}},
    )
    def test_account_delete_success(
        self, mock_list, mock_confirm, mock_delete, mock_active
    ):
        """Deleting a non-active account succeeds without hitting remaining-accounts branch."""
        result = handle_account_delete("myaccount")
        assert result == 0
        mock_delete.assert_called_once_with("myaccount")

    @patch(
        "hippius_sdk.cli_handlers_account.list_accounts",
        return_value={"acct1": {}},
    )
    def test_account_delete_not_found(self, mock_list):
        result = handle_account_delete("nonexistent")
        assert result == 1

    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=False)
    @patch(
        "hippius_sdk.cli_handlers_account.list_accounts",
        return_value={"myaccount": {}},
    )
    def test_account_delete_cancelled(self, mock_list, mock_confirm):
        """User declines confirmation, returns 0."""
        result = handle_account_delete("myaccount")
        assert result == 0


# ---- handle_account_login ----


class TestAccountLogin:
    @patch("hippius_sdk.cli_handlers_account.save_config")
    @patch(
        "hippius_sdk.cli_handlers_account.load_config",
        return_value={"accounts": {"active_account": None, "accounts": {}}},
    )
    @patch("hippius_sdk.cli_handlers_account.list_accounts", return_value={})
    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=False)
    @patch("hippius_sdk.cli_handlers_account.HippiusApiClient")
    @patch(
        "hippius_sdk.cli_handlers_account.click.prompt",
        side_effect=["testaccount", "my_api_token_123"],
    )
    @patch("hippius_sdk.cli_handlers_account.draw_logo")
    def test_account_login_success(
        self,
        mock_logo,
        mock_prompt,
        mock_api_class,
        mock_confirm,
        mock_list,
        mock_load,
        mock_save,
    ):
        # Set up mock API client for token validation
        mock_api_instance = MagicMock()
        mock_token_result = MagicMock()
        mock_token_result.substrate_address = "5TestAddress123"
        mock_api_instance.validate_token = AsyncMock(return_value=mock_token_result)
        mock_api_instance.close = AsyncMock()
        mock_api_instance.__aenter__ = AsyncMock(return_value=mock_api_instance)
        mock_api_instance.__aexit__ = AsyncMock(return_value=False)
        mock_api_class.return_value = mock_api_instance

        result = handle_account_login()
        assert result == 0
        mock_save.assert_called_once()
        saved_config = mock_save.call_args[0][0]
        assert "testaccount" in saved_config["accounts"]["accounts"]
        assert (
            saved_config["accounts"]["accounts"]["testaccount"]["api_token"]
            == "my_api_token_123"
        )
        assert (
            saved_config["accounts"]["accounts"]["testaccount"]["account_address"]
            == "5TestAddress123"
        )


# ---- handle_account_balance ----


class TestAccountBalance:
    @pytest.mark.asyncio
    @patch("hippius_sdk.cli_handlers_account.HippiusApiClient")
    @patch(
        "hippius_sdk.cli_handlers_account.get_config_value",
        return_value="https://api.hippius.com/api",
    )
    @patch("hippius_sdk.config.get_api_token", return_value="test_token")
    async def test_account_balance_success(
        self, mock_get_token, mock_get_config, mock_api_class
    ):
        """Returns 0 with credit balance."""
        mock_api_instance = MagicMock()
        mock_api_instance.get_account_balance = AsyncMock(
            return_value={"balance": 42.50, "account": "test@example.com"}
        )
        mock_api_instance.close = AsyncMock()
        mock_api_class.return_value = mock_api_instance

        client = MagicMock()
        result = await handle_account_balance(client)
        assert result == 0

    @pytest.mark.asyncio
    @patch("hippius_sdk.cli_handlers_account.HippiusApiClient")
    @patch(
        "hippius_sdk.cli_handlers_account.get_config_value",
        return_value="https://api.hippius.com/api",
    )
    @patch("hippius_sdk.config.get_api_token", return_value="test_token")
    async def test_account_balance_string_balance(
        self, mock_get_token, mock_get_config, mock_api_class
    ):
        """Balance as string is handled."""
        mock_api_instance = MagicMock()
        mock_api_instance.get_account_balance = AsyncMock(
            return_value={"balance": "100.00"}
        )
        mock_api_instance.close = AsyncMock()
        mock_api_class.return_value = mock_api_instance

        client = MagicMock()
        result = await handle_account_balance(client)
        assert result == 0
