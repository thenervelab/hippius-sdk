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
    @patch("hippius_sdk.cli_handlers.get_active_account", return_value="myaccount")
    @patch(
        "hippius_sdk.cli_handlers.load_config",
        return_value={
            "substrate": {
                "active_account": "myaccount",
                "accounts": {
                    "myaccount": {
                        "hippius_key": "abc123xyz789",
                        "hippius_key_encoded": False,
                    }
                },
            }
        },
    )
    def test_account_info_success(self, mock_load, mock_active):
        result = handle_account_info()
        assert result == 0

    @patch(
        "hippius_sdk.cli_handlers.load_config",
        return_value={"substrate": {}},
    )
    def test_account_info_no_account(self, mock_load):
        """Returns 1 when no active account and none specified."""
        result = handle_account_info()
        assert result == 1

    @patch("hippius_sdk.cli_handlers.get_active_account", return_value="myaccount")
    @patch(
        "hippius_sdk.cli_handlers.load_config",
        return_value={
            "substrate": {
                "active_account": "myaccount",
                "accounts": {
                    "myaccount": {
                        "hippius_key": "abc123xyz789",
                        "hippius_key_encoded": False,
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
        "hippius_sdk.cli_handlers.load_config",
        return_value={
            "substrate": {
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
    @patch("hippius_sdk.cli_handlers.get_account_address", return_value="5SomeAddress")
    @patch("hippius_sdk.cli_handlers.set_active_account")
    @patch(
        "hippius_sdk.cli_handlers.list_accounts",
        return_value={"acct1": {}, "acct2": {}},
    )
    def test_account_switch_success(self, mock_list, mock_set, mock_addr):
        result = handle_account_switch("acct1")
        assert result == 0
        mock_set.assert_called_once_with("acct1")

    @patch(
        "hippius_sdk.cli_handlers.list_accounts",
        return_value={"acct1": {}},
    )
    def test_account_switch_not_found(self, mock_list):
        result = handle_account_switch("nonexistent")
        assert result == 1


# ---- handle_account_delete ----


class TestAccountDelete:
    @patch("hippius_sdk.cli_handlers.get_active_account", return_value="other")
    @patch("hippius_sdk.cli_handlers.delete_account")
    @patch("hippius_sdk.cli_handlers.click.confirm", return_value=True)
    @patch(
        "hippius_sdk.cli_handlers.list_accounts",
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
        "hippius_sdk.cli_handlers.list_accounts",
        return_value={"acct1": {}},
    )
    def test_account_delete_not_found(self, mock_list):
        result = handle_account_delete("nonexistent")
        assert result == 1

    @patch("hippius_sdk.cli_handlers.click.confirm", return_value=False)
    @patch(
        "hippius_sdk.cli_handlers.list_accounts",
        return_value={"myaccount": {}},
    )
    def test_account_delete_cancelled(self, mock_list, mock_confirm):
        """User declines confirmation, returns 0."""
        result = handle_account_delete("myaccount")
        assert result == 0


# ---- handle_account_login ----


class TestAccountLogin:
    @patch("hippius_sdk.cli_handlers.save_config")
    @patch(
        "hippius_sdk.cli_handlers.load_config",
        return_value={"substrate": {"accounts": {}}},
    )
    @patch("hippius_sdk.cli_handlers.list_accounts", return_value={})
    @patch("hippius_sdk.cli_handlers.click.confirm", return_value=False)
    @patch(
        "hippius_sdk.cli_handlers.click.prompt",
        side_effect=["testaccount", "my_hippius_key_123"],
    )
    @patch("hippius_sdk.cli_handlers.draw_logo")
    def test_account_login_success(
        self, mock_logo, mock_prompt, mock_confirm, mock_list, mock_load, mock_save
    ):
        result = handle_account_login()
        assert result == 0
        mock_save.assert_called_once()
        saved_config = mock_save.call_args[0][0]
        assert "testaccount" in saved_config["substrate"]["accounts"]
        assert (
            saved_config["substrate"]["accounts"]["testaccount"]["hippius_key"]
            == "my_hippius_key_123"
        )


# ---- handle_account_balance ----


class TestAccountBalance:
    @pytest.mark.asyncio
    async def test_account_balance_success(self):
        """Returns 0 with credit balance."""
        client = MagicMock()
        client.api_client = MagicMock()
        client.api_client.get_account_balance = AsyncMock(
            return_value={"balance": 42.50, "account": "test@example.com"}
        )

        result = await handle_account_balance(client)
        assert result == 0
        client.api_client.get_account_balance.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_account_balance_string_balance(self):
        """Balance as string is handled."""
        client = MagicMock()
        client.api_client = MagicMock()
        client.api_client.get_account_balance = AsyncMock(
            return_value={"balance": "100.00"}
        )

        result = await handle_account_balance(client)
        assert result == 0
