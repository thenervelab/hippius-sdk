"""
Unit tests for CLI default-address handlers.
"""

from unittest.mock import patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_default_address_clear,
    handle_default_address_get,
    handle_default_address_set,
)


class TestDefaultAddressSet:
    @patch("hippius_sdk.cli_handlers_address.save_config")
    @patch(
        "hippius_sdk.cli_handlers_address.load_config",
        return_value={"substrate": {}},
    )
    def test_address_set_valid(self, mock_load, mock_save):
        """Address starting with '5' is saved."""
        result = handle_default_address_set(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        assert result == 0
        mock_save.assert_called_once()
        saved_config = mock_save.call_args[0][0]
        assert (
            saved_config["substrate"]["default_address"]
            == "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )

    @patch("hippius_sdk.cli_handlers_address.click.confirm", return_value=False)
    def test_address_set_invalid_declined(self, mock_confirm):
        """Non-'5' address, user declines -> returns 1."""
        result = handle_default_address_set("1InvalidAddress")
        assert result == 1

    @patch("hippius_sdk.cli_handlers_address.save_config")
    @patch(
        "hippius_sdk.cli_handlers_address.load_config",
        return_value={},
    )
    def test_address_set_creates_substrate_section(self, mock_load, mock_save):
        """Config without 'substrate' key gets it created."""
        result = handle_default_address_set("5SomeValidAddress")
        assert result == 0
        saved_config = mock_save.call_args[0][0]
        assert "substrate" in saved_config
        assert saved_config["substrate"]["default_address"] == "5SomeValidAddress"


class TestDefaultAddressGet:
    @patch(
        "hippius_sdk.cli_handlers_address.get_default_address",
        return_value="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    )
    def test_address_get_exists(self, mock_get):
        """Returns 0 and shows address."""
        result = handle_default_address_get()
        assert result == 0

    @patch("hippius_sdk.cli_handlers_address.get_default_address", return_value=None)
    def test_address_get_none(self, mock_get):
        """Returns 0 and shows warning when no address set."""
        result = handle_default_address_get()
        assert result == 0


class TestDefaultAddressClear:
    @patch("hippius_sdk.cli_handlers_address.save_config")
    @patch(
        "hippius_sdk.cli_handlers_address.load_config",
        return_value={"substrate": {"default_address": "5SomeAddress"}},
    )
    def test_address_clear_exists(self, mock_load, mock_save):
        """Removes default_address from config."""
        result = handle_default_address_clear()
        assert result == 0
        mock_save.assert_called_once()
        saved_config = mock_save.call_args[0][0]
        assert "default_address" not in saved_config["substrate"]

    @patch(
        "hippius_sdk.cli_handlers_address.load_config",
        return_value={"substrate": {}},
    )
    def test_address_clear_not_set(self, mock_load):
        """Returns 0 even if no address was set."""
        result = handle_default_address_clear()
        assert result == 0
