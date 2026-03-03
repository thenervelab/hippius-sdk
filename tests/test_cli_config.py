"""
Unit tests for CLI config handlers.
"""

from unittest.mock import patch

import pytest

from hippius_sdk.cli_handlers import (
    handle_config_get,
    handle_config_list,
    handle_config_reset,
    handle_config_set,
)


class TestConfigGet:
    @patch("hippius_sdk.cli_handlers_config.get_config_value", return_value="some_value")
    def test_config_get_success(self, mock_get):
        result = handle_config_get("arion", "base_url")
        assert result == 0
        mock_get.assert_called_once_with("arion", "base_url")


class TestConfigSet:
    @patch("hippius_sdk.cli_handlers_config.set_config_value")
    def test_config_set_success(self, mock_set):
        result = handle_config_set("arion", "base_url", "https://arion.hippius.com")
        assert result == 0
        mock_set.assert_called_once_with("arion", "base_url", "https://arion.hippius.com")

    @patch("hippius_sdk.cli_handlers_config.set_config_value")
    def test_config_set_boolean_true(self, mock_set):
        result = handle_config_set("cli", "verbose", "true")
        assert result == 0
        mock_set.assert_called_once_with("cli", "verbose", True)

    @patch("hippius_sdk.cli_handlers_config.set_config_value")
    def test_config_set_boolean_false(self, mock_set):
        result = handle_config_set("cli", "verbose", "false")
        assert result == 0
        mock_set.assert_called_once_with("cli", "verbose", False)


class TestConfigList:
    @patch(
        "hippius_sdk.cli_handlers_config.get_all_config",
        return_value={
            "arion": {"base_url": "https://arion.hippius.com"},
            "accounts": {"active_account": "test"},
        },
    )
    def test_config_list_success(self, mock_get_all):
        result = handle_config_list()
        assert result == 0
        mock_get_all.assert_called_once()


class TestConfigReset:
    @patch("hippius_sdk.cli_handlers_config.reset_config")
    def test_config_reset_success(self, mock_reset):
        result = handle_config_reset()
        assert result == 0
        mock_reset.assert_called_once()
