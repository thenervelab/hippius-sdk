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
    @patch("hippius_sdk.cli_handlers.get_config_value", return_value="some_value")
    def test_config_get_success(self, mock_get):
        result = handle_config_get("ipfs", "gateway")
        assert result == 0
        mock_get.assert_called_once_with("ipfs", "gateway")

    @patch(
        "hippius_sdk.cli_handlers.get_config_value",
        side_effect=KeyError("key not found"),
    )
    def test_config_get_error(self, mock_get):
        result = handle_config_get("ipfs", "nonexistent")
        assert result == 1


class TestConfigSet:
    @patch("hippius_sdk.cli_handlers.set_config_value")
    def test_config_set_success(self, mock_set):
        result = handle_config_set("ipfs", "gateway", "http://localhost:5001")
        assert result == 0
        mock_set.assert_called_once_with("ipfs", "gateway", "http://localhost:5001")

    @patch("hippius_sdk.cli_handlers.set_config_value")
    def test_config_set_boolean_true(self, mock_set):
        result = handle_config_set("encryption", "enabled", "true")
        assert result == 0
        mock_set.assert_called_once_with("encryption", "enabled", True)

    @patch("hippius_sdk.cli_handlers.set_config_value")
    def test_config_set_boolean_false(self, mock_set):
        result = handle_config_set("encryption", "enabled", "false")
        assert result == 0
        mock_set.assert_called_once_with("encryption", "enabled", False)


class TestConfigList:
    @patch(
        "hippius_sdk.cli_handlers.get_all_config",
        return_value={
            "ipfs": {"gateway": "http://localhost:5001"},
            "substrate": {"active_account": "test"},
        },
    )
    def test_config_list_success(self, mock_get_all):
        result = handle_config_list()
        assert result == 0
        mock_get_all.assert_called_once()

    @patch(
        "hippius_sdk.cli_handlers.get_all_config",
        side_effect=Exception("read error"),
    )
    def test_config_list_error(self, mock_get_all):
        result = handle_config_list()
        assert result == 1


class TestConfigReset:
    @patch("hippius_sdk.cli_handlers.reset_config")
    def test_config_reset_success(self, mock_reset):
        result = handle_config_reset()
        assert result == 0
        mock_reset.assert_called_once()

    @patch(
        "hippius_sdk.cli_handlers.reset_config",
        side_effect=Exception("reset error"),
    )
    def test_config_reset_error(self, mock_reset):
        result = handle_config_reset()
        assert result == 1
