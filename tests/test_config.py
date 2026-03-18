"""
Unit tests for hippius_sdk.config — get/set, encrypt/decrypt roundtrip.
"""

import json
import os
import tempfile
from unittest.mock import patch

import pytest

from hippius_sdk.accounts import encrypt_api_token
from hippius_sdk.config import (
    DEFAULT_CONFIG,
    _migrate_old_config,
    get_config_value,
    load_config,
    save_config,
    set_config_value,
)


@pytest.fixture
def temp_config_dir(tmp_path):
    """Redirect config to a temp directory."""
    config_file = tmp_path / "config.json"
    with patch("hippius_sdk.config.CONFIG_DIR", str(tmp_path)), patch(
        "hippius_sdk.config.CONFIG_FILE", str(config_file)
    ):
        yield tmp_path, config_file


class TestLoadSaveConfig:
    def test_load_default_when_missing(self, temp_config_dir):
        """Returns DEFAULT_CONFIG when no file exists."""
        config = load_config()
        assert "arion" in config
        assert "accounts" in config

    def test_save_and_reload(self, temp_config_dir):
        """save_config persists, load_config reads it back."""
        _, config_file = temp_config_dir
        config = load_config()
        config["cli"]["verbose"] = True
        save_config(config)

        assert config_file.exists()
        reloaded = load_config()
        assert reloaded["cli"]["verbose"] is True


class TestGetSetConfigValue:
    def test_get_existing_value(self, temp_config_dir):
        """get_config_value returns existing value."""
        val = get_config_value("arion", "base_url")
        assert val == "https://arion.hippius.com"

    def test_get_missing_returns_default(self, temp_config_dir):
        """get_config_value returns default for missing key."""
        val = get_config_value("nonexistent", "key", default="fallback")
        assert val == "fallback"

    def test_set_then_get(self, temp_config_dir):
        """set_config_value persists and get_config_value retrieves."""
        set_config_value("cli", "custom_key", "custom_value")
        val = get_config_value("cli", "custom_key")
        assert val == "custom_value"


class TestMigrateOldConfig:
    def test_no_migration_needed(self):
        """Config without 'ipfs' key passes through unchanged."""
        config = {"arion": {"base_url": "https://arion.hippius.com"}}
        result = _migrate_old_config(config)
        assert result is config

    def test_ipfs_config_migrated(self):
        """Config with 'ipfs' key gets migrated to new format."""
        old_config = {
            "ipfs": {"gateway_url": "https://old-gateway.com"},
            "substrate": {
                "url": "wss://custom.rpc",
                "active_account": "alice",
                "accounts": {
                    "alice": {
                        "seed_phrase": "word1 word2 word3",
                        "ss58_address": "5Alice",
                    }
                },
            },
        }
        result = _migrate_old_config(old_config)
        assert "ipfs" not in result
        assert result["substrate"]["url"] == "wss://custom.rpc"
        assert "alice" in result["accounts"]["accounts"]
        assert result["accounts"]["accounts"]["alice"]["account_address"] == "5Alice"


class TestEncryptDecryptRoundtrip:
    def test_encrypt_api_token_roundtrip(self, temp_config_dir):
        """Encrypt then decrypt returns the original token."""
        from hippius_sdk.accounts import decrypt_api_token

        # Create an account first
        config = load_config()
        config["accounts"]["accounts"]["test_enc"] = {
            "api_token": "my-secret-token",
            "api_token_encoded": False,
            "api_token_salt": None,
            "account_address": "5TestAddr",
        }
        config["accounts"]["active_account"] = "test_enc"
        save_config(config)

        # Encrypt
        encrypt_api_token("my-secret-token", "password123", "test_enc")

        # Verify it's encrypted
        config = load_config()
        account = config["accounts"]["accounts"]["test_enc"]
        assert account["api_token_encoded"] is True
        assert account["api_token"] != "my-secret-token"

        # Decrypt
        decrypted = decrypt_api_token("password123", "test_enc")
        assert decrypted == "my-secret-token"
