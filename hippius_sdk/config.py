"""
Configuration management for Hippius SDK.

This module handles loading and saving configuration from the user's home directory,
specifically in ~/.hippius/config.
"""

import json
import os
from typing import Any, Dict


# Define constants
CONFIG_DIR = os.path.expanduser("~/.hippius")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "arion": {
        "base_url": "https://arion.hippius.com",
        "api_url": "https://api.hippius.com/api",
        "hcfs_api_key": "SERVER",
    },
    "accounts": {
        "active_account": None,
        "accounts": {},
    },
    "substrate": {
        "url": "wss://rpc.hippius.network",
    },
    "cli": {
        "verbose": False,
        "max_retries": 3,
        "log_level": "warning",
    },
}


def ensure_config_dir() -> None:
    """Create configuration directory if it doesn't exist."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create configuration directory: {e}")


def _migrate_old_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect old config format (has 'ipfs' key) and migrate to new format.

    Preserves accounts and substrate settings where possible.
    """
    if "ipfs" not in config and "hippius" not in config:
        return config

    print("\nWARNING: Old configuration format detected.")
    print("Migrating to new Arion-based configuration...")
    print("You will need to re-login with: hippius account login\n")

    new_config = DEFAULT_CONFIG.copy()
    new_config["arion"] = dict(DEFAULT_CONFIG["arion"])
    new_config["accounts"] = {"active_account": None, "accounts": {}}
    new_config["substrate"] = dict(DEFAULT_CONFIG["substrate"])
    new_config["cli"] = dict(DEFAULT_CONFIG["cli"])

    # Preserve substrate URL if set
    if "substrate" in config and "url" in config["substrate"]:
        new_config["substrate"]["url"] = config["substrate"]["url"]

    # Migrate accounts from old format - preserve seed phrases for miner commands
    old_accounts = config.get("substrate", {}).get("accounts", {})
    old_active = config.get("substrate", {}).get("active_account")

    for name, data in old_accounts.items():
        migrated = {}
        # Preserve seed phrase data for miner operations
        if "seed_phrase" in data:
            migrated["seed_phrase"] = data["seed_phrase"]
            migrated["seed_phrase_encoded"] = data.get("seed_phrase_encoded", False)
            migrated["seed_phrase_salt"] = data.get("seed_phrase_salt")
        if "ss58_address" in data:
            migrated["account_address"] = data["ss58_address"]
        if migrated:
            new_config["accounts"]["accounts"][name] = migrated

    if old_active and old_active in new_config["accounts"]["accounts"]:
        new_config["accounts"]["active_account"] = old_active

    # Preserve CLI settings
    if "cli" in config:
        new_config["cli"].update(config["cli"])

    return new_config


def load_config() -> Dict[str, Any]:
    """
    Load configuration from the config file.

    If the file doesn't exist, create it with default values.
    If old format is detected, migrate to new format.

    Returns:
        Dict[str, Any]: The configuration dictionary
    """
    ensure_config_dir()

    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        # Migrate old config format if detected
        if "ipfs" in config or "hippius" in config:
            config = _migrate_old_config(config)
            save_config(config)

        # Ensure all config sections exist (for backward compatibility)
        for section, defaults in DEFAULT_CONFIG.items():
            if section not in config:
                config[section] = defaults

        return config
    except Exception as e:
        print(f"Warning: Could not load configuration file: {e}")
        print("Using default configuration")
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    """
    Save configuration to the config file.

    Args:
        config: The configuration dictionary to save

    Returns:
        bool: True if save was successful, False otherwise
    """
    ensure_config_dir()

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Warning: Could not save configuration file: {e}")
        return False


def get_config_value(section: str, key: str, default: Any = None) -> Any:
    """
    Get a configuration value from a specific section.

    Args:
        section: The configuration section
        key: The configuration key
        default: Default value if not found

    Returns:
        Any: The configuration value or default
    """
    config = load_config()
    return config.get(section, {}).get(key, default)


def set_config_value(section: str, key: str, value: Any) -> bool:
    """
    Set a configuration value in a specific section.

    Args:
        section: The configuration section
        key: The configuration key
        value: The value to set

    Returns:
        bool: True if save was successful, False otherwise
    """
    config = load_config()

    if section not in config:
        config[section] = {}

    config[section][key] = value
    return save_config(config)


def get_all_config() -> Dict[str, Any]:
    """
    Get the complete configuration.

    Returns:
        Dict[str, Any]: The full configuration dictionary
    """
    return load_config()


def reset_config() -> bool:
    """
    Reset configuration to default values.

    Returns:
        bool: True if reset was successful, False otherwise
    """
    return save_config(DEFAULT_CONFIG.copy())
