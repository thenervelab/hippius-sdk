"""
Hippius SDK - Python interface for Hippius blockchain storage
"""

from hippius_sdk.client import HippiusClient
from hippius_sdk.ipfs import IPFSClient
from hippius_sdk.config import (
    get_config_value,
    set_config_value,
    get_encryption_key,
    set_encryption_key,
    load_config,
    save_config,
    initialize_from_env,
    get_all_config,
    reset_config,
    get_seed_phrase,
    set_seed_phrase,
    encrypt_seed_phrase,
    decrypt_seed_phrase,
    get_active_account,
    set_active_account,
    list_accounts,
    delete_account,
    get_account_address,
)

__version__ = "0.1.0"
__all__ = [
    "HippiusClient",
    "IPFSClient",
    "get_config_value",
    "set_config_value",
    "get_encryption_key",
    "set_encryption_key",
    "load_config",
    "save_config",
    "initialize_from_env",
    "get_all_config",
    "reset_config",
    "get_seed_phrase",
    "set_seed_phrase",
    "encrypt_seed_phrase",
    "decrypt_seed_phrase",
    "get_active_account",
    "set_active_account",
    "list_accounts",
    "delete_account",
    "get_account_address",
]

# Initialize configuration from environment variables for backward compatibility
initialize_from_env()

# Note: Substrate functionality will be added in a future release
