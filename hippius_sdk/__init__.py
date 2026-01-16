"""
Hippius SDK - Python interface for Hippius blockchain storage
"""

from hippius_sdk.client import HippiusClient
from hippius_sdk.config import (
    decrypt_hippius_key,
    delete_account,
    encrypt_hippius_key,
    encrypt_seed_phrase,
    get_account_address,
    get_active_account,
    get_all_config,
    get_config_value,
    get_encryption_key,
    get_hippius_key,
    get_seed_phrase,
    initialize_from_env,
    list_accounts,
    load_config,
    reset_config,
    save_config,
    set_active_account,
    set_config_value,
    set_encryption_key,
    set_hippius_key,
    set_seed_phrase,
)
from hippius_sdk.ipfs import IPFSClient
from hippius_sdk.utils import format_cid, format_size, hex_to_ipfs_cid

__version__ = "0.2.74"
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
    "get_hippius_key",
    "set_hippius_key",
    "encrypt_hippius_key",
    "decrypt_hippius_key",
    "get_active_account",
    "set_active_account",
    "list_accounts",
    "delete_account",
    "get_account_address",
    "get_seed_phrase",
    "set_seed_phrase",
    "encrypt_seed_phrase",
    "format_cid",
    "format_size",
    "hex_to_ipfs_cid",
]

# Initialize configuration from environment variables for backward compatibility
initialize_from_env()

# Note: Substrate functionality will be added in a future release
