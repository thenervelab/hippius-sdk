"""
Utility functions for the Hippius SDK.

This module provides common utility functions used across the SDK.
"""

from typing import Any, Optional, Tuple

# Import here to avoid circular imports when these functions are used from utils
from substrateinterface import SubstrateInterface


def format_size(size_bytes: int) -> str:
    """
    Format a size in bytes to a human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        str: Human-readable size string (e.g., '1.23 MB', '456.78 KB')
    """
    if size_bytes >= 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    elif size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes} bytes"


def initialize_substrate_connection(
    self_obj: Any,
    seed_phrase: Optional[str] = None,
) -> Tuple[SubstrateInterface, Optional[str]]:
    """
    Initialize a Substrate connection if not already connected and set up the account.
    This function handles initializing the substrate connection and determining the account address
    to use in blockchain operations.

    Args:
        self_obj: The object (usually SubstrateClient instance) with required attributes
        seed_phrase: Optional seed phrase to use for the connection

    Returns:
        Tuple[SubstrateInterface, Optional[str]]: A tuple containing the Substrate interface
        object and the account address (or None if no address is available)
    """
    # Initialize Substrate connection if not already connected
    if not hasattr(self_obj, "_substrate") or self_obj._substrate is None:
        print("Initializing Substrate connection...")
        self_obj._substrate = SubstrateInterface(
            url=self_obj.url,
            ss58_format=42,  # Substrate default
            type_registry_preset="substrate-node-template",
        )
        print(f"Connected to Substrate node at {self_obj.url}")

    # Use provided account address or create keypair from seed_phrase
    account_address = None

    if hasattr(self_obj, "_ensure_keypair") and callable(self_obj._ensure_keypair):
        # Try to get the address from the keypair (using seed_phrase if provided)
        if not self_obj._ensure_keypair(seed_phrase):
            # If we have an account address already, use that
            if hasattr(self_obj, "_account_address") and self_obj._account_address:
                account_address = self_obj._account_address
            else:
                # No keypair or address available
                return self_obj._substrate, None

        if hasattr(self_obj, "_keypair") and self_obj._keypair:
            account_address = self_obj._keypair.ss58_address
            print(f"Using keypair address: {account_address}")
    elif hasattr(self_obj, "_account_address") and self_obj._account_address:
        account_address = self_obj._account_address

    return self_obj._substrate, account_address
