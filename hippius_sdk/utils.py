"""
Utility functions for the Hippius SDK.

This module provides common utility functions used across the SDK.
"""

import base64
import sys
from typing import Any, Optional, Tuple

# Import here to avoid circular imports when these functions are used from utils
from substrateinterface import SubstrateInterface

# Try importing PyNaCl for encryption functionality
try:
    import nacl.secret
    import nacl.utils

    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


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


def is_valid_cid(cid: str) -> bool:
    """
    Check if a string is likely a valid IPFS CID.

    Args:
        cid: String to check

    Returns:
        bool: True if it appears to be a valid CID
    """
    return (
        cid
        and isinstance(cid, str)
        and cid.startswith(("Qm", "bafy", "bafk", "bafyb", "bafzb", "b"))
    )


def normalize_hex_string(hex_string: str) -> str:
    """
    Normalize a hex string by removing '0x' prefix if present.

    Args:
        hex_string: Hex string to normalize

    Returns:
        str: Normalized hex string without '0x' prefix
    """
    if isinstance(hex_string, str) and hex_string.startswith("0x"):
        return hex_string[2:]
    return hex_string


def is_valid_hex(hex_string: str) -> bool:
    """
    Check if a string contains only valid hexadecimal characters.

    Args:
        hex_string: String to check

    Returns:
        bool: True if the string contains only valid hex characters
    """
    return all(c in "0123456789abcdefABCDEF" for c in hex_string)


def hex_to_ipfs_cid(hex_string: str) -> str:
    """
    Convert a hex-encoded IPFS CID to a regular IPFS CID.

    This function handles multiple formats:
    1. Proper CIDs directly (starting with Qm, bafy, etc.)
    2. Hex strings that, when decoded, represent ASCII CIDs
    3. Binary CIDv0 hex representations
    4. Other hex formats

    Args:
        hex_string: Hex string representation of an IPFS CID

    Returns:
        str: Regular IPFS CID
    """
    # If it's already a proper CID, return it directly
    if is_valid_cid(hex_string):
        return hex_string

    # Normalize by removing 0x prefix if present
    norm_hex = normalize_hex_string(hex_string)

    # If not valid hex after normalization, it might be a direct CID
    if not is_valid_hex(norm_hex):
        if is_valid_cid(norm_hex):
            return norm_hex
        # Return original if we can't process it
        return hex_string

    # First, try to decode as ASCII if it's a hex representation of ASCII characters
    try:
        bytes_data = bytes.fromhex(norm_hex)
        ascii_str = bytes_data.decode("ascii")

        # If the decoded string starts with a valid CID prefix, return it
        if is_valid_cid(ascii_str):
            return ascii_str
    except Exception:
        # If ASCII decoding fails, continue with other methods
        pass

    # Try to decode as a binary CID
    try:
        import base58

        binary_data = bytes.fromhex(norm_hex)

        # Check if it matches CIDv0 pattern (starts with 0x12, 0x20)
        if len(binary_data) > 2 and binary_data[0] == 0x12 and binary_data[1] == 0x20:
            # CIDv0 (Qm...)
            return base58.b58encode(binary_data).decode("utf-8")

        # If it doesn't match CIDv0, for CIDv1 just return the hex without 0x prefix
        return norm_hex
    except ImportError:
        # If base58 is not available
        print("Warning: base58 module not available for proper CID conversion")
        return norm_hex
    except Exception as e:
        print(f"Error converting hex to CID: {e}")
        return hex_string


def format_cid(cid: str) -> str:
    """
    Format a CID for display.

    This is a wrapper around hex_to_ipfs_cid for backward compatibility.

    Args:
        cid: Content Identifier (CID) to format

    Returns:
        str: Formatted CID string
    """
    return hex_to_ipfs_cid(cid)


def generate_key() -> str:
    """
    Generate a random encryption key for NaCl secretbox.

    Returns:
        str: A base64-encoded encryption key that can be used with the SDK's
             encryption functions or stored in configuration.

    Raises:
        SystemExit: If PyNaCl is not installed
    """
    if not ENCRYPTION_AVAILABLE:
        print(
            "Error: PyNaCl is required for encryption. Install it with: pip install pynacl"
        )
        sys.exit(1)

    # Generate a random key
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # Encode to base64 for storage and configuration
    encoded_key = base64.b64encode(key).decode()

    return encoded_key


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
