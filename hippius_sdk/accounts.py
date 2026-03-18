"""
Account management for the Hippius SDK.

Provides CRUD operations for user accounts, API token management,
seed phrase storage, and encryption of credentials.
"""

import getpass
from typing import Any, Dict, Optional

from substrateinterface import Keypair

from hippius_sdk.config import load_config, save_config, get_config_value
from hippius_sdk.crypto import decrypt_with_password, encrypt_with_password


def _resolve_account(account_name: Optional[str] = None):
    """Resolve account name, load config, and return (config, name, account_data) or None on error."""
    config = load_config()
    name_to_use = account_name or config["accounts"].get("active_account")
    if not name_to_use:
        print("Error: No account specified and no active account")
        return None
    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None
    return config, name_to_use, config["accounts"]["accounts"][name_to_use]


def _ensure_account_structure(config, account_name):
    """Ensure accounts dict exists and account entry is present. Returns the account dict."""
    if "accounts" not in config["accounts"]:
        config["accounts"]["accounts"] = {}
    if account_name not in config["accounts"]["accounts"]:
        config["accounts"]["accounts"][account_name] = {}
    return config["accounts"]["accounts"][account_name]


def get_active_account() -> Optional[str]:
    """
    Get the name of the currently active account.

    Returns:
        Optional[str]: The name of the active account, or None if not set
    """
    return get_config_value("accounts", "active_account")


def set_active_account(account_name: str) -> bool:
    """
    Set the active account by name.

    Args:
        account_name: Name of the account to set as active

    Returns:
        bool: True if successful, False otherwise
    """
    config = load_config()

    # Check if the account exists
    if account_name not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{account_name}' not found")
        return False

    # Set as active account
    config["accounts"]["active_account"] = account_name
    return save_config(config)


def list_accounts() -> Dict[str, Dict[str, Any]]:
    """
    Get a list of all stored accounts.

    Returns:
        Dict[str, Dict[str, Any]]: Dictionary of account names to account data
    """
    config = load_config()
    accounts = config["accounts"].get("accounts", {})

    # Mark the active account
    active_account = config["accounts"].get("active_account")
    if active_account and active_account in accounts:
        accounts[active_account]["is_active"] = True

    return accounts


def delete_account(account_name: str) -> bool:
    """
    Delete an account by name.

    Args:
        account_name: Name of the account to delete

    Returns:
        bool: True if successful, False otherwise
    """
    config = load_config()

    # Check if the account exists
    if account_name not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{account_name}' not found")
        return False

    # Delete the account
    del config["accounts"]["accounts"][account_name]

    # Update active account if needed
    if config["accounts"].get("active_account") == account_name:
        if config["accounts"]["accounts"]:
            # Set the first remaining account as active
            config["accounts"]["active_account"] = next(
                iter(config["accounts"]["accounts"])
            )
        else:
            # No more accounts
            config["accounts"]["active_account"] = None

    return save_config(config)


def get_account_address(account_name: Optional[str] = None) -> Optional[str]:
    """
    Get the account address for an account.

    Args:
        account_name: Optional name of the account (if None, uses active account)

    Returns:
        Optional[str]: The account address, or None if not available
    """
    resolved = _resolve_account(account_name)
    if not resolved:
        return None
    _, _, account_data = resolved
    return account_data.get("account_address")


def encrypt_api_token(
    api_token: str, password: Optional[str] = None, account_name: Optional[str] = None
) -> bool:
    """
    Encrypt the API token using password-based encryption.

    Args:
        api_token: The plain text API token to encrypt
        password: Optional password (if None, will prompt)
        account_name: Optional name for the account (if None, uses active account)

    Returns:
        bool: True if encryption and saving was successful, False otherwise
    """
    # Get password from user if not provided
    if password is None:
        password = getpass.getpass("Enter password to encrypt API token: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            raise ValueError("Passwords do not match")

    # Encrypt the API token
    encrypted_data, salt = encrypt_with_password(api_token, password)

    config = load_config()
    name_to_use = account_name or config["accounts"].get("active_account")
    if not name_to_use:
        print("Error: No account name specified and no active account")
        return False

    account = _ensure_account_structure(config, name_to_use)
    account["api_token"] = encrypted_data
    account["api_token_encoded"] = True
    account["api_token_salt"] = salt

    # Set as active account if no active account exists
    if not config["accounts"].get("active_account"):
        config["accounts"]["active_account"] = name_to_use

    return save_config(config)


def decrypt_api_token(
    password: Optional[str] = None, account_name: Optional[str] = None
) -> Optional[str]:
    """
    Decrypt the API token using password-based decryption.

    Args:
        password: Optional password (if None, will prompt; if empty string, will skip password for read-only operations)
        account_name: Optional account name (if None, uses active account)

    Returns:
        Optional[str]: The decrypted API token, or None if decryption failed
    """
    resolved = _resolve_account(account_name)
    if not resolved:
        return None
    _, _, account_data = resolved
    is_encoded = account_data.get("api_token_encoded", False)

    if not is_encoded:
        return account_data.get("api_token")

    encrypted_data = account_data.get("api_token")
    salt = account_data.get("api_token_salt")

    if not encrypted_data or not salt:
        print("Error: No encrypted API token found or missing salt")
        return None

    # Check if we're in skip-password mode (empty string)
    # This is used for read-only operations that don't need the key
    if password == "":
        return None

    # Get password from user if not provided
    if password is None:
        password = getpass.getpass("Enter password to decrypt API token: \n\n")

    # Decrypt the API token
    return decrypt_with_password(encrypted_data, salt, password)


def get_api_token(
    password: Optional[str] = None, account_name: Optional[str] = None
) -> Optional[str]:
    """
    Get the API token from configuration, decrypting if necessary.

    Args:
        password: Optional password for decryption (if None and needed, will prompt;
                if empty string, will skip decryption for read-only operations)
        account_name: Optional account name (if None, uses active account)

    Returns:
        Optional[str]: The API token, or None if not available
    """
    resolved = _resolve_account(account_name)
    if not resolved:
        return None
    _, name_to_use, account_data = resolved
    is_encoded = account_data.get("api_token_encoded", False)

    # If password is an empty string, this indicates we're doing a read-only operation
    # that doesn't require the API token, so we can return None
    if password == "" and is_encoded:
        return None

    if is_encoded:
        return decrypt_api_token(password, name_to_use)
    else:
        return account_data.get("api_token")


def set_api_token(
    api_token: str,
    encode: bool = False,
    password: Optional[str] = None,
    account_name: Optional[str] = None,
) -> bool:
    """
    Set the API token in configuration, with optional encryption.

    Args:
        api_token: The API token to store
        encode: Whether to encrypt the API token (requires password)
        password: Optional password for encryption (if None and encode=True, will prompt)
        account_name: Optional name for the account (if None, uses active account)

    Returns:
        bool: True if saving was successful, False otherwise
    """
    if encode:
        return encrypt_api_token(api_token, password, account_name)

    config = load_config()
    name_to_use = account_name or config["accounts"].get("active_account")
    if not name_to_use:
        print("Error: No account name specified and no active account")
        return False

    account = _ensure_account_structure(config, name_to_use)
    account["api_token"] = api_token
    account["api_token_encoded"] = False
    account["api_token_salt"] = None

    # Set as active account if no active account exists
    if not config["accounts"].get("active_account"):
        config["accounts"]["active_account"] = name_to_use

    return save_config(config)


def set_seed_phrase(
    seed_phrase: str,
    encode: bool = False,
    password: Optional[str] = None,
    account_name: Optional[str] = None,
) -> bool:
    """
    Set the substrate seed phrase in configuration, with optional encryption.

    Args:
        seed_phrase: The seed phrase to store
        encode: Whether to encrypt the seed phrase (requires password)
        password: Optional password for encryption (if None and encode=True, will prompt)
        account_name: Optional name for the account (if None, uses active account)

    Returns:
        bool: True if saving was successful, False otherwise
    """
    if encode:
        return encrypt_seed_phrase(seed_phrase, password, account_name)

    config = load_config()

    # Get the SS58 address from the seed phrase
    keypair = Keypair.create_from_mnemonic(seed_phrase)
    ss58_address = keypair.ss58_address

    name_to_use = account_name or config["accounts"].get("active_account")
    if not name_to_use:
        print("Error: No account name specified and no active account")
        return False

    account = _ensure_account_structure(config, name_to_use)
    account["seed_phrase"] = seed_phrase
    account["seed_phrase_encoded"] = False
    account["seed_phrase_salt"] = None
    account["account_address"] = ss58_address

    # Set as active account if no active account exists
    if not config["accounts"].get("active_account"):
        config["accounts"]["active_account"] = name_to_use

    return save_config(config)


def encrypt_seed_phrase(
    seed_phrase: str, password: Optional[str] = None, account_name: Optional[str] = None
) -> bool:
    """
    Encrypt the substrate seed phrase using password-based encryption.

    Args:
        seed_phrase: The plain text seed phrase to encrypt
        password: Optional password (if None, will prompt)
        account_name: Optional name for the account (if None, uses active account)

    Returns:
        bool: True if encryption and saving was successful, False otherwise
    """
    # Get password from user if not provided
    if password is None:
        password = getpass.getpass("Enter password to encrypt seed phrase: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            raise ValueError("Passwords do not match")

    # Encrypt the seed phrase
    encrypted_data, salt = encrypt_with_password(seed_phrase, password)

    # Get the SS58 address from the seed phrase
    keypair = Keypair.create_from_mnemonic(seed_phrase)
    ss58_address = keypair.ss58_address

    config = load_config()
    name_to_use = account_name or config["accounts"].get("active_account")
    if not name_to_use:
        print("Error: No account name specified and no active account")
        return False

    account = _ensure_account_structure(config, name_to_use)
    account["seed_phrase"] = encrypted_data
    account["seed_phrase_encoded"] = True
    account["seed_phrase_salt"] = salt
    account["account_address"] = ss58_address

    # Set as active account if no active account exists
    if not config["accounts"].get("active_account"):
        config["accounts"]["active_account"] = name_to_use

    return save_config(config)


def decrypt_seed_phrase(
    password: Optional[str] = None, account_name: Optional[str] = None
) -> Optional[str]:
    """
    Decrypt the substrate seed phrase using password-based decryption.

    Args:
        password: Optional password (if None, will prompt; if empty string, will skip password for read-only operations)
        account_name: Optional account name (if None, uses active account)

    Returns:
        Optional[str]: The decrypted seed phrase, or None if decryption failed
    """
    resolved = _resolve_account(account_name)
    if not resolved:
        return None
    _, _, account_data = resolved
    is_encoded = account_data.get("seed_phrase_encoded", False)

    if not is_encoded:
        return account_data.get("seed_phrase")

    encrypted_data = account_data.get("seed_phrase")
    salt = account_data.get("seed_phrase_salt")

    if not encrypted_data or not salt:
        print("Error: No encrypted seed phrase found or missing salt")
        return None

    # Check if we're in skip-password mode (empty string)
    # This is used for read-only operations that don't need blockchain interaction
    if password == "":
        # Don't print a message as it's confusing to the user
        return None

    # Get password from user if not provided
    if password is None:
        password = getpass.getpass("Enter password to decrypt seed phrase: \n\n")

    # Decrypt the seed phrase
    return decrypt_with_password(encrypted_data, salt, password)


def get_seed_phrase(
    password: Optional[str] = None, account_name: Optional[str] = None
) -> Optional[str]:
    """
    Get the substrate seed phrase from configuration, decrypting if necessary.

    Args:
        password: Optional password for decryption (if None and needed, will prompt;
                if empty string, will skip decryption for read-only operations)
        account_name: Optional account name (if None, uses active account)

    Returns:
        Optional[str]: The seed phrase, or None if not available
    """
    resolved = _resolve_account(account_name)
    if not resolved:
        return None
    _, name_to_use, account_data = resolved
    is_encoded = account_data.get("seed_phrase_encoded", False)

    # If password is an empty string, this indicates we're doing a read-only operation
    # that doesn't require the seed phrase, so we can return None
    if password == "" and is_encoded:
        return None

    if is_encoded:
        return decrypt_seed_phrase(password, name_to_use)
    else:
        return account_data.get("seed_phrase")
