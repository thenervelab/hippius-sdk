"""
Configuration management for Hippius SDK.

This module handles loading and saving configuration from the user's home directory,
specifically in ~/.hippius/config.
"""

import base64
import getpass
import json
import os
from typing import Any, Dict, Optional, Tuple, Union

import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from substrateinterface import Keypair

# Define constants
CONFIG_DIR = os.path.expanduser("~/.hippius")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "arion": {
        "base_url": "https://arion.hippius.com",
        "api_url": "https://api.hippius.com/api",
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
    },
}


def ensure_config_dir() -> None:
    """Create configuration directory if it doesn't exist."""
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            print(f"Created Hippius configuration directory: {CONFIG_DIR}")
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


def _derive_key_from_password(
    password: str, salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Derive an encryption key from a password using PBKDF2.

    Args:
        password: The user password
        salt: Optional salt bytes. If None, a new random salt is generated

    Returns:
        Tuple[bytes, bytes]: (derived_key, salt)
    """
    try:
        # Verify PBKDF2HMAC is already imported at the top
        if not PBKDF2HMAC:
            raise ImportError("PBKDF2HMAC not available")
    except ImportError:
        raise ImportError(
            "cryptography is required for password-based encryption. Install it with: pip install cryptography"
        )

    # Generate a salt if not provided
    if salt is None:
        salt = os.urandom(16)

    # Create a PBKDF2HMAC instance
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes (256 bits) key
        salt=salt,
        iterations=100000,  # Recommended minimum by NIST
    )

    # Derive the key
    key = kdf.derive(password.encode("utf-8"))

    return key, salt


def encrypt_with_password(data: str, password: str) -> Tuple[str, str]:
    """
    Encrypt data using a password-derived key.

    Args:
        data: String data to encrypt
        password: User password

    Returns:
        Tuple[str, str]: (base64_encrypted_data, base64_salt)
    """
    try:
        # Derive key from password with a new salt
        key, salt = _derive_key_from_password(password)

        # Verify NaCl is available (imported at the top)
        try:
            if not hasattr(nacl, "secret") or not hasattr(nacl, "utils"):
                raise ImportError("NaCl modules not available")
        except ImportError:
            raise ValueError(
                "PyNaCl is required for encryption. Install it with: pip install pynacl"
            )

        # Create a SecretBox with our derived key
        box = nacl.secret.SecretBox(key)

        # Encrypt the data
        encrypted_data = box.encrypt(data.encode("utf-8"))

        # Convert to base64 for storage
        encoded_data = base64.b64encode(encrypted_data).decode("utf-8")
        encoded_salt = base64.b64encode(salt).decode("utf-8")

        return encoded_data, encoded_salt

    except Exception as e:
        raise ValueError(f"Error encrypting data with password: {e}")


def decrypt_with_password(encrypted_data: str, salt: str, password: str) -> str:
    """
    Decrypt data using a password-derived key.

    Args:
        encrypted_data: Base64-encoded encrypted data
        salt: Base64-encoded salt
        password: User password

    Returns:
        str: Decrypted data
    """
    # Decode the encrypted data and salt
    encrypted_bytes = base64.b64decode(encrypted_data)
    salt_bytes = base64.b64decode(salt)

    # Derive the key from the password and salt
    key, _ = _derive_key_from_password(password, salt_bytes)

    # Verify NaCl is available (imported at the top)
    try:
        if not hasattr(nacl, "secret") or not hasattr(nacl, "utils"):
            raise ImportError("NaCl modules not available")
    except ImportError:
        raise ValueError(
            "PyNaCl is required for decryption. Install it with: pip install pynacl"
        )

    # Create a SecretBox with our derived key
    box = nacl.secret.SecretBox(key)

    # Decrypt the data
    decrypted_data = box.decrypt(encrypted_bytes)

    # Return the decrypted string
    return decrypted_data.decode("utf-8")


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

    # Use active account if no account specified
    name_to_use = account_name
    if name_to_use is None:
        name_to_use = config["accounts"].get("active_account")
        if not name_to_use:
            print("Error: No account name specified and no active account")
            return False

    # Ensure accounts structure exists
    if "accounts" not in config["accounts"]:
        config["accounts"]["accounts"] = {}

    # Get or create account data
    if name_to_use not in config["accounts"]["accounts"]:
        config["accounts"]["accounts"][name_to_use] = {}

    # Store the API token data
    config["accounts"]["accounts"][name_to_use]["api_token"] = encrypted_data
    config["accounts"]["accounts"][name_to_use]["api_token_encoded"] = True
    config["accounts"]["accounts"][name_to_use]["api_token_salt"] = salt

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
    config = load_config()

    name_to_use = account_name or config["accounts"].get("active_account")

    if not name_to_use:
        print("Error: No account specified and no active account")
        return None

    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None

    account_data = config["accounts"]["accounts"][name_to_use]
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
    config = load_config()

    name_to_use = account_name or config["accounts"].get("active_account")

    if not name_to_use:
        print("Error: No account specified and no active account")
        return None

    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None

    account_data = config["accounts"]["accounts"][name_to_use]
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
    else:
        config = load_config()

        # Use active account if no account specified
        name_to_use = account_name
        if name_to_use is None:
            name_to_use = config["accounts"].get("active_account")
            if not name_to_use:
                print("Error: No account name specified and no active account")
                return False

        # Ensure accounts structure exists
        if "accounts" not in config["accounts"]:
            config["accounts"]["accounts"] = {}

        # Get or create account data
        if name_to_use not in config["accounts"]["accounts"]:
            config["accounts"]["accounts"][name_to_use] = {}

        # Store the API token data
        config["accounts"]["accounts"][name_to_use]["api_token"] = api_token
        config["accounts"]["accounts"][name_to_use]["api_token_encoded"] = False
        config["accounts"]["accounts"][name_to_use]["api_token_salt"] = None

        # Set as active account if no active account exists
        if not config["accounts"].get("active_account"):
            config["accounts"]["active_account"] = name_to_use

        return save_config(config)


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
    config = load_config()

    name_to_use = account_name or config["accounts"].get("active_account")

    if not name_to_use:
        print("Error: No account specified and no active account")
        return None

    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None

    return config["accounts"]["accounts"][name_to_use].get("account_address")


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
    else:
        config = load_config()

        # Get the SS58 address from the seed phrase
        ss58_address = None
        try:
            keypair = Keypair.create_from_mnemonic(seed_phrase)
            ss58_address = keypair.ss58_address
        except Exception as e:
            print(f"Warning: Could not derive SS58 address: {e}")

        # Use active account if no account specified
        name_to_use = account_name
        if name_to_use is None:
            name_to_use = config["accounts"].get("active_account")
            if not name_to_use:
                print("Error: No account name specified and no active account")
                return False

        # Ensure accounts structure exists
        if "accounts" not in config["accounts"]:
            config["accounts"]["accounts"] = {}

        # Get or create account data
        if name_to_use not in config["accounts"]["accounts"]:
            config["accounts"]["accounts"][name_to_use] = {}

        # Store the account data
        account = config["accounts"]["accounts"][name_to_use]
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
    try:
        # Get password from user if not provided
        if password is None:
            password = getpass.getpass("Enter password to encrypt seed phrase: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                raise ValueError("Passwords do not match")

        # Encrypt the seed phrase
        encrypted_data, salt = encrypt_with_password(seed_phrase, password)

        # Get the SS58 address from the seed phrase
        ss58_address = None
        try:
            keypair = Keypair.create_from_mnemonic(seed_phrase)
            ss58_address = keypair.ss58_address
        except Exception as e:
            print(f"Warning: Could not derive SS58 address: {e}")

        config = load_config()

        # Use active account if no account specified
        name_to_use = account_name
        if name_to_use is None:
            name_to_use = config["accounts"].get("active_account")
            if not name_to_use:
                print("Error: No account name specified and no active account")
                return False

        # Ensure accounts structure exists
        if "accounts" not in config["accounts"]:
            config["accounts"]["accounts"] = {}

        # Get or create account data
        if name_to_use not in config["accounts"]["accounts"]:
            config["accounts"]["accounts"][name_to_use] = {}

        # Store the account data
        account = config["accounts"]["accounts"][name_to_use]
        account["seed_phrase"] = encrypted_data
        account["seed_phrase_encoded"] = True
        account["seed_phrase_salt"] = salt
        account["account_address"] = ss58_address

        # Set as active account if no active account exists
        if not config["accounts"].get("active_account"):
            config["accounts"]["active_account"] = name_to_use

        return save_config(config)

    except Exception as e:
        print(f"Error encrypting seed phrase: {e}")
        return False


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
    config = load_config()

    name_to_use = account_name or config["accounts"].get("active_account")

    if not name_to_use:
        print("Error: No account specified and no active account")
        return None

    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None

    account_data = config["accounts"]["accounts"][name_to_use]
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
    config = load_config()

    name_to_use = account_name or config["accounts"].get("active_account")

    if not name_to_use:
        print("Error: No account specified and no active account")
        return None

    if name_to_use not in config["accounts"].get("accounts", {}):
        print(f"Error: Account '{name_to_use}' not found")
        return None

    account_data = config["accounts"]["accounts"][name_to_use]
    is_encoded = account_data.get("seed_phrase_encoded", False)

    # If password is an empty string, this indicates we're doing a read-only operation
    # that doesn't require the seed phrase, so we can return None
    if password == "" and is_encoded:
        return None

    if is_encoded:
        return decrypt_seed_phrase(password, name_to_use)
    else:
        return account_data.get("seed_phrase")


# Initialize configuration on module import
ensure_config_dir()
