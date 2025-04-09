"""
Configuration management for Hippius SDK.

This module handles loading and saving configuration from the user's home directory,
specifically in ~/.hippius/config.
"""

import os
import json
import base64
import hashlib
import getpass
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple

# Define constants
CONFIG_DIR = os.path.expanduser("~/.hippius")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEFAULT_CONFIG = {
    "ipfs": {
        "gateway": "https://ipfs.io",
        "api_url": "https://store.hippius.network",
        "local_ipfs": False,
    },
    "substrate": {
        "url": "wss://rpc.hippius.network",
        "seed_phrase": None,
        "seed_phrase_encoded": False,
        "seed_phrase_salt": None,  # Salt for password-based encryption
        "default_miners": [],
        "active_account": None,  # Name of the active account
        "accounts": {},  # Dictionary of accounts with names as keys
    },
    "encryption": {
        "encrypt_by_default": False,
        "encryption_key": None,
    },
    "erasure_coding": {
        "default_k": 3,
        "default_m": 5,
        "default_chunk_size": 1024 * 1024,  # 1MB
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


def load_config() -> Dict[str, Any]:
    """
    Load configuration from the config file.

    If the file doesn't exist, create it with default values.

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

        # Ensure all config sections exist (for backward compatibility)
        for section, defaults in DEFAULT_CONFIG.items():
            if section not in config:
                config[section] = defaults

        return config
    except Exception as e:
        print(f"Warning: Could not load configuration file: {e}")
        print(f"Using default configuration")
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


def get_encryption_key() -> Optional[bytes]:
    """
    Get the encryption key from the configuration.

    Returns:
        Optional[bytes]: The encryption key or None if not set
    """
    key_str = get_config_value("encryption", "encryption_key")
    if not key_str:
        return None

    try:
        return base64.b64decode(key_str)
    except Exception as e:
        print(f"Warning: Could not decode encryption key from config: {e}")
        return None


def set_encryption_key(key: Union[bytes, str]) -> bool:
    """
    Set the encryption key in the configuration.

    Args:
        key: The encryption key (bytes or base64-encoded string)

    Returns:
        bool: True if save was successful, False otherwise
    """
    # Convert bytes to base64 string if needed
    if isinstance(key, bytes):
        key = base64.b64encode(key).decode()

    return set_config_value("encryption", "encryption_key", key)


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
    # Import cryptography for PBKDF2
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import os
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

        # Import NaCl for encryption
        try:
            import nacl.secret
            import nacl.utils
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
    try:
        # Decode the encrypted data and salt
        encrypted_bytes = base64.b64decode(encrypted_data)
        salt_bytes = base64.b64decode(salt)

        # Derive the key from the password and salt
        key, _ = _derive_key_from_password(password, salt_bytes)

        # Import NaCl for decryption
        try:
            import nacl.secret
            import nacl.utils
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

    except Exception as e:
        raise ValueError(f"Error decrypting data with password: {e}")


def encrypt_seed_phrase(
    seed_phrase: str, password: Optional[str] = None, account_name: Optional[str] = None
) -> bool:
    """
    Encrypt the substrate seed phrase using password-based encryption.

    Args:
        seed_phrase: The plain text seed phrase to encrypt
        password: Optional password (if None, will prompt)
        account_name: Optional name for the account (if None, uses legacy mode or active account)

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
            from substrateinterface import Keypair

            keypair = Keypair.create_from_mnemonic(seed_phrase)
            ss58_address = keypair.ss58_address
        except Exception as e:
            print(f"Warning: Could not derive SS58 address: {e}")

        config = load_config()

        # Check if we're using the new multi-account system
        if account_name is not None:
            # Multi-account mode
            if "accounts" not in config["substrate"]:
                config["substrate"]["accounts"] = {}

            # Store the account data
            config["substrate"]["accounts"][account_name] = {
                "seed_phrase": encrypted_data,
                "seed_phrase_encoded": True,
                "seed_phrase_salt": salt,
                "ss58_address": ss58_address,
            }

            # Set as active account if no active account exists
            if not config["substrate"].get("active_account"):
                config["substrate"]["active_account"] = account_name

        else:
            # Legacy mode - single account
            config["substrate"]["seed_phrase"] = encrypted_data
            config["substrate"]["seed_phrase_encoded"] = True
            config["substrate"]["seed_phrase_salt"] = salt
            config["substrate"]["ss58_address"] = ss58_address

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
        password: Optional password (if None, will prompt)
        account_name: Optional account name (if None, uses active account or legacy mode)

    Returns:
        Optional[str]: The decrypted seed phrase, or None if decryption failed
    """
    try:
        config = load_config()

        # Determine if we're using multi-account mode
        if account_name is not None or config["substrate"].get("active_account"):
            # Multi-account mode
            name_to_use = account_name or config["substrate"].get("active_account")

            if not name_to_use:
                print("Error: No account specified and no active account")
                return None

            if name_to_use not in config["substrate"].get("accounts", {}):
                print(f"Error: Account '{name_to_use}' not found")
                return None

            account_data = config["substrate"]["accounts"][name_to_use]
            is_encoded = account_data.get("seed_phrase_encoded", False)

            if not is_encoded:
                return account_data.get("seed_phrase")

            encrypted_data = account_data.get("seed_phrase")
            salt = account_data.get("seed_phrase_salt")

        else:
            # Legacy mode - single account
            is_encoded = config["substrate"].get("seed_phrase_encoded", False)

            if not is_encoded:
                return config["substrate"].get("seed_phrase")

            encrypted_data = config["substrate"].get("seed_phrase")
            salt = config["substrate"].get("seed_phrase_salt")

        if not encrypted_data or not salt:
            print("Error: No encrypted seed phrase found or missing salt")
            return None

        # Get password from user if not provided
        if password is None:
            password = getpass.getpass("Enter password to decrypt seed phrase: ")

        # Decrypt the seed phrase
        return decrypt_with_password(encrypted_data, salt, password)

    except Exception as e:
        print(f"Error decrypting seed phrase: {e}")
        return None


def get_seed_phrase(
    password: Optional[str] = None, account_name: Optional[str] = None
) -> Optional[str]:
    """
    Get the substrate seed phrase from configuration, decrypting if necessary.

    Args:
        password: Optional password for decryption (if None and needed, will prompt)
        account_name: Optional account name (if None, uses active account or legacy mode)

    Returns:
        Optional[str]: The seed phrase, or None if not available
    """
    config = load_config()

    # Determine if we're using multi-account mode
    if account_name is not None or config["substrate"].get("active_account"):
        # Multi-account mode
        name_to_use = account_name or config["substrate"].get("active_account")

        if not name_to_use:
            print("Error: No account specified and no active account")
            return None

        if name_to_use not in config["substrate"].get("accounts", {}):
            print(f"Error: Account '{name_to_use}' not found")
            return None

        account_data = config["substrate"]["accounts"][name_to_use]
        is_encoded = account_data.get("seed_phrase_encoded", False)

    else:
        # Legacy mode - single account
        is_encoded = config["substrate"].get("seed_phrase_encoded", False)

    if is_encoded:
        # If encoded, decrypt it
        return decrypt_seed_phrase(password, account_name)
    else:
        # If not encoded, just return the plain text seed phrase
        if account_name is not None or config["substrate"].get("active_account"):
            # Multi-account mode
            name_to_use = account_name or config["substrate"].get("active_account")
            return config["substrate"]["accounts"][name_to_use].get("seed_phrase")
        else:
            # Legacy mode
            return config["substrate"].get("seed_phrase")


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
        account_name: Optional name for the account (if None, uses legacy mode or active account)

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
            from substrateinterface import Keypair

            keypair = Keypair.create_from_mnemonic(seed_phrase)
            ss58_address = keypair.ss58_address
        except Exception as e:
            print(f"Warning: Could not derive SS58 address: {e}")

        # Determine if we're using multi-account mode
        if account_name is not None:
            # Multi-account mode
            if "accounts" not in config["substrate"]:
                config["substrate"]["accounts"] = {}

            # Store the account data
            config["substrate"]["accounts"][account_name] = {
                "seed_phrase": seed_phrase,
                "seed_phrase_encoded": False,
                "seed_phrase_salt": None,
                "ss58_address": ss58_address,
            }

            # Set as active account if no active account exists
            if not config["substrate"].get("active_account"):
                config["substrate"]["active_account"] = account_name

        else:
            # Legacy mode - single account
            config["substrate"]["seed_phrase"] = seed_phrase
            config["substrate"]["seed_phrase_encoded"] = False
            config["substrate"]["seed_phrase_salt"] = None
            config["substrate"]["ss58_address"] = ss58_address

        return save_config(config)


def get_active_account() -> Optional[str]:
    """
    Get the name of the currently active account.

    Returns:
        Optional[str]: The name of the active account, or None if not set
    """
    return get_config_value("substrate", "active_account")


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
    if account_name not in config["substrate"].get("accounts", {}):
        print(f"Error: Account '{account_name}' not found")
        return False

    # Set as active account
    config["substrate"]["active_account"] = account_name
    return save_config(config)


def list_accounts() -> Dict[str, Dict[str, Any]]:
    """
    Get a list of all stored accounts.

    Returns:
        Dict[str, Dict[str, Any]]: Dictionary of account names to account data
    """
    config = load_config()
    accounts = config["substrate"].get("accounts", {})

    # Mark the active account
    active_account = config["substrate"].get("active_account")
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
    if account_name not in config["substrate"].get("accounts", {}):
        print(f"Error: Account '{account_name}' not found")
        return False

    # Delete the account
    del config["substrate"]["accounts"][account_name]

    # Update active account if needed
    if config["substrate"].get("active_account") == account_name:
        if config["substrate"]["accounts"]:
            # Set the first remaining account as active
            config["substrate"]["active_account"] = next(
                iter(config["substrate"]["accounts"])
            )
        else:
            # No more accounts
            config["substrate"]["active_account"] = None

    return save_config(config)


def get_account_address(account_name: Optional[str] = None) -> Optional[str]:
    """
    Get the SS58 address for an account.

    Args:
        account_name: Optional name of the account (if None, uses active account or legacy mode)

    Returns:
        Optional[str]: The SS58 address, or None if not available
    """
    config = load_config()

    # Determine if we're using multi-account mode
    if account_name is not None or config["substrate"].get("active_account"):
        # Multi-account mode
        name_to_use = account_name or config["substrate"].get("active_account")

        if not name_to_use:
            print("Error: No account specified and no active account")
            return None

        if name_to_use not in config["substrate"].get("accounts", {}):
            print(f"Error: Account '{name_to_use}' not found")
            return None

        return config["substrate"]["accounts"][name_to_use].get("ss58_address")
    else:
        # Legacy mode - single account
        return config["substrate"].get("ss58_address")


def initialize_from_env() -> None:
    """
    Initialize configuration from environment variables.

    This is useful for maintaining backward compatibility with .env files.
    """
    # Load dotenv first to get environment variables
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    config = load_config()
    changed = False

    # IPFS settings
    if os.getenv("IPFS_GATEWAY"):
        config["ipfs"]["gateway"] = os.getenv("IPFS_GATEWAY")
        changed = True

    if os.getenv("IPFS_API_URL"):
        config["ipfs"]["api_url"] = os.getenv("IPFS_API_URL")
        changed = True

    # Substrate settings
    if os.getenv("SUBSTRATE_URL"):
        config["substrate"]["url"] = os.getenv("SUBSTRATE_URL")
        changed = True

    if os.getenv("SUBSTRATE_SEED_PHRASE"):
        # Don't encrypt from env variables by default
        config["substrate"]["seed_phrase"] = os.getenv("SUBSTRATE_SEED_PHRASE")
        config["substrate"]["seed_phrase_encoded"] = False
        config["substrate"]["seed_phrase_salt"] = None
        changed = True

    if os.getenv("SUBSTRATE_DEFAULT_MINERS"):
        miners = os.getenv("SUBSTRATE_DEFAULT_MINERS").split(",")
        config["substrate"]["default_miners"] = [m.strip() for m in miners if m.strip()]
        changed = True

    # Encryption settings
    if os.getenv("HIPPIUS_ENCRYPTION_KEY"):
        config["encryption"]["encryption_key"] = os.getenv("HIPPIUS_ENCRYPTION_KEY")
        changed = True

    if os.getenv("HIPPIUS_ENCRYPT_BY_DEFAULT"):
        value = os.getenv("HIPPIUS_ENCRYPT_BY_DEFAULT").lower()
        config["encryption"]["encrypt_by_default"] = value in ("true", "1", "yes")
        changed = True

    if changed:
        save_config(config)


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


def get_keypair(
    ss58_address: Optional[str] = None, account_name: Optional[str] = None
) -> "Keypair":
    """
    Get a Keypair object for a given SS58 address or account name.

    This function will attempt to find the specified account and generate
    a Keypair object using the stored seed phrase.

    Args:
        ss58_address: SS58 address of the account
        account_name: Name of the account (used if ss58_address is None)

    Returns:
        Keypair: A substrate Keypair object

    Raises:
        ValueError: If the account cannot be found or if the seed phrase is not available
        ImportError: If the required dependencies are not installed
    """
    # Import here to avoid circular imports
    try:
        from substrateinterface import Keypair
    except ImportError:
        raise ImportError(
            "Substrate interface is required to get a keypair. "
            "Install with: pip install substrate-interface"
        )

    # If ss58_address is provided, look for a matching account
    if ss58_address:
        accounts = list_accounts()
        found_account = None

        for name, data in accounts.items():
            if data.get("ss58_address") == ss58_address:
                found_account = name
                break

        if found_account:
            account_name = found_account
        else:
            raise ValueError(f"No account found with SS58 address: {ss58_address}")

    # If no account_name by this point, use the active account
    if not account_name:
        account_name = get_active_account()
        if not account_name:
            raise ValueError(
                "No account specified and no active account. "
                "Set an active account with: hippius account switch <account_name>"
            )

    # Get the seed phrase for the account
    seed_phrase = get_seed_phrase(account_name=account_name)
    if not seed_phrase:
        if get_config_value("substrate", "seed_phrase_encoded"):
            raise ValueError(
                f"The seed phrase for account '{account_name}' is encrypted. "
                f"Please decrypt it first with: hippius seed decode --account {account_name}"
            )
        else:
            raise ValueError(
                f"No seed phrase found for account '{account_name}'. "
                f'Set one with: hippius seed set "your seed phrase" --account {account_name}'
            )

    # Create and return the keypair
    return Keypair.create_from_mnemonic(seed_phrase)


# Initialize configuration on module import
ensure_config_dir()
