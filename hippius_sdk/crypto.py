"""
Cryptographic utilities for the Hippius SDK.

Provides password-based encryption/decryption using PBKDF2 key derivation
with NaCl SecretBox (XSalsa20-Poly1305), and AES-GCM decryption for
HCFS mnemonic files.
"""

import base64
import os
from typing import Optional, Tuple

import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
    Encrypt data using a password-derived key (PBKDF2 + NaCl SecretBox).

    Args:
        data: String data to encrypt
        password: User password

    Returns:
        Tuple[str, str]: (base64_encrypted_data, base64_salt)
    """
    # Derive key from password with a new salt
    key, salt = _derive_key_from_password(password)

    # Create a SecretBox with our derived key
    box = nacl.secret.SecretBox(key)

    # Encrypt the data
    encrypted_data = box.encrypt(data.encode("utf-8"))

    # Convert to base64 for storage
    encoded_data = base64.b64encode(encrypted_data).decode("utf-8")
    encoded_salt = base64.b64encode(salt).decode("utf-8")

    return encoded_data, encoded_salt


def decrypt_with_password(encrypted_data: str, salt: str, password: str) -> str:
    """
    Decrypt data using a password-derived key (PBKDF2 + NaCl SecretBox).

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

    # Create a SecretBox with our derived key
    box = nacl.secret.SecretBox(key)

    # Decrypt the data
    decrypted_data = box.decrypt(encrypted_bytes)

    # Return the decrypted string
    return decrypted_data.decode("utf-8")


def decrypt_hcfs_mnemonic(encrypted_data: dict, password: str) -> str:
    """
    Decrypt an HCFS mnemonic file using PBKDF2 + AES-GCM (matching Rust hcfs-client scheme).

    Args:
        encrypted_data: Dict with 'salt', 'iv', 'data' keys (base64-encoded)
        password: Encryption password

    Returns:
        str: Decrypted mnemonic phrase
    """
    salt = base64.b64decode(encrypted_data["salt"])
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["data"])

    # PBKDF2 key derivation (matching Rust: PBKDF2_HMAC_SHA256, 10000 iterations)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
    )
    derived_key = kdf.derive(password.encode())

    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")
