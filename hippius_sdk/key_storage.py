"""
Key storage module for managing encryption keys per seed phrase.

This module provides PostgreSQL-backed storage for:
1. Base64 encoded seed phrases
2. Encryption keys associated with each seed phrase (versioned, never deleted)
"""

import base64
import hashlib
import os
from datetime import datetime
from typing import Optional

from hippius_sdk.config import get_config_value

# Import asyncpg with fallback
try:
    import asyncpg

    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False


class KeyStorageError(Exception):
    """Base exception for key storage operations."""

    pass


class KeyStorage:
    """PostgreSQL-backed key storage for seed phrases and encryption keys."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize key storage with database connection.

        Args:
            database_url: PostgreSQL connection URL. If None, uses config or defaults to localhost.
        """
        if not ASYNCPG_AVAILABLE:
            raise KeyStorageError(
                "asyncpg is required for key storage. Install it with: pip install 'hippius_sdk[key_storage]'"
            )

        if database_url is None:
            database_url = get_config_value(
                "key_storage",
                "database_url",
                "postgresql://postgres:password@localhost:5432/hippius_keys",
            )

        self.database_url = database_url

    async def _get_connection(self):
        """Get a database connection."""
        try:
            return await asyncpg.connect(self.database_url)
        except Exception as e:
            raise KeyStorageError(f"Failed to connect to database: {e}")

    async def _ensure_tables_exist(self):
        """Create tables if they don't exist."""
        create_seed_phrases_table = """
        CREATE TABLE IF NOT EXISTS seed_phrases (
            id SERIAL PRIMARY KEY,
            seed_hash VARCHAR(64) UNIQUE NOT NULL,
            seed_phrase_b64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        create_encryption_keys_table = """
        CREATE TABLE IF NOT EXISTS encryption_keys (
            id SERIAL PRIMARY KEY,
            seed_hash VARCHAR(64) NOT NULL,
            encryption_key_b64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seed_hash) REFERENCES seed_phrases(seed_hash)
        );
        """

        create_index = """
        CREATE INDEX IF NOT EXISTS idx_encryption_keys_seed_hash_created 
        ON encryption_keys(seed_hash, created_at DESC);
        """

        try:
            conn = await self._get_connection()
            try:
                await conn.execute(create_seed_phrases_table)
                await conn.execute(create_encryption_keys_table)
                await conn.execute(create_index)
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to create tables: {e}")

    def _hash_seed_phrase(self, seed_phrase: str) -> str:
        """Create a SHA-256 hash of the seed phrase for indexing."""
        return hashlib.sha256(seed_phrase.encode("utf-8")).hexdigest()

    async def _ensure_seed_phrase_exists(self, seed_phrase: str) -> str:
        """Ensure seed phrase exists in database and return its hash."""
        seed_hash = self._hash_seed_phrase(seed_phrase)
        seed_phrase_b64 = base64.b64encode(seed_phrase.encode("utf-8")).decode("utf-8")

        try:
            conn = await self._get_connection()
            try:
                # Try to insert, ignore if already exists
                await conn.execute(
                    """
                    INSERT INTO seed_phrases (seed_hash, seed_phrase_b64) 
                    VALUES ($1, $2) 
                    ON CONFLICT (seed_hash) DO NOTHING
                """,
                    seed_hash,
                    seed_phrase_b64,
                )
            finally:
                await conn.close()
            return seed_hash
        except Exception as e:
            raise KeyStorageError(f"Failed to store seed phrase: {e}")

    async def set_key_for_seed(self, seed_phrase: str, encryption_key_b64: str) -> None:
        """
        Store a new encryption key for a seed phrase.

        Creates a new row (doesn't update existing ones) to maintain key history.

        Args:
            seed_phrase: The seed phrase
            encryption_key_b64: Base64-encoded encryption key

        Raises:
            KeyStorageError: If storage fails
        """
        await self._ensure_tables_exist()
        seed_hash = await self._ensure_seed_phrase_exists(seed_phrase)

        try:
            conn = await self._get_connection()
            try:
                await conn.execute(
                    """
                    INSERT INTO encryption_keys (seed_hash, encryption_key_b64)
                    VALUES ($1, $2)
                """,
                    seed_hash,
                    encryption_key_b64,
                )
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to store encryption key: {e}")

    async def get_key_for_seed(self, seed_phrase: str) -> Optional[str]:
        """
        Get the most recent encryption key for a seed phrase.

        Args:
            seed_phrase: The seed phrase

        Returns:
            Base64-encoded encryption key or None if not found

        Raises:
            KeyStorageError: If database operation fails
        """
        await self._ensure_tables_exist()
        seed_hash = self._hash_seed_phrase(seed_phrase)

        try:
            conn = await self._get_connection()
            try:
                result = await conn.fetchrow(
                    """
                    SELECT encryption_key_b64 
                    FROM encryption_keys 
                    WHERE seed_hash = $1 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """,
                    seed_hash,
                )

                return result["encryption_key_b64"] if result else None
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to retrieve encryption key: {e}")

    async def generate_and_store_key_for_seed(self, seed_phrase: str) -> str:
        """
        Generate a new encryption key and store it for the seed phrase.

        Args:
            seed_phrase: The seed phrase

        Returns:
            Base64-encoded encryption key that was generated and stored

        Raises:
            KeyStorageError: If generation or storage fails
        """
        # Generate a new encryption key
        try:
            import nacl.secret
            import nacl.utils

            # Generate a random key
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            key_b64 = base64.b64encode(key).decode("utf-8")

            # Store it
            await self.set_key_for_seed(seed_phrase, key_b64)

            return key_b64
        except ImportError:
            raise KeyStorageError(
                "PyNaCl is required for key generation. Install it with: pip install pynacl"
            )
        except Exception as e:
            raise KeyStorageError(f"Failed to generate encryption key: {e}")


# Module-level convenience functions
_default_storage = None


def is_key_storage_enabled() -> bool:
    """
    Check if key storage is enabled and available.

    Returns True if:
    1. Explicitly enabled in config, OR
    2. asyncpg is available (key_storage extra installed) AND not explicitly disabled
    """
    # Check if explicitly disabled
    config_value = get_config_value("key_storage", "enabled", None)
    if config_value is False:
        return False

    # If explicitly enabled, return True
    if config_value is True:
        return True

    # If not set in config, auto-detect based on asyncpg availability
    # This allows users who install [key_storage] extra to use it without manual config
    return ASYNCPG_AVAILABLE


def get_default_storage() -> KeyStorage:
    """Get the default KeyStorage instance."""
    global _default_storage
    if _default_storage is None:
        _default_storage = KeyStorage()
    return _default_storage


async def get_key_for_seed(seed_phrase: str) -> Optional[str]:
    """
    Get the most recent encryption key for a seed phrase.

    Args:
        seed_phrase: The seed phrase

    Returns:
        Base64-encoded encryption key or None if not found
    """
    return await get_default_storage().get_key_for_seed(seed_phrase)


async def set_key_for_seed(seed_phrase: str, encryption_key_b64: str) -> None:
    """
    Store a new encryption key for a seed phrase.

    Args:
        seed_phrase: The seed phrase
        encryption_key_b64: Base64-encoded encryption key
    """
    return await get_default_storage().set_key_for_seed(seed_phrase, encryption_key_b64)


async def generate_and_store_key_for_seed(seed_phrase: str) -> str:
    """
    Generate a new encryption key and store it for the seed phrase.

    Args:
        seed_phrase: The seed phrase

    Returns:
        Base64-encoded encryption key that was generated and stored
    """
    return await get_default_storage().generate_and_store_key_for_seed(seed_phrase)
