"""
Key storage module for managing encryption keys per subaccount ID.

This module provides PostgreSQL-backed storage for:
1. Encryption keys associated with each subaccount ID (versioned, never deleted)
"""

import base64
import hashlib
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
    """PostgreSQL-backed key storage for subaccount encryption keys."""

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
        create_encryption_keys_table = """
        CREATE TABLE IF NOT EXISTS encryption_keys (
            id SERIAL PRIMARY KEY,
            subaccount_id VARCHAR(255) NOT NULL,
            encryption_key_b64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        create_index = """
        CREATE INDEX IF NOT EXISTS idx_encryption_keys_subaccount_created 
        ON encryption_keys(subaccount_id, created_at DESC);
        """

        try:
            conn = await self._get_connection()
            try:
                await conn.execute(create_encryption_keys_table)
                await conn.execute(create_index)
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to create tables: {e}")

    def _hash_subaccount_id(self, subaccount_id: str) -> str:
        """Create a SHA-256 hash of the subaccount ID for indexing."""
        return hashlib.sha256(subaccount_id.encode("utf-8")).hexdigest()

    async def set_key_for_subaccount(
        self, subaccount_id: str, encryption_key_b64: str
    ) -> None:
        """
        Store a new encryption key for a subaccount.

        Creates a new row (doesn't update existing ones) to maintain key history.

        Args:
            subaccount_id: The subaccount identifier
            encryption_key_b64: Base64-encoded encryption key

        Raises:
            KeyStorageError: If storage fails
        """
        await self._ensure_tables_exist()
        subaccount_hash = self._hash_subaccount_id(subaccount_id)

        try:
            conn = await self._get_connection()
            try:
                await conn.execute(
                    """
                    INSERT INTO encryption_keys (subaccount_id, encryption_key_b64)
                    VALUES ($1, $2)
                """,
                    subaccount_hash,
                    encryption_key_b64,
                )
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to store encryption key: {e}")

    async def get_key_for_subaccount(self, subaccount_id: str) -> Optional[str]:
        """
        Get the most recent encryption key for a subaccount.

        Args:
            subaccount_id: The subaccount identifier

        Returns:
            Base64-encoded encryption key or None if not found

        Raises:
            KeyStorageError: If database operation fails
        """
        await self._ensure_tables_exist()
        subaccount_hash = self._hash_subaccount_id(subaccount_id)

        try:
            conn = await self._get_connection()
            try:
                result = await conn.fetchrow(
                    """
                    SELECT encryption_key_b64 
                    FROM encryption_keys 
                    WHERE subaccount_id = $1 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """,
                    subaccount_hash,
                )

                return result["encryption_key_b64"] if result else None
            finally:
                await conn.close()
        except Exception as e:
            raise KeyStorageError(f"Failed to retrieve encryption key: {e}")

    async def generate_and_store_key_for_subaccount(self, subaccount_id: str) -> str:
        """
        Generate a new encryption key and store it for the subaccount.

        Args:
            subaccount_id: The subaccount identifier

        Returns:
            Base64-encoded encryption key that was generated and stored

        Raises:
            KeyStorageError: If generation or storage fails
        """
        try:
            import nacl.secret
            import nacl.utils

            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            key_b64 = base64.b64encode(key).decode("utf-8")

            await self.set_key_for_subaccount(subaccount_id, key_b64)

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


async def get_key_for_subaccount(subaccount_id: str) -> Optional[str]:
    """
    Get the most recent encryption key for a subaccount.

    Args:
        subaccount_id: The subaccount identifier

    Returns:
        Base64-encoded encryption key or None if not found
    """
    return await get_default_storage().get_key_for_subaccount(subaccount_id)


async def set_key_for_subaccount(subaccount_id: str, encryption_key_b64: str) -> None:
    """
    Store a new encryption key for a subaccount.

    Args:
        subaccount_id: The subaccount identifier
        encryption_key_b64: Base64-encoded encryption key
    """
    return await get_default_storage().set_key_for_subaccount(
        subaccount_id, encryption_key_b64
    )


async def generate_and_store_key_for_subaccount(subaccount_id: str) -> str:
    """
    Generate a new encryption key and store it for the subaccount.

    Args:
        subaccount_id: The subaccount identifier

    Returns:
        Base64-encoded encryption key that was generated and stored
    """
    return await get_default_storage().generate_and_store_key_for_subaccount(
        subaccount_id
    )
