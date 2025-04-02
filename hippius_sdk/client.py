"""
Main client for the Hippius SDK.
"""

import os
from typing import Dict, Any, Optional, List, Union
from hippius_sdk.ipfs import IPFSClient
from hippius_sdk.substrate import SubstrateClient, FileInput


class HippiusClient:
    """
    Main client for interacting with the Hippius ecosystem.

    Provides IPFS operations, with Substrate functionality for storage requests.
    """

    def __init__(
        self,
        ipfs_gateway: str = "https://ipfs.io",
        ipfs_api_url: str = "https://relay-fr.hippius.network",
        substrate_url: str = None,
        substrate_seed_phrase: str = None,
        encrypt_by_default: Optional[bool] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize the Hippius client.

        Args:
            ipfs_gateway: IPFS gateway URL for downloading content
            ipfs_api_url: IPFS API URL for uploading content. Defaults to Hippius relay node.
            substrate_url: WebSocket URL of the Hippius substrate node
            substrate_seed_phrase: Seed phrase for Substrate account
            encrypt_by_default: Whether to encrypt files by default (from .env if None)
            encryption_key: Encryption key for NaCl secretbox (from .env if None)
        """
        self.ipfs = IPFSClient(
            gateway=ipfs_gateway,
            api_url=ipfs_api_url,
            encrypt_by_default=encrypt_by_default,
            encryption_key=encryption_key,
        )

        # Initialize Substrate client
        try:
            self.substrate_client = SubstrateClient(
                url=substrate_url, seed_phrase=substrate_seed_phrase
            )
        except Exception as e:
            print(f"Warning: Could not initialize Substrate client: {e}")
            self.substrate_client = None

    def upload_file(
        self, file_path: str, encrypt: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Upload a file to IPFS with optional encryption.

        Args:
            file_path: Path to the file to upload
            encrypt: Whether to encrypt the file (overrides default)

        Returns:
            Dict[str, Any]: Dictionary containing file details including:
                - cid: Content Identifier of the uploaded file
                - filename: Name of the file
                - size_bytes: Size of the file in bytes
                - size_formatted: Human-readable file size
                - encrypted: Whether the file was encrypted

        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
            ValueError: If encryption is requested but not available
        """
        # Use the enhanced IPFSClient method directly with encryption parameter
        return self.ipfs.upload_file(file_path, encrypt=encrypt)

    def upload_directory(
        self, dir_path: str, encrypt: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Upload a directory to IPFS with optional encryption.

        Args:
            dir_path: Path to the directory to upload
            encrypt: Whether to encrypt files (overrides default)

        Returns:
            Dict[str, Any]: Dictionary containing directory details including:
                - cid: Content Identifier of the uploaded directory
                - dirname: Name of the directory
                - file_count: Number of files uploaded
                - total_size_bytes: Total size in bytes
                - size_formatted: Human-readable total size
                - encrypted: Whether files were encrypted

        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
            ValueError: If encryption is requested but not available
        """
        # Use the enhanced IPFSClient method directly with encryption parameter
        return self.ipfs.upload_directory(dir_path, encrypt=encrypt)

    def download_file(
        self, cid: str, output_path: str, decrypt: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Download a file from IPFS with optional decryption.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
            decrypt: Whether to decrypt the file (overrides default)

        Returns:
            Dict[str, Any]: Dictionary containing download details including:
                - success: Whether the download was successful
                - output_path: Path where the file was saved
                - size_bytes: Size of the downloaded file in bytes
                - size_formatted: Human-readable file size
                - elapsed_seconds: Time taken for the download
                - decrypted: Whether the file was decrypted

        Raises:
            requests.RequestException: If the download fails
            ValueError: If decryption is requested but fails
        """
        return self.ipfs.download_file(cid, output_path, decrypt=decrypt)

    def cat(
        self,
        cid: str,
        max_display_bytes: int = 1024,
        format_output: bool = True,
        decrypt: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Get the content of a file from IPFS with optional decryption.

        Args:
            cid: Content Identifier (CID) of the file
            max_display_bytes: Maximum number of bytes to include in the preview
            format_output: Whether to attempt to decode the content as text
            decrypt: Whether to decrypt the file (overrides default)

        Returns:
            Dict[str, Any]: Dictionary containing content details including:
                - content: Complete binary content of the file
                - size_bytes: Size of the content in bytes
                - size_formatted: Human-readable size
                - is_text: Whether the content seems to be text
                - text_preview/hex_preview: Preview of the content
                - decrypted: Whether the file was decrypted
        """
        return self.ipfs.cat(cid, max_display_bytes, format_output, decrypt=decrypt)

    def exists(self, cid: str) -> Dict[str, Any]:
        """
        Check if a CID exists on IPFS.

        Args:
            cid: Content Identifier (CID) to check

        Returns:
            Dict[str, Any]: Dictionary containing:
                - exists: Boolean indicating if the CID exists
                - cid: The CID that was checked
                - formatted_cid: Formatted version of the CID
                - gateway_url: URL to access the content if it exists
        """
        return self.ipfs.exists(cid)

    def pin(self, cid: str) -> Dict[str, Any]:
        """
        Pin a CID to IPFS to keep it available.

        Args:
            cid: Content Identifier (CID) to pin

        Returns:
            Dict[str, Any]: Dictionary containing:
                - success: Boolean indicating if pinning was successful
                - cid: The CID that was pinned
                - formatted_cid: Formatted version of the CID
                - message: Status message
        """
        return self.ipfs.pin(cid)

    def format_cid(self, cid: str) -> str:
        """
        Format a CID for display.

        This is a convenience method that delegates to the IPFSClient.

        Args:
            cid: Content Identifier (CID) to format

        Returns:
            str: Formatted CID string
        """
        return self.ipfs.format_cid(cid)

    def format_size(self, size_bytes: int) -> str:
        """
        Format a size in bytes to a human-readable string.

        This is a convenience method that delegates to the IPFSClient.

        Args:
            size_bytes: Size in bytes

        Returns:
            str: Human-readable size string (e.g., '1.23 MB', '456.78 KB')
        """
        return self.ipfs.format_size(size_bytes)

    def generate_encryption_key(self) -> str:
        """
        Generate a new random encryption key for use with the SDK.

        Returns:
            str: Base64-encoded encryption key ready for use in .env file
                 or directly as the encryption_key parameter (after base64 decoding).

        Raises:
            ImportError: If PyNaCl is not installed
        """
        try:
            import nacl.utils
            import nacl.secret
            import base64

            # Generate a random key
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

            # Encode to base64 for storage in .env
            encoded_key = base64.b64encode(key).decode()

            return encoded_key
        except ImportError:
            raise ImportError(
                "PyNaCl is required for encryption. Install it with: pip install pynacl"
            )
