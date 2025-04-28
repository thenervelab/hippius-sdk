"""
Main client for the Hippius SDK.
"""

import base64
from typing import Any, Dict, List, Optional

import nacl.secret
import nacl.utils

from hippius_sdk.config import get_config_value, get_encryption_key
from hippius_sdk.ipfs import IPFSClient
from hippius_sdk.substrate import SubstrateClient


class HippiusClient:
    """
    Main client for interacting with the Hippius ecosystem.

    Provides IPFS operations, with Substrate functionality for storage requests.
    """

    def __init__(
        self,
        ipfs_gateway: Optional[str] = None,
        ipfs_api_url: Optional[str] = None,
        substrate_url: Optional[str] = None,
        substrate_seed_phrase: Optional[str] = None,
        seed_phrase_password: Optional[str] = None,
        account_name: Optional[str] = None,
        encrypt_by_default: Optional[bool] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize the Hippius client.

        Args:
            ipfs_gateway: IPFS gateway URL for downloading content (from config if None)
            ipfs_api_url: IPFS API URL for uploading content (from config if None)
            substrate_url: WebSocket URL of the Hippius substrate node (from config if None)
            substrate_seed_phrase: Seed phrase for Substrate account (from config if None)
            seed_phrase_password: Password to decrypt the seed phrase if it's encrypted
            account_name: Name of the account to use (uses active account if None)
            encrypt_by_default: Whether to encrypt files by default (from config if None)
            encryption_key: Encryption key for NaCl secretbox (from config if None)
        """
        # Load configuration values if not explicitly provided
        if ipfs_gateway is None:
            ipfs_gateway = get_config_value("ipfs", "gateway", "https://ipfs.io")

        if ipfs_api_url is None:
            ipfs_api_url = get_config_value(
                "ipfs", "api_url", "https://store.hippius.network"
            )

            # Check if local IPFS is enabled in config
            if get_config_value("ipfs", "local_ipfs", False):
                ipfs_api_url = "http://localhost:5001"

        if substrate_url is None:
            substrate_url = get_config_value(
                "substrate", "url", "wss://rpc.hippius.network"
            )

        if substrate_seed_phrase is None:
            substrate_seed_phrase = get_config_value("substrate", "seed_phrase")

        if encrypt_by_default is None:
            encrypt_by_default = get_config_value(
                "encryption", "encrypt_by_default", False
            )

        if encryption_key is None:
            encryption_key = get_encryption_key()

        # Initialize IPFS client
        self.ipfs_client = IPFSClient(
            gateway=ipfs_gateway,
            api_url=ipfs_api_url,
            encrypt_by_default=encrypt_by_default,
            encryption_key=encryption_key,
        )

        # Initialize Substrate client
        try:
            self.substrate_client = SubstrateClient(
                url=substrate_url,
                seed_phrase=substrate_seed_phrase,
                password=seed_phrase_password,
                account_name=account_name,
            )
        except Exception as e:
            print(f"Warning: Could not initialize Substrate client: {e}")
            self.substrate_client = None

    async def upload_file(
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
        return await self.ipfs_client.upload_file(file_path, encrypt=encrypt)

    async def upload_directory(
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
        return await self.ipfs_client.upload_directory(dir_path, encrypt=encrypt)

    async def download_file(
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
        return await self.ipfs_client.download_file(cid, output_path, decrypt=decrypt)

    async def cat(
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
        return await self.ipfs_client.cat(
            cid, max_display_bytes, format_output, decrypt=decrypt
        )

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
        return self.ipfs_client.exists(cid)

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
        return self.ipfs_client.pin(cid)

    def format_cid(self, cid: str) -> str:
        """
        Format a CID for display.

        This is a convenience method that delegates to the IPFSClient.

        Args:
            cid: Content Identifier (CID) to format

        Returns:
            str: Formatted CID string
        """
        return self.ipfs_client.format_cid(cid)

    def format_size(self, size_bytes: int) -> str:
        """
        Format a size in bytes to a human-readable string.

        This is a convenience method that delegates to the IPFSClient.

        Args:
            size_bytes: Size in bytes

        Returns:
            str: Human-readable size string (e.g., '1.23 MB', '456.78 KB')
        """
        return self.ipfs_client.format_size(size_bytes)

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
            # Generate a random key
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

            # Encode to base64 for storage in .env
            encoded_key = base64.b64encode(key).decode()

            return encoded_key
        except ImportError:
            raise ImportError(
                "PyNaCl is required for encryption. Install it with: pip install pynacl"
            )

    async def erasure_code_file(
        self,
        file_path: str,
        k: int = 3,
        m: int = 5,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        encrypt: Optional[bool] = None,
        max_retries: int = 3,
        verbose: bool = True,
    ) -> Dict[str, Any]:
        """
        Split a file using erasure coding, then upload the chunks to IPFS.

        This implements an (m, k) Reed-Solomon code where:
        - m = total number of chunks
        - k = minimum chunks needed to reconstruct the file (k <= m)
        - The file can be reconstructed from any k of the m chunks

        Args:
            file_path: Path to the file to upload
            k: Number of data chunks (minimum required to reconstruct)
            m: Total number of chunks (k + redundancy)
            chunk_size: Size of each chunk in bytes before encoding
            encrypt: Whether to encrypt the file before encoding (defaults to self.encrypt_by_default)
            max_retries: Maximum number of retry attempts for IPFS uploads
            verbose: Whether to print progress information

        Returns:
            dict: Metadata including the original file info and chunk information

        Raises:
            ValueError: If erasure coding is not available or parameters are invalid
            RuntimeError: If chunk uploads fail
        """
        return await self.ipfs_client.erasure_code_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            max_retries=max_retries,
            verbose=verbose,
        )

    async def reconstruct_from_erasure_code(
        self,
        metadata_cid: str,
        output_file: str,
        temp_dir: str = None,
        max_retries: int = 3,
        verbose: bool = True,
    ) -> str:
        """
        Reconstruct a file from erasure-coded chunks using its metadata.

        Args:
            metadata_cid: IPFS CID of the metadata file
            output_file: Path where the reconstructed file should be saved
            temp_dir: Directory to use for temporary files (default: system temp)
            max_retries: Maximum number of retry attempts for IPFS downloads
            verbose: Whether to print progress information

        Returns:
            str: Path to the reconstructed file

        Raises:
            ValueError: If reconstruction fails
            RuntimeError: If not enough chunks can be downloaded
        """
        return await self.ipfs_client.reconstruct_from_erasure_code(
            metadata_cid=metadata_cid,
            output_file=output_file,
            temp_dir=temp_dir,
            max_retries=max_retries,
            verbose=verbose,
        )

    async def store_erasure_coded_file(
        self,
        file_path: str,
        k: int = 3,
        m: int = 5,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        encrypt: Optional[bool] = None,
        miner_ids: List[str] = None,
        max_retries: int = 3,
        verbose: bool = True,
    ) -> Dict[str, Any]:
        """
        Erasure code a file, upload the chunks to IPFS, and store in the Hippius marketplace.

        This is a convenience method that combines erasure_code_file with storage_request.

        Args:
            file_path: Path to the file to upload
            k: Number of data chunks (minimum required to reconstruct)
            m: Total number of chunks (k + redundancy)
            chunk_size: Size of each chunk in bytes before encoding
            encrypt: Whether to encrypt the file before encoding
            miner_ids: List of specific miner IDs to use for storage
            max_retries: Maximum number of retry attempts
            verbose: Whether to print progress information

        Returns:
            dict: Result including metadata CID and transaction hash

        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If processing fails
        """
        return await self.ipfs_client.store_erasure_coded_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            miner_ids=miner_ids,
            substrate_client=self.substrate_client,
            max_retries=max_retries,
            verbose=verbose,
        )
