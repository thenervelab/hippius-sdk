"""
Main client for the Hippius SDK.
"""

import base64
from typing import Any, Callable, Dict, List, Optional, Union, AsyncIterator

import nacl.secret
import nacl.utils

from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.config import (
    get_config_value,
    get_encryption_key,
    validate_ipfs_node_url,
)
from hippius_sdk.ipfs import IPFSClient, S3DownloadResult


class HippiusClient:
    """
    Main client for interacting with the Hippius ecosystem.

    Provides IPFS operations and API-based storage management.
    """

    def __init__(
        self,
        ipfs_api_url: Optional[str] = None,
        hippius_key: Optional[str] = None,
        hippius_key_password: Optional[str] = None,
        api_url: Optional[str] = None,
        account_name: Optional[str] = None,
        encrypt_by_default: Optional[bool] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize the Hippius client.

        Args:
            ipfs_api_url: IPFS API URL for uploading/downloading content (from config if None)
            hippius_key: HIPPIUS_KEY for API authentication (from config if None)
            hippius_key_password: Password to decrypt the HIPPIUS_KEY if it's encrypted
            api_url: Hippius API URL (default: https://api.hippius.com)
            account_name: Name of the account to use (uses active account if None)
            encrypt_by_default: Whether to encrypt files by default (from config if None)
            encryption_key: Encryption key for NaCl secretbox (from config if None)
        """
        # Load configuration values if not explicitly provided
        if ipfs_api_url is None:
            # Check if local IPFS is enabled in config
            if get_config_value("ipfs", "local_ipfs", False):
                ipfs_api_url = "http://localhost:5001"
            else:
                ipfs_api_url = get_config_value("ipfs", "api_url", None)
                # Validate the URL (will raise ValueError if missing or deprecated)
                ipfs_api_url = validate_ipfs_node_url(ipfs_api_url)

        if encrypt_by_default is None:
            encrypt_by_default = get_config_value(
                "encryption", "encrypt_by_default", False
            )

        if encryption_key is None:
            encryption_key = get_encryption_key()

        # Initialize IPFS client
        self.ipfs_client = IPFSClient(
            api_url=ipfs_api_url,
            encrypt_by_default=encrypt_by_default,
            encryption_key=encryption_key,
        )

        # Initialize Hippius API client
        api_url_to_use = api_url or get_config_value(
            "hippius", "api_url", "https://api.hippius.com/api"
        )
        self.api_client = HippiusApiClient(
            api_url=api_url_to_use,
            hippius_key=hippius_key,
            hippius_key_password=hippius_key_password,
            account_name=account_name,
        )

    async def upload_file(
        self,
        file_path: str,
        encrypt: Optional[bool] = None,
        hippius_key: Optional[str] = None,
        pin: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload a file to local IPFS node and optionally pin to Hippius API.

        Flow:
            1. Upload file to local IPFS node -> get CID
            2. If pin=True, pin CID to Hippius API via /storage-control/requests/

        Args:
            file_path: Path to the file to upload
            encrypt: Whether to encrypt the file (overrides default)
            hippius_key: Optional HIPPIUS_KEY for API authentication
            pin: Whether to pin to Hippius API after upload (default: True)

        Returns:
            Dict[str, Any]: Dictionary containing file details including:
                - cid: Content Identifier of the uploaded file
                - filename: Name of the file
                - size_bytes: Size of the file in bytes
                - size_formatted: Human-readable file size
                - encrypted: Whether the file was encrypted
                - pinned: Whether file was pinned to Hippius API (if pin=True)
                - pin_request_id: Pin request ID (if pin=True and successful)
                - pin_error: Error message if pinning failed (if pin=True)

        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
            ValueError: If encryption is requested but not available
        """
        upload_result = await self.ipfs_client.upload_file(
            file_path,
            encrypt=encrypt,
        )

        cid = upload_result["cid"]
        filename = upload_result["filename"]

        if pin:
            pin_result = await self.api_client.pin_file(
                cid=cid,
                filename=filename,
                hippius_key=hippius_key,
            )

            upload_result["pinned"] = True
            upload_result["pin_request_id"] = pin_result.get("id") or pin_result.get(
                "request_id"
            )
        else:
            upload_result["pinned"] = False

        return upload_result

    async def upload_directory(
        self,
        dir_path: str,
        encrypt: Optional[bool] = None,
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
        return await self.ipfs_client.upload_directory(
            dir_path,
            encrypt=encrypt,
        )

    async def download_file(
        self,
        cid: str,
        output_path: str,
        decrypt: Optional[bool] = None,
        skip_directory_check: bool = False,
    ) -> Dict[str, Any]:
        """
        Download a file from IPFS with optional decryption.
        Supports downloading directories - in that case, a directory structure will be created.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file/directory will be saved
            decrypt: Whether to decrypt the file (overrides default)
            skip_directory_check: don't check if it's a directory.

        Returns:
            Dict[str, Any]: Dictionary containing download details including:
                - success: Whether the download was successful
                - output_path: Path where the file was saved
                - size_bytes: Size of the downloaded file in bytes
                - size_formatted: Human-readable file size
                - elapsed_seconds: Time taken for the download
                - decrypted: Whether the file was decrypted
                - is_directory: Whether the download was a directory

        Raises:
            requests.RequestException: If the download fails
            ValueError: If decryption is requested but fails
        """
        return await self.ipfs_client.download_file(
            cid,
            output_path,
            _=decrypt,
            skip_directory_check=skip_directory_check,
        )

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
            cid,
            max_display_bytes,
            format_output,
            decrypt=decrypt,
        )

    async def exists(self, cid: str) -> Dict[str, Any]:
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
        return await self.ipfs_client.exists(cid)

    async def pin(self, cid: str) -> Dict[str, Any]:
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
        return await self.ipfs_client.pin(cid)

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
    ) -> Dict:
        """
        Reconstruct a file from erasure-coded chunks using its metadata.

        Args:
            metadata_cid: IPFS CID of the metadata file
            output_file: Path where the reconstructed file should be saved
            temp_dir: Directory to use for temporary files (default: system temp)
            max_retries: Maximum number of retry attempts for IPFS downloads
            verbose: Whether to print progress information

        Returns:
            Dict: containing file reconstruction info.

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
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        publish: bool = True,
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
            progress_callback: Optional callback function for progress updates
                            Function receives (stage_name, current, total)
            publish: Whether to publish to the blockchain (True) or just perform local
                    erasure coding without publishing (False). When False, no password
                    is needed for seed phrase access.

        Returns:
            dict: Result including metadata CID and transaction hash (if published)

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
            substrate_client=None,
            max_retries=max_retries,
            verbose=verbose,
            progress_callback=progress_callback,
            publish=publish,
        )

    async def delete_file(
        self,
        cid: str,
        cancel_from_blockchain: bool = True,
        unpin: bool = True,
    ) -> Dict[str, Any]:
        """
        Delete a file from IPFS and optionally cancel its storage on the blockchain.

        Args:
            cid: Content Identifier (CID) of the file to delete
            cancel_from_blockchain: Whether to also cancel the storage request from the blockchain
            unpin: whether to unpin or not.
        Returns:
            Dict containing the result of the operation

        Raises:
            RuntimeError: If deletion fails completely
        """
        return await self.ipfs_client.delete_file(
            cid,
            cancel_from_blockchain,
            unpin=unpin,
        )

    async def delete_ec_file(
        self,
        metadata_cid: str,
        cancel_from_blockchain: bool = True,
        parallel_limit: int = 20,
    ) -> bool:
        """
        Delete an erasure-coded file, including all its chunks in parallel.

        Args:
            metadata_cid: CID of the metadata file for the erasure-coded file
            cancel_from_blockchain: Whether to cancel storage from blockchain
            parallel_limit: Maximum number of concurrent deletion operations

        Returns:
            True or false if failed.

        Raises:
            RuntimeError: If deletion fails completely
        """
        return await self.ipfs_client.delete_ec_file(
            metadata_cid,
            cancel_from_blockchain,
            parallel_limit,
        )

    async def s3_download(
        self,
        cid: str,
        output_path: Optional[str] = None,
        subaccount_id: Optional[str] = None,
        bucket_name: Optional[str] = None,
        auto_decrypt: bool = True,
        download_node: str = "http://localhost:5001",
        return_bytes: bool = False,
        streaming: bool = False,
    ) -> Union[S3DownloadResult, bytes, AsyncIterator[bytes]]:
        """
        Download content from IPFS with flexible output options and automatic decryption.

        This method provides multiple output modes:
        1. File output: Downloads to specified path (default mode)
        2. Bytes output: Returns decrypted bytes in memory (return_bytes=True)
        3. Streaming output: Returns raw streaming iterator from IPFS node (streaming=True)

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved (None for bytes/streaming)
            subaccount_id: The subaccount/account identifier (required for decryption)
            bucket_name: The bucket name for key isolation (required for decryption)
            auto_decrypt: Whether to attempt automatic decryption (default: True)
            download_node: IPFS node URL for download (default: local node)
            return_bytes: If True, return bytes instead of saving to file
            streaming: If True, return decrypted bytes when auto_decrypt=True, or raw streaming iterator when auto_decrypt=False

        Returns:
            S3DownloadResult: Download info and decryption status (default)
            bytes: Raw decrypted content when return_bytes=True or streaming=True with auto_decrypt=True
            AsyncIterator[bytes]: Raw streaming iterator when streaming=True and auto_decrypt=False

        Raises:
            HippiusIPFSError: If IPFS download fails
            FileNotFoundError: If the output directory doesn't exist
            ValueError: If decryption fails
        """
        return await self.ipfs_client.s3_download(
            cid=cid,
            output_path=output_path,
            subaccount_id=subaccount_id,
            bucket_name=bucket_name,
            auto_decrypt=auto_decrypt,
            download_node=download_node,
            return_bytes=return_bytes,
            streaming=streaming,
        )
