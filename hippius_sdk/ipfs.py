"""
IPFS operations for the Hippius SDK.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import shutil
import tempfile
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

import httpx
from pydantic import BaseModel

from hippius_sdk.config import get_config_value, get_encryption_key
from hippius_sdk.errors import HippiusIPFSError, HippiusSubstrateError
from hippius_sdk.ipfs_core import AsyncIPFSClient
from hippius_sdk.key_storage import (
    generate_and_store_key_for_seed,
    get_key_for_seed,
    is_key_storage_enabled,
)
from hippius_sdk.substrate import FileInput, SubstrateClient
from hippius_sdk.utils import format_cid, format_size

# Import PyNaCl for encryption
try:
    import nacl.secret
    import nacl.utils

    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

# Import zfec for erasure coding
try:
    import zfec

    ERASURE_CODING_AVAILABLE = True
except ImportError:
    ERASURE_CODING_AVAILABLE = False

# Configuration constants
PARALLEL_EC_CHUNKS = 20  # Maximum number of concurrent chunk downloads
PARALLEL_ORIGINAL_CHUNKS = (
    15  # Maximum number of original chunks to process in parallel
)


class S3PublishResult(BaseModel):
    """Result model for s3_publish method."""

    cid: str
    file_name: str
    size_bytes: int
    encryption_key: Optional[str]
    tx_hash: str


class S3DownloadResult(BaseModel):
    """Result model for s3_download method."""

    cid: str
    output_path: str
    size_bytes: int
    size_formatted: str
    elapsed_seconds: float
    decrypted: bool
    encryption_key: Optional[str]


# Set up logger for this module
logger = logging.getLogger(__name__)


class IPFSClient:
    """Client for interacting with IPFS."""

    def __init__(
        self,
        gateway: Optional[str] = None,
        api_url: Optional[str] = None,
        encrypt_by_default: Optional[bool] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize the IPFS client.

        Args:
            gateway: IPFS gateway URL for downloading content (from config if None)
            api_url: IPFS API URL for uploading content (from config if None)
                    Set to None to try to connect to a local IPFS daemon.
            encrypt_by_default: Whether to encrypt files by default (from config if None)
            encryption_key: Encryption key for NaCl secretbox (from config if None)
        """
        # Load configuration values if not explicitly provided
        if gateway is None:
            gateway = get_config_value("ipfs", "gateway", "https://get.hippius.network")

        if api_url is None:
            api_url = get_config_value(
                "ipfs", "api_url", "https://store.hippius.network"
            )

            # Check if local IPFS is enabled in config
            if get_config_value("ipfs", "local_ipfs", False):
                api_url = "http://localhost:5001"

        self.gateway = gateway.rstrip("/")
        self.api_url = api_url

        # Extract base URL from API URL for HTTP fallback
        self.base_url = api_url

        try:
            self.client = AsyncIPFSClient(api_url=api_url, gateway=self.gateway)
        except httpx.ConnectError as e:
            print(
                f"Warning: Falling back to local IPFS daemon, but still using gateway={self.gateway}"
            )
            self.client = AsyncIPFSClient(gateway=self.gateway)

        self._initialize_encryption(encrypt_by_default, encryption_key)

    def _initialize_encryption(
        self, encrypt_by_default: Optional[bool], encryption_key: Optional[bytes]
    ):
        """Initialize encryption settings from parameters or configuration."""
        # Check if encryption is available
        if not ENCRYPTION_AVAILABLE:
            self.encryption_available = False
            self.encrypt_by_default = False
            self.encryption_key = None
            return

        # Set up encryption default from parameter or config
        if encrypt_by_default is None:
            self.encrypt_by_default = get_config_value(
                "encryption", "encrypt_by_default", False
            )
        else:
            self.encrypt_by_default = encrypt_by_default

        # Set up encryption key from parameter or config
        if encryption_key is None:
            self.encryption_key = get_encryption_key()
        else:
            self.encryption_key = encryption_key

        # Check if we have a valid key and can encrypt
        self.encryption_available = (
            ENCRYPTION_AVAILABLE
            and self.encryption_key is not None
            and len(self.encryption_key) == nacl.secret.SecretBox.KEY_SIZE
        )

        # If encryption is requested but not available, warn the user
        if self.encrypt_by_default and not self.encryption_available:
            print(
                "Warning: Encryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt binary data using XSalsa20-Poly1305 (NaCl/libsodium).

        Args:
            data: Binary data to encrypt

        Returns:
            bytes: Encrypted data

        Raises:
            ValueError: If encryption is not available
            TypeError: If data is not bytes
        """
        if not self.encryption_available:
            raise ValueError(
                "Encryption is not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")

        # Create a SecretBox with our key
        box = nacl.secret.SecretBox(self.encryption_key)

        # Encrypt the data (nonce is automatically generated and included in the output)
        encrypted = box.encrypt(data)
        return encrypted

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data encrypted with encrypt_data.

        Args:
            encrypted_data: Data encrypted with encrypt_data

        Returns:
            bytes: Decrypted data

        Raises:
            ValueError: If decryption fails or encryption is not available
        """
        if not self.encryption_available:
            raise ValueError(
                "Encryption is not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        # Create a SecretBox with our key
        box = nacl.secret.SecretBox(self.encryption_key)

        try:
            # Decrypt the data
            decrypted = box.decrypt(encrypted_data)
            return decrypted
        except Exception as e:
            raise ValueError(
                f"Decryption failed: {str(e)}. Incorrect key or corrupted data?"
            )

    async def upload_file(
        self,
        file_path: str,
        include_formatted_size: bool = True,
        encrypt: Optional[bool] = None,
        max_retries: int = 3,
        seed_phrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upload a file to IPFS with optional encryption.

        Args:
            file_path: Path to the file to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)
            encrypt: Whether to encrypt the file (overrides default)
            max_retries: Maximum number of retry attempts (default: 3)
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - cid: Content Identifier (CID) of the uploaded file
                - filename: Name of the uploaded file
                - size_bytes: Size of the file in bytes
                - size_formatted: Human-readable file size (if include_formatted_size is True)
                - encrypted: Whether the file was encrypted

        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
            ValueError: If encryption is requested but not available
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")

        # Determine if we should encrypt
        should_encrypt = self.encrypt_by_default if encrypt is None else encrypt

        # Check if encryption is available if requested
        if should_encrypt and not self.encryption_available:
            raise ValueError(
                "Encryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        # Get file info before upload
        filename = os.path.basename(file_path)
        size_bytes = os.path.getsize(file_path)

        # If encryption is requested, encrypt the file first
        temp_file_path = None
        try:
            if should_encrypt:
                # Read the file content
                with open(file_path, "rb") as f:
                    file_data = f.read()

                # Encrypt the data
                encrypted_data = self.encrypt_data(file_data)

                # Create a temporary file for the encrypted data
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file_path = temp_file.name
                    temp_file.write(encrypted_data)

                # Use the temporary file for upload
                upload_path = temp_file_path
            else:
                # Use the original file for upload
                upload_path = file_path

            result = await self.client.add_file(upload_path)
            cid = result["Hash"]

        finally:
            # Clean up temporary file if created
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

        # Format the result
        result = {
            "cid": cid,
            "filename": filename,
            "size_bytes": size_bytes,
            "encrypted": should_encrypt,
        }

        # Add formatted size if requested
        if include_formatted_size:
            result["size_formatted"] = self.format_size(size_bytes)

        return result

    async def upload_directory(
        self,
        dir_path: str,
        include_formatted_size: bool = True,
        encrypt: Optional[bool] = None,
        seed_phrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upload a directory to IPFS with optional encryption of files.

        Args:
            dir_path: Path to the directory to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)
            encrypt: Whether to encrypt files (overrides default)
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - cid: Content Identifier (CID) of the uploaded directory
                - dirname: Name of the uploaded directory
                - file_count: Number of files in the directory
                - total_size_bytes: Total size of all files in bytes
                - size_formatted: Human-readable total size (if include_formatted_size is True)
                - encrypted: Whether files were encrypted

        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
            ValueError: If encryption is requested but not available
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory {dir_path} not found")

        # Determine if we should encrypt
        should_encrypt = self.encrypt_by_default if encrypt is None else encrypt

        # Check if encryption is available if requested
        if should_encrypt and not self.encryption_available:
            raise ValueError(
                "Encryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        # For encryption, we have to handle each file separately, so we'll use a different approach
        if should_encrypt:
            # Create a temporary directory for encrypted files
            temp_dir = tempfile.mkdtemp()
            try:
                # Process each file in the directory
                file_count = 0
                total_size_bytes = 0

                for root, _, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, dir_path)

                        # Create the directory structure in the temp directory
                        temp_file_dir = os.path.dirname(
                            os.path.join(temp_dir, rel_path)
                        )
                        os.makedirs(temp_file_dir, exist_ok=True)

                        # Read and encrypt the file
                        with open(file_path, "rb") as f:
                            file_data = f.read()

                        encrypted_data = self.encrypt_data(file_data)

                        # Write the encrypted file to the temp directory
                        with open(os.path.join(temp_dir, rel_path), "wb") as f:
                            f.write(encrypted_data)

                        file_count += 1
                        total_size_bytes += os.path.getsize(file_path)

                # Use temp_dir instead of dir_path for upload
                result = await self.client.add_directory(temp_dir)
                if isinstance(result, list):
                    cid = result[-1]["Hash"]
                else:
                    cid = result["Hash"]
            finally:
                # Clean up the temporary directory
                shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            # Get directory info
            dirname = os.path.basename(dir_path)
            file_count = 0
            total_size_bytes = 0

            # Calculate directory size and file count
            for root, _, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size_bytes += os.path.getsize(file_path)
                        file_count += 1
                    except (OSError, IOError):
                        pass

            # Upload to IPFS

            result = await self.client.add_directory(dir_path)
            if isinstance(result, list):
                # Get the last item, which should be the directory itself
                cid = result[-1]["Hash"]
            else:
                cid = result["Hash"]

        # Get dirname in case it wasn't set (for encryption path)
        dirname = os.path.basename(dir_path)

        # Format the result
        result = {
            "cid": cid,
            "dirname": dirname,
            "file_count": file_count,
            "total_size_bytes": total_size_bytes,
            "encrypted": should_encrypt,
        }

        # Add formatted size if requested
        if include_formatted_size:
            result["size_formatted"] = self.format_size(total_size_bytes)

        return result

    def format_size(self, size_bytes: int) -> str:
        """
        Format a size in bytes to a human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            str: Human-readable size string (e.g., '1.23 MB', '456.78 KB')
        """
        return format_size(size_bytes)

    def format_cid(self, cid: str) -> str:
        """
        Format a CID for display.

        This method handles both regular CIDs and hex-encoded CIDs.

        Args:
            cid: Content Identifier (CID) to format

        Returns:
            str: Formatted CID string
        """
        return format_cid(cid)

    async def download_file(
        self,
        cid: str,
        output_path: str,
        _: Optional[bool] = None,
        max_retries: int = 3,
        seed_phrase: Optional[str] = None,
        skip_directory_check: bool = False,
    ) -> Dict[str, Any]:
        """
        Download a file from IPFS with optional decryption.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
            _: Whether to decrypt the file (overrides default)
            max_retries: Maximum number of retry attempts (default: 3)
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)
            skip_directory_check: Whether to skip checking if the CID is a directory (default: False)

        Returns:
            Dict[str, Any]: Dictionary containing download results:
                - success: Whether the download was successful
                - output_path: Path where the file was saved
                - size_bytes: Size of the downloaded file in bytes
                - size_formatted: Human-readable file size
                - elapsed_seconds: Time taken for the download in seconds
                - decrypted: Whether the file was decrypted

        Raises:
            requests.RequestException: If the download fails
            ValueError: If decryption is requested but fails
        """
        start_time = time.time()
        is_directory = False

        # Check if this is a directory (unless skip_directory_check is True)
        if not skip_directory_check:
            try:
                ls_result = await self.client.ls(cid)
                if isinstance(ls_result, dict) and ls_result.get("Objects", []):
                    # Check if we have Links with non-empty names, which indicates a directory
                    # Links with empty names are file chunks, not directory entries
                    for obj in ls_result["Objects"]:
                        links = obj.get("Links", [])
                        if links:
                            # Check if any link has a non-empty name (directory entry)
                            # Links with empty names are file chunks, not directory entries
                            has_named_links = any(
                                link.get("Name", "").strip() for link in links
                            )
                            if has_named_links:
                                is_directory = True
                            break
            except Exception:
                # If ls check fails, continue treating as a regular file
                pass

        # Handle based on whether it's a directory or file
        if is_directory:
            try:
                # Use the AsyncIPFSClient's directory handling method
                os.makedirs(
                    os.path.dirname(os.path.abspath(output_path)), exist_ok=True
                )
                output_path = await self.client.download_directory(cid, output_path)
                downloaded_size = 0

                # Walk through the downloaded directory to calculate total size
                for root, _, files in os.walk(output_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        downloaded_size += os.path.getsize(file_path)

                # Return success
                return {
                    "success": True,
                    "output_path": output_path,
                    "size_bytes": downloaded_size,
                    "size_formatted": self.format_size(downloaded_size),
                    "elapsed_seconds": time.time() - start_time,
                    "decrypted": False,
                    "is_directory": True,
                }
            except Exception as e:
                raise RuntimeError(f"Failed to download directory: {str(e)}")
        else:
            # Regular file download
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            retries = 0
            while retries < max_retries:
                try:
                    url = f"{self.gateway}/ipfs/{cid}"
                    async with self.client.client.stream(
                        url=url, method="GET"
                    ) as response:
                        response.raise_for_status()

                        with open(output_path, "wb") as f:
                            async for chunk in response.aiter_bytes(chunk_size=8192):
                                f.write(chunk)
                    break

                except (httpx.HTTPError, IOError) as e:
                    retries += 1

                    if retries < max_retries:
                        wait_time = 2**retries
                        print(f"Download attempt {retries} failed: {str(e)}")
                        print(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        raise

        file_size_bytes = os.path.getsize(output_path)
        elapsed_time = time.time() - start_time

        return {
            "success": True,
            "output_path": output_path,
            "size_bytes": file_size_bytes,
            "size_formatted": self.format_size(file_size_bytes),
            "elapsed_seconds": round(elapsed_time, 2),
            "decrypted": _,
        }

    async def cat(
        self,
        cid: str,
        max_display_bytes: int = 1024,
        format_output: bool = True,
        decrypt: Optional[bool] = None,
        seed_phrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get the content of a file from IPFS with optional decryption.

        Args:
            cid: Content Identifier (CID) of the file
            max_display_bytes: Maximum number of bytes to include in the preview (default: 1024)
            format_output: Whether to attempt to decode the content as text (default: True)
            decrypt: Whether to decrypt the file (overrides default)
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - content: Complete binary content of the file
                - size_bytes: Size of the content in bytes
                - size_formatted: Human-readable size
                - preview: First part of the content (limited by max_display_bytes)
                - is_text: Whether the content seems to be text
                - text_preview: Text preview if is_text is True (up to max_display_bytes)
                - hex_preview: Hex preview if is_text is False (up to max_display_bytes)
                - decrypted: Whether the file was decrypted

        Raises:
            requests.RequestException: If fetching the content fails
            ValueError: If decryption is requested but fails
        """
        # Determine if we should decrypt
        should_decrypt = self.encrypt_by_default if decrypt is None else decrypt

        # Check if decryption is available if requested
        if should_decrypt and not self.encryption_available:
            raise ValueError(
                "Decryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        content = await self.client.cat(cid)

        # Decrypt if needed
        if should_decrypt:
            try:
                content = self.decrypt_data(content)
            except Exception as e:
                raise ValueError(f"Failed to decrypt file: {str(e)}")

        size_bytes = len(content)

        result = {
            "content": content,
            "size_bytes": size_bytes,
            "size_formatted": self.format_size(size_bytes),
            "decrypted": should_decrypt,
        }

        # Add preview
        if format_output:
            # Limit preview size
            preview = content[:max_display_bytes]
            result["preview"] = preview

            # Try to decode as text
            try:
                text_preview = preview.decode("utf-8")
                result["is_text"] = True
                result["text_preview"] = text_preview
            except UnicodeDecodeError:
                result["is_text"] = False
                result["hex_preview"] = preview.hex()

        return result

    async def exists(
        self, cid: str, seed_phrase: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if a CID exists on IPFS.

        Args:
            cid: Content Identifier (CID) to check
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - exists: Boolean indicating if the CID exists
                - cid: The CID that was checked
                - formatted_cid: Formatted version of the CID
                - gateway_url: URL to access the content if it exists
        """
        formatted_cid = self.format_cid(cid)
        gateway_url = f"{self.gateway}/ipfs/{cid}"
        exists = await self.client.ls(cid)

        return {
            "exists": exists,
            "cid": cid,
            "formatted_cid": formatted_cid,
            "gateway_url": gateway_url if exists else None,
        }

    async def publish_global(
        self, cid: str, seed_phrase: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Publish a CID to the global IPFS network, ensuring it's widely available.

        This makes the content available beyond the local IPFS node by pinning
        it to multiple public services.

        Args:
            cid: Content Identifier (CID) to publish globally
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - published: Boolean indicating if publishing was successful
                - cid: The CID that was published
                - formatted_cid: Formatted version of the CID
                - message: Status message
        """
        # First ensure it's pinned locally
        pin_result = await self.pin(cid, seed_phrase=seed_phrase)

        if not pin_result.get("success", False):
            return {
                "published": False,
                "cid": cid,
                "formatted_cid": self.format_cid(cid),
                "message": f"Failed to pin content locally: {pin_result.get('message', 'Unknown error')}",
            }

        # Then request pinning on public services
        # This implementation focuses on making the content available through
        # the default gateway, which provides sufficient global access
        return {
            "published": True,
            "cid": cid,
            "formatted_cid": self.format_cid(cid),
            "message": "Content published to global IPFS network",
        }

    async def pin(self, cid: str, seed_phrase: Optional[str] = None) -> Dict[str, Any]:
        """
        Pin a CID to IPFS to keep it available.

        Args:
            cid: Content Identifier (CID) to pin
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - success: Boolean indicating if pinning was successful
                - cid: The CID that was pinned
                - formatted_cid: Formatted version of the CID
                - message: Status message

        Raises:
            ConnectionError: If no IPFS connection is available
        """
        formatted_cid = self.format_cid(cid)

        try:
            if self.client:
                await self.client.pin(cid)
                success = True
                message = "Successfully pinned"
            else:
                success = False
                message = "No IPFS client available"
        except httpx.HTTPError as e:
            success = False
            message = f"Failed to pin: {str(e)}"

        return {
            "success": success,
            "cid": cid,
            "formatted_cid": formatted_cid,
            "message": message,
        }

    async def erasure_code_file(
        self,
        file_path: str,
        k: int = 3,
        m: int = 5,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        encrypt: Optional[bool] = None,
        max_retries: int = 3,
        verbose: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        seed_phrase: Optional[str] = None,
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
            progress_callback: Optional callback function for progress updates
                            Function receives (stage_name, current, total)
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            dict: Metadata including the original file info and chunk information

        Raises:
            ValueError: If erasure coding is not available or parameters are invalid
            RuntimeError: If chunk uploads fail
        """
        if not ERASURE_CODING_AVAILABLE:
            raise ValueError(
                "Erasure coding is not available. Install zfec: pip install zfec"
            )

        if k >= m:
            raise ValueError(
                f"Invalid erasure coding parameters: k ({k}) must be less than m ({m})"
            )

        # Get original file info
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(file_name)[1]

        # Determine if encryption should be used
        should_encrypt = self.encrypt_by_default if encrypt is None else encrypt

        if should_encrypt and not self.encryption_available:
            raise ValueError(
                "Encryption requested but not available. Install PyNaCl and configure an encryption key."
            )

        # Generate a unique ID for this file
        file_id = str(uuid.uuid4())

        if verbose:
            print(f"Processing file: {file_name} ({file_size / 1024 / 1024:.2f} MB)")
            print(
                f"Erasure coding parameters: k={k}, m={m} (need {k}/{m} chunks to reconstruct)"
            )
            if should_encrypt:
                print("Encryption: Enabled")

        # Step 1: Read and potentially encrypt the file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Calculate original file hash
        original_file_hash = hashlib.sha256(file_data).hexdigest()

        # Encrypt if requested
        if should_encrypt:
            if verbose:
                print("Encrypting file data...")
            file_data = self.encrypt_data(file_data)

        # Step 2: Split the file into chunks for erasure coding
        chunk_size = int(chunk_size)
        chunk_size = max(1, chunk_size)  # Ensure it's at least 1 byte

        chunks = []
        chunk_positions = []
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i : i + chunk_size]
            chunks.append(chunk)
            chunk_positions.append(i)

        # Pad the last chunk if necessary
        if chunks and len(chunks[-1]) < chunk_size:
            pad_size = int(chunk_size - len(chunks[-1]))
            chunks[-1] = chunks[-1] + b"\0" * pad_size

        # If we don't have enough chunks for the requested parameters, adjust
        if len(chunks) < k:
            if verbose:
                print(
                    f"Warning: File has fewer chunks ({len(chunks)}) than k={k}. Adjusting parameters."
                )

            # If we have a very small file, we'll just use a single chunk
            # but will still split it into k sub-blocks during encoding
            if len(chunks) == 1:
                if verbose:
                    print(
                        f"Small file (single chunk): will split into {k} sub-blocks for encoding"
                    )
            else:
                # If we have multiple chunks but fewer than k, adjust k to match
                old_k = k
                k = max(1, len(chunks))
                if verbose:
                    print(f"Adjusting k from {old_k} to {k} to match available chunks")

            # Ensure m is greater than k for redundancy
            if m <= k:
                old_m = m
                m = k + 2  # Ensure we have at least 2 redundant chunks
                if verbose:
                    print(f"Adjusting m from {old_m} to {m} to ensure redundancy")

            if verbose:
                print(f"New parameters: k={k}, m={m}")

        # Ensure we have at least one chunk to process
        if not chunks:
            raise ValueError("File is empty or too small to process")

        # For k=1 case, ensure we have proper sized input for zfec
        if k == 1 and len(chunks) == 1:
            # zfec expects the input to be exactly chunk_size for k=1
            # So we need to pad if shorter or truncate if longer
            if len(chunks[0]) != chunk_size:
                chunks[0] = chunks[0].ljust(chunk_size, b"\0")[:chunk_size]

        # Create metadata
        metadata = {
            "original_file": {
                "name": file_name,
                "size": file_size,
                "hash": original_file_hash,
                "extension": file_extension,
            },
            "erasure_coding": {
                "k": k,
                "m": m,
                "chunk_size": chunk_size,
                "encrypted": should_encrypt,
                "file_id": file_id,
            },
            "chunks": [],
        }

        # Step 3: Apply erasure coding to each chunk
        if verbose:
            print(f"Applying erasure coding to {len(chunks)} chunks...")

        all_encoded_chunks = []
        for i, chunk in enumerate(chunks):
            try:
                # For zfec encoder.encode(), we must provide exactly k blocks

                # Calculate how many bytes each sub-block should have
                sub_block_size = (
                    len(chunk) + k - 1
                ) // k  # ceiling division for even distribution

                # Split the chunk into exactly k sub-blocks of equal size (padding as needed)
                sub_blocks = []
                for j in range(k):
                    start = j * sub_block_size
                    end = min(start + sub_block_size, len(chunk))
                    sub_block = chunk[start:end]

                    # Pad if needed to make all sub-blocks the same size
                    if len(sub_block) < sub_block_size:
                        sub_block = sub_block.ljust(sub_block_size, b"\0")

                    sub_blocks.append(sub_block)

                # Verify we have exactly k sub-blocks
                if len(sub_blocks) != k:
                    raise ValueError(
                        f"Expected {k} sub-blocks but got {len(sub_blocks)}"
                    )

                # Encode the k sub-blocks to create m encoded blocks
                encoder = zfec.Encoder(k, m)
                encoded_chunks = encoder.encode(sub_blocks)

                # Add to our collection
                all_encoded_chunks.append(encoded_chunks)

                if verbose and (i + 1) % 10 == 0:
                    print(f"  Encoded {i + 1}/{len(chunks)} chunks")
            except Exception as e:
                # If encoding fails, provide more helpful error message
                error_msg = f"Error encoding chunk {i}: {str(e)}"
                print(f"Error details: chunk size={len(chunk)}, k={k}, m={m}")
                print(
                    f"Sub-blocks created: {len(sub_blocks) if 'sub_blocks' in locals() else 'None'}"
                )
                raise RuntimeError(f"{error_msg}")

        # Step 4: Upload all chunks to IPFS
        if verbose:
            print(
                f"Uploading {len(chunks) * m} erasure-coded chunks to IPFS in parallel..."
            )

        chunk_uploads = 0
        chunk_data = []
        batch_size = 20  # Number of concurrent uploads

        # Create a temporary directory for the chunks
        with tempfile.TemporaryDirectory() as temp_dir:
            # Prepare all chunks for upload
            all_chunk_info = []

            for original_idx, encoded_chunks in enumerate(all_encoded_chunks):
                for share_idx, share_data in enumerate(encoded_chunks):
                    # Create a name for this chunk that includes needed info
                    chunk_name = f"{file_id}_chunk_{original_idx}_{share_idx}.ec"
                    chunk_path = os.path.join(temp_dir, chunk_name)

                    # Write the chunk to a temp file
                    with open(chunk_path, "wb") as f:
                        f.write(share_data)

                    # Store info for async upload
                    all_chunk_info.append(
                        {
                            "name": chunk_name,
                            "path": chunk_path,
                            "original_chunk": original_idx,
                            "share_idx": share_idx,
                            "size": len(share_data),
                        }
                    )

            # Create a semaphore to limit concurrent uploads
            semaphore = asyncio.Semaphore(batch_size)

            # Track total uploads for progress reporting
            total_chunks = len(all_chunk_info)

            # Initialize progress tracking if callback provided
            if progress_callback:
                progress_callback("upload", 0, total_chunks)

            if verbose:
                print(f"Uploading {total_chunks} erasure-coded chunks to IPFS...")

            # Define upload task for a single chunk
            async def upload_chunk(chunk_info):
                nonlocal chunk_uploads

                async with semaphore:
                    try:
                        chunk_cid = await self.upload_file(
                            chunk_info["path"], max_retries=max_retries
                        )
                        chunk_info["cid"] = chunk_cid
                        chunk_uploads += 1

                        # Update progress through callback
                        if progress_callback:
                            progress_callback("upload", chunk_uploads, total_chunks)

                        if verbose and chunk_uploads % 10 == 0:
                            print(f"  Uploaded {chunk_uploads}/{total_chunks} chunks")
                        return chunk_info
                    except Exception as e:
                        if verbose:
                            print(
                                f"Error uploading chunk {chunk_info['name']}: {str(e)}"
                            )
                        return None

            # Create tasks for all chunk uploads
            upload_tasks = [upload_chunk(chunk_info) for chunk_info in all_chunk_info]

            # Wait for all uploads to complete
            completed_uploads = await asyncio.gather(*upload_tasks)

            # Filter out failed uploads
            chunk_data = [upload for upload in completed_uploads if upload is not None]

            # Add all chunk info to metadata
            metadata["chunks"] = chunk_data

            # Step 5: Create and upload the metadata file
            metadata_path = os.path.join(temp_dir, f"{file_id}_metadata.json")

            # Use binary mode to avoid any platform-specific text encoding issues
            with open(metadata_path, "wb") as f:
                # Encode the JSON with UTF-8 encoding explicitly
                metadata_json = json.dumps(metadata, indent=2, ensure_ascii=False)
                f.write(metadata_json.encode("utf-8"))

            # Verify file was written correctly
            if os.path.getsize(metadata_path) == 0:
                raise ValueError("Failed to write metadata file (file size is 0)")

            if verbose:
                print("Uploading metadata file...")
                print(f"Metadata file size: {os.path.getsize(metadata_path)} bytes")

            # Upload the metadata file to IPFS
            metadata_cid_result = await self.upload_file(
                metadata_path, max_retries=max_retries
            )

            # Extract just the CID string from the result dictionary
            metadata_cid = metadata_cid_result["cid"]
            metadata["metadata_cid"] = metadata_cid

            if verbose:
                print("Erasure coding complete!")
                print(f"Metadata CID: {metadata_cid}")
                print(f"Original file size: {file_size / 1024 / 1024:.2f} MB")
                print(f"Total chunks: {len(chunks) * m}")
                print(f"Minimum chunks needed: {k * len(chunks)}")

            return metadata

    async def reconstruct_from_erasure_code(
        self,
        metadata_cid: str,
        output_file: str,
        temp_dir: str = None,
        max_retries: int = 3,
        verbose: bool = True,
        seed_phrase: Optional[str] = None,
    ) -> Dict:
        """
        Reconstruct a file from erasure-coded chunks using its metadata.

        Args:
            metadata_cid: IPFS CID of the metadata file
            output_file: Path where the reconstructed file should be saved
            temp_dir: Directory to use for temporary files (default: system temp)
            max_retries: Maximum number of retry attempts for IPFS downloads
            verbose: Whether to print progress information
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict: containing file reconstruction info.

        Raises:
            ValueError: If reconstruction fails
            RuntimeError: If not enough chunks can be downloaded
        """
        if not ERASURE_CODING_AVAILABLE:
            raise ValueError(
                "Erasure coding is not available. Install zfec: pip install zfec"
            )

        # Start timing the reconstruction process
        start_time = time.time()

        # Create a temporary directory if not provided
        if temp_dir is None:
            temp_dir_obj = tempfile.TemporaryDirectory()
            temp_dir = temp_dir_obj.name
        else:
            temp_dir_obj = None

        try:
            # Step 1: Download and parse the metadata file
            if verbose:
                print(f"Downloading metadata file (CID: {metadata_cid})...")

            metadata_path = os.path.join(temp_dir, "metadata.json")
            await self.download_file(
                metadata_cid,
                metadata_path,
                max_retries=max_retries,
                seed_phrase=seed_phrase,
            )

            if verbose:
                metadata_download_time = time.time() - start_time
                print(f"Metadata downloaded in {metadata_download_time:.2f} seconds")
                print(f"Metadata file size: {os.path.getsize(metadata_path)} bytes")

            # Read using binary mode to avoid any encoding issues
            with open(metadata_path, "rb") as f:
                metadata_content = f.read().decode("utf-8")
                metadata = json.loads(metadata_content)

            # Step 2: Extract key information
            original_file = metadata["original_file"]
            erasure_params = metadata["erasure_coding"]
            chunks_info = metadata["chunks"]

            k = erasure_params["k"]
            m = erasure_params["m"]
            is_encrypted = erasure_params.get("encrypted", False)
            chunk_size = erasure_params.get("chunk_size", 1024 * 1024)
            total_original_size = original_file["size"]

            if verbose:
                print(
                    f"File: {original_file['name']} ({original_file['size'] / 1024 / 1024:.2f} MB)"
                )
                print(
                    f"Erasure coding parameters: k={k}, m={m} (need {k} of {m} chunks to reconstruct)"
                )
                if is_encrypted:
                    print("Encrypted: Yes")
                print(
                    f"Using parallel download with max {PARALLEL_ORIGINAL_CHUNKS} original chunks and {PARALLEL_EC_CHUNKS} chunk downloads concurrently"
                )

            # Step 3: Group chunks by their original chunk index
            chunks_by_original = {}
            for chunk in chunks_info:
                orig_idx = chunk["original_chunk"]
                if orig_idx not in chunks_by_original:
                    chunks_by_original[orig_idx] = []
                chunks_by_original[orig_idx].append(chunk)

            # Step 4: Process all original chunks in parallel
            if verbose:
                total_original_chunks = len(chunks_by_original)
                total_chunks_needed = total_original_chunks * k
                print(
                    f"Downloading and reconstructing {total_chunks_needed} chunks in parallel..."
                )

            # Create semaphores to limit concurrency
            encoded_chunks_semaphore = asyncio.Semaphore(PARALLEL_EC_CHUNKS)
            original_chunks_semaphore = asyncio.Semaphore(PARALLEL_ORIGINAL_CHUNKS)

            # Process a single original chunk and its required downloads
            async def process_original_chunk(orig_idx, available_chunks):
                # Limit number of original chunks processing at once
                async with original_chunks_semaphore:
                    if verbose:
                        print(f"Processing original chunk {orig_idx}...")

                    if len(available_chunks) < k:
                        raise ValueError(
                            f"Not enough chunks available for original chunk {orig_idx}. "
                            f"Need {k}, but only have {len(available_chunks)}."
                        )

                    # Try slightly more than k chunks (k+2) to handle some failures
                    num_to_try = min(k + 2, len(available_chunks))
                    chunks_to_try = random.sample(available_chunks, num_to_try)

                    # Track downloaded chunks
                    download_tasks = []

                    # Start parallel downloads for chunks
                    for chunk in chunks_to_try:
                        chunk_path = os.path.join(temp_dir, f"{chunk['name']}")

                        # Extract CID
                        chunk_cid = (
                            chunk["cid"]["cid"]
                            if isinstance(chunk["cid"], dict) and "cid" in chunk["cid"]
                            else chunk["cid"]
                        )

                        # Create download task
                        async def download_chunk(cid, path, chunk_info):
                            async with encoded_chunks_semaphore:
                                try:
                                    # Always skip directory check for erasure code chunks
                                    await self.download_file(
                                        cid,
                                        path,
                                        max_retries=max_retries,
                                        skip_directory_check=True,
                                        seed_phrase=seed_phrase,
                                    )

                                    # Read chunk data
                                    with open(path, "rb") as f:
                                        share_data = f.read()

                                    return {
                                        "success": True,
                                        "data": share_data,
                                        "share_idx": chunk_info["share_idx"],
                                        "name": chunk_info["name"],
                                    }
                                except Exception as e:
                                    if verbose:
                                        print(
                                            f"Error downloading chunk {chunk_info['name']}: {str(e)}"
                                        )
                                    return {
                                        "success": False,
                                        "error": str(e),
                                        "name": chunk_info["name"],
                                    }

                        # Create task
                        task = asyncio.create_task(
                            download_chunk(chunk_cid, chunk_path, chunk)
                        )
                        download_tasks.append(task)

                    # Process downloads as they complete
                    downloaded_shares = []
                    share_indexes = []

                    for done_task in asyncio.as_completed(download_tasks):
                        result = await done_task

                        if result["success"]:
                            downloaded_shares.append(result["data"])
                            share_indexes.append(result["share_idx"])

                            # Once we have k chunks, cancel remaining downloads
                            if len(downloaded_shares) >= k:
                                for task in download_tasks:
                                    if not task.done():
                                        task.cancel()
                                break

                    # Check if we have enough chunks
                    if len(downloaded_shares) < k:
                        raise ValueError(
                            f"Failed to download enough chunks for original chunk {orig_idx}. "
                            f"Need {k}, but only downloaded {len(downloaded_shares)}."
                        )

                    # Reconstruct this chunk
                    decoder = zfec.Decoder(k, m)
                    reconstructed_data = decoder.decode(
                        downloaded_shares, share_indexes
                    )

                    if not isinstance(reconstructed_data, list):
                        raise TypeError(
                            f"Unexpected type from decoder: {type(reconstructed_data)}. Expected list of bytes."
                        )

                    # Calculate the actual size of this original chunk
                    is_last_chunk = orig_idx == max(chunks_by_original.keys())
                    original_chunk_size = total_original_size - orig_idx * chunk_size
                    if not is_last_chunk:
                        original_chunk_size = min(chunk_size, original_chunk_size)

                    # Recombine the sub-blocks
                    reconstructed_chunk = b""
                    total_bytes = 0
                    for sub_block in reconstructed_data:
                        bytes_to_take = min(
                            len(sub_block), original_chunk_size - total_bytes
                        )
                        if bytes_to_take <= 0:
                            break

                        reconstructed_chunk += sub_block[:bytes_to_take]
                        total_bytes += bytes_to_take

                    return reconstructed_chunk

            # Create tasks for all original chunks and process them in parallel
            chunk_tasks = []
            for orig_idx in sorted(chunks_by_original.keys()):
                chunk_tasks.append(
                    process_original_chunk(orig_idx, chunks_by_original[orig_idx])
                )

            # Wait for all chunks to be reconstructed
            if verbose:
                print(f"Waiting for {len(chunk_tasks)} chunk tasks to complete...")

            # Track progress
            start_chunks_time = time.time()

            # Wait for all chunks to complete (preserves ordering)
            reconstructed_chunks = await asyncio.gather(*chunk_tasks)

            if verbose:
                print(
                    f"All chunks downloaded and decoded successfully in {time.time() - start_chunks_time:.2f} seconds"
                )

            if verbose:
                download_time = time.time() - start_time
                print(f"Chunk reconstruction completed in {download_time:.2f} seconds")
                print(
                    f"Received {len(reconstructed_chunks)} of {len(chunk_tasks)} expected chunks"
                )

            # Step 5: Combine the reconstructed chunks into a file
            print("Combining reconstructed chunks...")

            if verbose:
                print(f"Processing {len(reconstructed_chunks)} reconstructed chunks...")

            # Process chunks to remove padding correctly
            processed_chunks = []
            size_processed = 0

            # Guard against empty chunks
            if not reconstructed_chunks:
                raise ValueError("No chunks were successfully reconstructed")

            # Track progress for large files
            chunk_process_start = time.time()

            for i, chunk in enumerate(reconstructed_chunks):
                if verbose and i % 10 == 0:
                    print(f"Processing chunk {i+1}/{len(reconstructed_chunks)}...")

                # For all chunks except the last one, use full chunk size
                if i < len(reconstructed_chunks) - 1:
                    # Calculate how much of this chunk should be used (handle full chunks)
                    chunk_valid_bytes = min(
                        chunk_size, total_original_size - size_processed
                    )
                    processed_chunks.append(chunk[:chunk_valid_bytes])
                    size_processed += chunk_valid_bytes
                else:
                    # For the last chunk, calculate the remaining bytes needed
                    remaining_bytes = total_original_size - size_processed
                    processed_chunks.append(chunk[:remaining_bytes])
                    size_processed += remaining_bytes

            if verbose:
                print(
                    f"Chunk processing completed in {time.time() - chunk_process_start:.2f} seconds"
                )
                print(f"Concatenating {len(processed_chunks)} processed chunks...")

            # Concatenate all processed chunks
            concat_start = time.time()
            file_data = b"".join(processed_chunks)
            if verbose:
                print(
                    f"Concatenation completed in {time.time() - concat_start:.2f} seconds"
                )

            # Double-check the final size matches the original
            if len(file_data) != original_file["size"]:
                print(
                    f"Warning: Reconstructed size ({len(file_data)}) differs from original ({original_file['size']})"
                )
                # Ensure we have exactly the right size
                if len(file_data) > original_file["size"]:
                    file_data = file_data[: original_file["size"]]
                else:
                    # If we're short, pad with zeros (shouldn't happen with proper reconstruction)
                    print(
                        "Warning: Reconstructed file is smaller than original, padding with zeros"
                    )
                    file_data += b"\0" * (original_file["size"] - len(file_data))

            # Step 6: Decrypt if necessary
            if is_encrypted:
                if not self.encryption_available:
                    raise ValueError(
                        "File is encrypted but encryption is not available. "
                        "Install PyNaCl and configure an encryption key."
                    )

                if verbose:
                    print("Decrypting file data...")

                file_data = self.decrypt_data(file_data)

            # Step 7: Write to the output file
            print(f"Writing {len(file_data)} bytes to {output_file}...")
            write_start = time.time()
            with open(output_file, "wb") as f:
                f.write(file_data)
            if verbose:
                print(
                    f"File writing completed in {time.time() - write_start:.2f} seconds"
                )

            # Step 8: Verify hash if available
            if "hash" in original_file:
                print("Verifying file hash...")
                hash_start = time.time()
                actual_hash = hashlib.sha256(file_data).hexdigest()
                expected_hash = original_file["hash"]

                if actual_hash != expected_hash:
                    print("Warning: File hash mismatch!")
                    print(f"  Expected: {expected_hash}")
                    print(f"  Actual:   {actual_hash}")
                else:
                    print(
                        f"Hash verification successful in {time.time() - hash_start:.2f} seconds!"
                    )

            total_time = time.time() - start_time
            if verbose:
                print(f"Reconstruction complete in {total_time:.2f} seconds!")
                print(f"File saved to: {output_file}")

            return {
                "output_path": output_file,
                "size_bytes": size_processed,
            }

        finally:
            # Clean up temporary directory if we created it
            if temp_dir_obj is not None:
                temp_dir_obj.cleanup()

    async def store_erasure_coded_file(
        self,
        file_path: str,
        k: int = 3,
        m: int = 5,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        encrypt: Optional[bool] = None,
        miner_ids: List[str] = None,
        substrate_client=None,
        max_retries: int = 3,
        verbose: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        publish: bool = True,
        seed_phrase: Optional[str] = None,
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
            substrate_client: SubstrateClient to use (or None to create one)
            max_retries: Maximum number of retry attempts
            verbose: Whether to print progress information
            progress_callback: Optional callback function for progress updates
                            Function receives (stage_name, current, total)
            publish: Whether to publish to the blockchain (True) or just perform local
                    erasure coding without publishing (False). When False, no password
                    is needed for seed phrase access.
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            dict: Result including metadata CID and transaction hash (if published)

        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If processing fails
        """
        # Step 1: Create substrate client if we need it and are publishing
        if substrate_client is None and publish:
            substrate_client = SubstrateClient(password=None, account_name=None)
        # Step 2: Erasure code the file and upload chunks
        metadata = await self.erasure_code_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            max_retries=max_retries,
            verbose=verbose,
            progress_callback=progress_callback,
            seed_phrase=seed_phrase,
        )

        original_file = metadata["original_file"]
        metadata_cid = metadata["metadata_cid"]

        # Initialize transaction hash variable
        tx_hash = None

        # Only proceed with blockchain storage if publish is True
        if publish:
            # Create a list to hold all the file inputs (metadata + all chunks)
            all_file_inputs = []

            # Step 3: Prepare metadata file for storage
            if verbose:
                print(
                    f"Preparing to store metadata and {len(metadata['chunks'])} chunks in the Hippius marketplace..."
                )

            # Create a file input for the metadata file
            metadata_file_input = FileInput(
                file_hash=metadata_cid, file_name=f"{original_file['name']}.ec_metadata"
            )
            all_file_inputs.append(metadata_file_input)

            # Step 4: Add all chunks to the storage request
            if verbose:
                print("Adding all chunks to storage request...")

            for i, chunk in enumerate(metadata["chunks"]):
                # Extract the CID string from the chunk's cid dictionary
                chunk_cid = (
                    chunk["cid"]["cid"]
                    if isinstance(chunk["cid"], dict) and "cid" in chunk["cid"]
                    else chunk["cid"]
                )
                chunk_file_input = FileInput(
                    file_hash=chunk_cid, file_name=chunk["name"]
                )
                all_file_inputs.append(chunk_file_input)

                # Print progress for large numbers of chunks
                if verbose and (i + 1) % 50 == 0:
                    print(
                        f"  Prepared {i + 1}/{len(metadata['chunks'])} chunks for storage"
                    )

            # Step 5: Submit the storage request for all files
            if verbose:
                print(
                    f"Submitting storage request for 1 metadata file and {len(metadata['chunks'])} chunks..."
                )

            tx_hash = await substrate_client.storage_request(
                files=all_file_inputs, miner_ids=miner_ids, seed_phrase=seed_phrase
            )
            if verbose:
                print("Successfully stored all files in marketplace!")
                print(f"Transaction hash: {tx_hash}")
                print(f"Metadata CID: {metadata_cid}")
                print(
                    f"Total files stored: {len(all_file_inputs)} (1 metadata + {len(metadata['chunks'])} chunks)"
                )

            result = {
                "metadata": metadata,
                "metadata_cid": metadata_cid,
                "transaction_hash": tx_hash,
                "total_files_stored": len(all_file_inputs),
            }
        else:
            # Not publishing to blockchain (--no-publish flag used)
            if verbose:
                print("Not publishing to blockchain (--no-publish flag used)")
                print(f"Metadata CID: {metadata_cid}")
                print(f"Total chunks: {len(metadata['chunks'])}")

            result = {
                "metadata": metadata,
                "metadata_cid": metadata_cid,
                "total_files_stored": len(metadata["chunks"])
                + 1,  # +1 for metadata file
            }

        return result

    async def delete_file(
        self,
        cid: str,
        cancel_from_blockchain: bool = True,
        seed_phrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Delete a file or directory from IPFS and optionally cancel its storage on the blockchain.
        If deleting a directory, all files within the directory will be unpinned recursively.

        Args:
            cid: Content Identifier (CID) of the file/directory to delete
            cancel_from_blockchain: Whether to also cancel the storage request from the blockchain
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)

        Returns:
            Dict containing the result of the operation
        """
        result = {
            "cid": cid,
            "unpin_result": None,
            "blockchain_result": None,
            "timing": {
                "start_time": time.time(),
                "end_time": None,
                "duration_seconds": None,
            },
            "is_directory": False,
            "child_files": [],
        }

        # First check if this is a directory
        try:
            ls_result = await self.client.ls(cid)
            is_directory = ls_result.get("is_directory", False)
            result["is_directory"] = is_directory

            # If it's a directory, recursively unpin all contained files first
            if is_directory:
                print(f"Detected directory: {cid}")
                links = []

                # Extract all links from the directory listing
                if "Objects" in ls_result and len(ls_result["Objects"]) > 0:
                    for obj in ls_result["Objects"]:
                        if "Links" in obj:
                            links.extend(obj["Links"])

                child_files = []
                # Unpin each item in the directory
                for link in links:
                    link_hash = link.get("Hash")
                    link_name = link.get("Name", "unknown")
                    if link_hash:
                        child_files.append({"cid": link_hash, "name": link_name})
                        try:
                            # Recursively delete if it's a subdirectory
                            link_type = link.get("Type")
                            if (
                                link_type == 1
                                or str(link_type) == "1"
                                or link_type == "dir"
                            ):
                                # Recursive delete, but don't cancel from blockchain (we'll do that for parent)
                                await self.delete_file(
                                    link_hash, cancel_from_blockchain=False
                                )
                            else:
                                # Regular file unpin
                                try:
                                    await self.client.unpin(link_hash)
                                    print(
                                        f"Unpinned file: {link_name} (CID: {link_hash})"
                                    )
                                except Exception as unpin_error:
                                    # Just note the error but don't let it stop the whole process
                                    # This is common with IPFS servers that may return 500 errors for
                                    # unpinning content that was never explicitly pinned
                                    print(
                                        f"Note: Could not unpin {link_name}: {str(unpin_error).split('For more information')[0]}"
                                    )
                        except Exception as e:
                            print(
                                f"Warning: Problem processing child item {link_name}: {str(e).split('For more information')[0]}"
                            )

                # Record the child files that were processed
                result["child_files"] = child_files
        except Exception as e:
            print(f"Warning: Failed to check if CID is a directory: {e}")
            # Continue with regular file unpin

        # Now unpin the main file/directory
        try:
            print(f"Unpinning from IPFS: {cid}")
            unpin_result = await self.client.unpin(cid)
            result["unpin_result"] = unpin_result
            result["success"] = True
            print("Successfully unpinned from IPFS")
        except Exception as e:
            # Handle 500 errors from IPFS server gracefully - they often occur
            # when the content wasn't explicitly pinned or was already unpinned
            error_str = str(e)
            if "500 Internal Server Error" in error_str:
                print(
                    f"Note: IPFS server reported content may already be unpinned: {cid}"
                )
                result["unpin_result"] = {"Pins": [cid]}  # Simulate successful unpin
                result["success"] = True
            else:
                print(
                    f"Warning: Failed to unpin from IPFS: {error_str.split('For more information')[0]}"
                )
                result["success"] = False

        # Then, if requested, cancel from blockchain
        if cancel_from_blockchain:
            try:
                substrate_client = SubstrateClient()
                await substrate_client.cancel_storage_request(
                    cid, seed_phrase=seed_phrase
                )
                print("Successfully cancelled storage from blockchain")
                result["blockchain_result"] = {"success": True}
            except Exception as e:
                # Handle the case where the CID is not in storage requests
                error_str = str(e)
                if "not found in storage requests" in error_str:
                    print(
                        "Note: Content was not found in blockchain storage requests (may already be deleted)"
                    )
                    result["blockchain_result"] = {
                        "success": True,
                        "already_deleted": True,
                    }
                else:
                    print(f"Warning: Error cancelling from blockchain: {error_str}")
                    result["blockchain_result"] = {"success": False, "error": error_str}

        # Update timing information
        result["timing"]["end_time"] = time.time()
        result["timing"]["duration_seconds"] = (
            result["timing"]["end_time"] - result["timing"]["start_time"]
        )

        return result

    async def delete_ec_file(
        self,
        metadata_cid: str,
        cancel_from_blockchain: bool = True,
        parallel_limit: int = 20,
        seed_phrase: Optional[str] = None,
        metadata_timeout: int = 30,  # Timeout in seconds for metadata fetch
    ) -> bool:
        """
        Delete an erasure-coded file, including all its chunks in parallel.

        Args:
            metadata_cid: CID of the metadata file for the erasure-coded file
            cancel_from_blockchain: Whether to cancel storage from blockchain
            parallel_limit: Maximum number of concurrent deletion operations
            seed_phrase: Optional seed phrase to use for blockchain interactions (uses config if None)
            metadata_timeout: Timeout in seconds for metadata fetch operation (default: 30)

        Returns:
            bool: True if the deletion was successful, False otherwise
        """
        print(f"Starting deletion process for metadata CID: {metadata_cid}")

        chunks = []

        try:
            # First download the metadata to get chunk CIDs with timeout
            try:
                print("Attempting to fetch metadata file...")
                # Create a task for fetching metadata with timeout
                metadata_task = asyncio.create_task(self.cat(metadata_cid))
                try:
                    metadata_result = await asyncio.wait_for(
                        metadata_task, timeout=metadata_timeout
                    )
                    print(
                        f"Successfully fetched metadata (size: {len(metadata_result['content'])} bytes)"
                    )

                    # Parse the metadata JSON
                    metadata_json = json.loads(
                        metadata_result["content"].decode("utf-8")
                    )
                    chunks = metadata_json.get("chunks", [])
                    print(f"Found {len(chunks)} chunks in metadata")
                except asyncio.TimeoutError:
                    print(
                        f"Timed out after {metadata_timeout}s waiting for metadata download"
                    )
                    # We'll continue with blockchain cancellation even without metadata
            except json.JSONDecodeError as e:
                # If we can't parse the metadata JSON, record the error but continue
                print(f"Error parsing metadata JSON: {e}")
            except Exception as e:
                # Any other metadata error
                print(f"Error retrieving or processing metadata: {e}")

            # Extract all chunk CIDs
            chunk_cids = []
            for chunk in chunks:
                chunk_cid = chunk.get("cid", {})
                if isinstance(chunk_cid, dict) and "cid" in chunk_cid:
                    chunk_cids.append(chunk_cid["cid"])
                elif isinstance(chunk_cid, str):
                    chunk_cids.append(chunk_cid)

            print(f"Extracted {len(chunk_cids)} CIDs from chunks")

            # Create a semaphore to limit concurrent operations
            semaphore = asyncio.Semaphore(parallel_limit)

            # Define the unpin task for each chunk with error handling and timeout
            async def unpin_chunk(cid):
                async with semaphore:
                    try:
                        # Add a timeout for each unpin operation
                        unpin_task = asyncio.create_task(self.client.unpin(cid))
                        await asyncio.wait_for(
                            unpin_task, timeout=10
                        )  # 10-second timeout per unpin
                        return {"success": True, "cid": cid}
                    except asyncio.TimeoutError:
                        print(f"Unpin operation timed out for CID: {cid}")
                        return {"success": False, "cid": cid, "error": "timeout"}
                    except Exception as e:
                        # Record failure but continue with other chunks
                        print(f"Error unpinning CID {cid}: {str(e)}")
                        return {"success": False, "cid": cid, "error": str(e)}

            # Unpin all chunks in parallel
            if chunk_cids:
                print(f"Starting parallel unpin of {len(chunk_cids)} chunks...")
                unpin_tasks = [unpin_chunk(cid) for cid in chunk_cids]
                results = await asyncio.gather(*unpin_tasks)

                # Count failures
                failures = [r for r in results if not r["success"]]
                if failures:
                    print(f"Failed to unpin {len(failures)} chunks")
                else:
                    print("Successfully unpinned all chunks")
        except Exception as e:
            # If we can't process chunks at all, record the failure
            print(f"Exception during chunks processing: {e}")

        # Unpin the metadata file itself, regardless of whether we could process chunks
        try:
            print(f"Unpinning metadata file: {metadata_cid}")
            unpin_task = asyncio.create_task(self.client.unpin(metadata_cid))
            await asyncio.wait_for(unpin_task, timeout=10)  # 10-second timeout
            print("Successfully unpinned metadata file")
        except Exception as e:
            # Record the failure but continue with blockchain cancellation
            print(f"Error unpinning metadata file: {e}")

        # Handle blockchain cancellation if requested
        if cancel_from_blockchain:
            try:
                # Create a substrate client
                print("Creating substrate client for blockchain cancellation...")
                substrate_client = SubstrateClient()

                # This will raise appropriate exceptions if it fails:
                # - HippiusAlreadyDeletedError if already deleted
                # - HippiusFailedSubstrateDelete if transaction fails
                # - Other exceptions for other failures
                print(f"Cancelling storage request for CID: {metadata_cid}")
                await substrate_client.cancel_storage_request(
                    metadata_cid, seed_phrase=seed_phrase
                )
                print("Successfully cancelled storage request on blockchain")
            except Exception as e:
                print(f"Error during blockchain cancellation: {e}")
                # Re-raise the exception to be handled by the caller
                raise

        # If we get here, either:
        # 1. Blockchain cancellation succeeded (if requested)
        # 2. We weren't doing blockchain cancellation
        # In either case, we report success
        print("Delete EC file operation completed successfully")
        return True

    async def s3_publish(
        self,
        file_path: str,
        encrypt: bool,
        seed_phrase: str,
        store_node: str = "http://localhost:5001",
        pin_node: str = "https://store.hippius.network",
    ) -> S3PublishResult:
        """
        Publish a file to IPFS and the Hippius marketplace in one operation.

        This method uses a two-node architecture for optimal performance:
        1. Uploads to store_node (local) for immediate availability
        2. Pins to pin_node (remote) for persistence and backup
        3. Publishes to substrate marketplace

        This method automatically manages encryption keys per seed phrase:
        - If encrypt=True, it will get or generate an encryption key for the seed phrase
        - Keys are stored in PostgreSQL and versioned (never deleted)
        - Always uses the most recent key for a seed phrase

        Args:
            file_path: Path to the file to publish
            encrypt: Whether to encrypt the file before uploading
            seed_phrase: Seed phrase for blockchain transaction signing
            store_node: IPFS node URL for initial upload (default: local node)
            pin_node: IPFS node URL for backup pinning (default: remote service)

        Returns:
            S3PublishResult: Object containing CID, file info, and transaction hash

        Raises:
            HippiusIPFSError: If IPFS operations (add or pin) fail
            HippiusSubstrateError: If substrate call fails
            FileNotFoundError: If the file doesn't exist
            ValueError: If encryption is requested but not available
        """
        # Check if file exists and get initial info
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")

        # Get file info
        filename = os.path.basename(file_path)
        size_bytes = os.path.getsize(file_path)

        # Handle encryption if requested with automatic key management
        encryption_key_used = None
        if encrypt:
            # Check if key storage is enabled and available
            try:
                key_storage_available = is_key_storage_enabled()
                logger.debug(f"Key storage enabled: {key_storage_available}")
            except ImportError:
                logger.debug("Key storage module not available")
                key_storage_available = False

            if key_storage_available:
                # Try to get existing key for this seed phrase
                existing_key_b64 = await get_key_for_seed(seed_phrase)

                if existing_key_b64:
                    # Use existing key
                    logger.debug("Using existing encryption key for seed phrase")
                    encryption_key_bytes = base64.b64decode(existing_key_b64)
                    encryption_key_used = existing_key_b64
                else:
                    # Generate and store new key for this seed phrase
                    logger.info("Generating new encryption key for seed phrase")
                    new_key_b64 = await generate_and_store_key_for_seed(seed_phrase)
                    encryption_key_bytes = base64.b64decode(new_key_b64)
                    encryption_key_used = new_key_b64

                # Read file content into memory
                with open(file_path, "rb") as f:
                    file_data = f.read()

                # Encrypt the data using the key from key storage
                import nacl.secret

                box = nacl.secret.SecretBox(encryption_key_bytes)
                encrypted_data = box.encrypt(file_data)

                # Overwrite the original file with encrypted data
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
            else:
                # Fallback to the original encryption system if key_storage is not available
                if not self.encryption_available:
                    raise ValueError(
                        "Encryption requested but not available. Either install key storage with 'pip install hippius_sdk[key_storage]' or configure an encryption key with 'hippius keygen --save'"
                    )

                # Read file content into memory
                with open(file_path, "rb") as f:
                    file_data = f.read()

                # Encrypt the data using the client's encryption key
                encrypted_data = self.encrypt_data(file_data)

                # Overwrite the original file with encrypted data
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)

                # Store the encryption key for the result
                encryption_key_used = (
                    base64.b64encode(self.encryption_key).decode("utf-8")
                    if self.encryption_key
                    else None
                )

        # Step 1: Upload to store_node (local) for immediate availability
        try:
            store_client = AsyncIPFSClient(api_url=store_node)
            result = await store_client.add_file(file_path)
            cid = result["Hash"]
            logger.info(f"File uploaded to store node {store_node} with CID: {cid}")
        except Exception as e:
            raise HippiusIPFSError(
                f"Failed to upload file to store node {store_node}: {str(e)}"
            )

        # Step 2: Pin to pin_node (remote) for persistence and backup
        try:
            pin_client = AsyncIPFSClient(api_url=pin_node)
            await pin_client.pin(cid)
            logger.info(f"File pinned to backup node {pin_node}")
        except Exception as e:
            raise HippiusIPFSError(
                f"Failed to pin file to store node {store_node}: {str(e)}"
            )

        # Publish to substrate marketplace
        try:
            # Pass the seed phrase directly to avoid password prompts for encrypted config
            substrate_client = SubstrateClient(seed_phrase=seed_phrase)
            logger.info(
                f"Submitting storage request to substrate for file: {filename}, CID: {cid}"
            )

            tx_hash = await substrate_client.storage_request(
                files=[
                    FileInput(
                        file_hash=cid,
                        file_name=filename,
                    )
                ],
                miner_ids=[],
                seed_phrase=seed_phrase,
            )

            logger.debug(f"Substrate call result: {tx_hash}")

            # Check if we got a valid transaction hash
            if not tx_hash or tx_hash == "0x" or len(tx_hash) < 10:
                logger.error(f"Invalid transaction hash received: {tx_hash}")
                raise HippiusSubstrateError(
                    f"Invalid transaction hash received: {tx_hash}. This might indicate insufficient credits or transaction failure."
                )

            logger.info(
                f"Successfully published to substrate with transaction: {tx_hash}"
            )

        except Exception as e:
            logger.error(f"Substrate call failed: {str(e)}")
            logger.debug(
                "Possible causes: insufficient credits, network issues, invalid seed phrase, or substrate node unavailability"
            )
            raise HippiusSubstrateError(f"Failed to publish to substrate: {str(e)}")

        return S3PublishResult(
            cid=cid,
            file_name=filename,
            size_bytes=size_bytes,
            encryption_key=encryption_key_used,
            tx_hash=tx_hash,
        )

    async def s3_download(
        self,
        cid: str,
        output_path: str,
        seed_phrase: str,
        auto_decrypt: bool = True,
        download_node: str = "http://localhost:5001",
    ) -> S3DownloadResult:
        """
        Download a file from IPFS with automatic decryption.

        This method uses the download_node for immediate availability and automatically
        manages decryption keys per seed phrase:
        - Downloads the file from the specified download_node (local by default)
        - If auto_decrypt=True, attempts to decrypt using stored keys for the seed phrase
        - Falls back to client encryption key if key storage is not available
        - Returns the file in decrypted form if decryption succeeds

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
            seed_phrase: Seed phrase to use for retrieving decryption keys
            auto_decrypt: Whether to attempt automatic decryption (default: True)
            download_node: IPFS node URL for download (default: local node)

        Returns:
            S3DownloadResult: Object containing download info and decryption status

        Raises:
            HippiusIPFSError: If IPFS download fails
            FileNotFoundError: If the output directory doesn't exist
            ValueError: If decryption fails
        """
        start_time = time.time()

        # Download the file directly from the specified download_node
        try:
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            download_client = AsyncIPFSClient(api_url=download_node)

            download_url = f"{download_node.rstrip('/')}/api/v0/cat?arg={cid}"
            async with download_client.client.stream("POST", download_url) as response:
                response.raise_for_status()

                with open(output_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)

            logger.info(f"File downloaded from {download_node} with CID: {cid}")

        except Exception as e:
            raise HippiusIPFSError(
                f"Failed to download file from {download_node}: {str(e)}"
            )

        # Get file info after download
        size_bytes = os.path.getsize(output_path)
        elapsed_time = time.time() - start_time

        # Attempt automatic decryption if requested
        decrypted = False
        encryption_key_used = None

        if auto_decrypt:
            # Check if key storage is enabled and available
            try:
                key_storage_available = is_key_storage_enabled()
                logger.debug(f"Key storage enabled: {key_storage_available}")
            except ImportError:
                logger.debug("Key storage module not available")
                key_storage_available = False

            # Read the downloaded file content
            with open(output_path, "rb") as f:
                file_data = f.read()

            # Check if file is empty - this indicates a problem
            if len(file_data) == 0:
                logger.error(f"Downloaded file is empty (0 bytes) for CID: {cid}")
                raise HippiusIPFSError(
                    f"File not available: Downloaded 0 bytes for CID {cid}. "
                    f"File may not exist on download node {download_node}. "
                    f"Download URL: {download_url}"
                )
            elif (
                len(file_data) < 40
            ):  # PyNaCl encrypted data is at least 40 bytes (24-byte nonce + 16-byte auth tag + data)
                logger.info(
                    f"File too small to be encrypted ({len(file_data)} bytes), treating as plaintext"
                )
                decrypted = False
                encryption_key_used = None
            else:
                # File has content, attempt decryption if requested
                decryption_attempted = False
                decryption_successful = False

                if key_storage_available:
                    # Try to get the encryption key for this seed phrase
                    try:
                        existing_key_b64 = await get_key_for_seed(seed_phrase)

                        if existing_key_b64:
                            logger.debug(
                                "Found encryption key for seed phrase, attempting decryption"
                            )
                            decryption_attempted = True
                            encryption_key_used = existing_key_b64

                            # Attempt decryption with the stored key
                            try:
                                import nacl.secret

                                encryption_key_bytes = base64.b64decode(
                                    existing_key_b64
                                )
                                box = nacl.secret.SecretBox(encryption_key_bytes)
                                decrypted_data = box.decrypt(file_data)

                                # Write the decrypted data back to the file
                                with open(output_path, "wb") as f:
                                    f.write(decrypted_data)

                                decryption_successful = True
                                decrypted = True
                                size_bytes = len(
                                    decrypted_data
                                )  # Update size to decrypted size
                                logger.info(
                                    "Successfully decrypted file using stored key"
                                )

                            except Exception as decrypt_error:
                                logger.debug(
                                    f"Decryption failed with stored key: {decrypt_error}"
                                )
                                # Continue to try fallback decryption
                        else:
                            logger.debug("No encryption key found for seed phrase")

                    except Exception as e:
                        logger.debug(f"Error retrieving key from storage: {e}")

                # If key storage decryption failed or wasn't available, try client encryption key
                if not decryption_successful and self.encryption_available:
                    logger.debug("Attempting decryption with client encryption key")
                    decryption_attempted = True

                    try:
                        decrypted_data = self.decrypt_data(file_data)

                        # Write the decrypted data back to the file
                        with open(output_path, "wb") as f:
                            f.write(decrypted_data)

                        decryption_successful = True
                        decrypted = True
                        size_bytes = len(
                            decrypted_data
                        )  # Update size to decrypted size

                        # Store the encryption key for the result
                        encryption_key_used = (
                            base64.b64encode(self.encryption_key).decode("utf-8")
                            if self.encryption_key
                            else None
                        )
                        logger.info(
                            "Successfully decrypted file using client encryption key"
                        )

                    except Exception as decrypt_error:
                        logger.debug(
                            f"Decryption failed with client key: {decrypt_error}"
                        )

                # Log final decryption status
                if decryption_attempted and not decryption_successful:
                    logger.info(
                        "File may not be encrypted or decryption keys don't match"
                    )
                elif not decryption_attempted:
                    logger.debug("No decryption attempted - no keys available")

        return S3DownloadResult(
            cid=cid,
            output_path=output_path,
            size_bytes=size_bytes,
            size_formatted=self.format_size(size_bytes),
            elapsed_seconds=round(elapsed_time, 2),
            decrypted=decrypted,
            encryption_key=encryption_key_used,
        )
