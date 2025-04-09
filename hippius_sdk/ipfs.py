"""
IPFS operations for the Hippius SDK.
"""

import os
import json
import requests
import base64
import time
import tempfile
import hashlib
import uuid
from typing import Dict, Any, Optional, Union, List, Tuple
import ipfshttpclient
from dotenv import load_dotenv
from hippius_sdk.config import (
    get_config_value,
    get_encryption_key,
)

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
            gateway = get_config_value("ipfs", "gateway", "https://ipfs.io")

        if api_url is None:
            api_url = get_config_value(
                "ipfs", "api_url", "https://store.hippius.network"
            )

            # Check if local IPFS is enabled in config
            if get_config_value("ipfs", "local_ipfs", False):
                api_url = "http://localhost:5001"

        self.gateway = gateway.rstrip("/")
        self.api_url = api_url
        self.client = None

        # Extract base URL from API URL for HTTP fallback
        self.base_url = api_url

        # Connect to IPFS daemon
        if api_url:
            try:
                # Only attempt to use ipfshttpclient if the URL is in multiaddr format (starts with /)
                if api_url.startswith("/"):
                    self.client = ipfshttpclient.connect(api_url)
                else:
                    # For regular HTTP URLs, we'll use the HTTP API directly
                    print(f"Using HTTP API at {api_url} for IPFS operations")
            except ipfshttpclient.exceptions.ConnectionError as e:
                print(f"Warning: Could not connect to IPFS node at {api_url}: {e}")
                print(f"Falling back to HTTP API for uploads")
                # We'll use HTTP API fallback for uploads
                try:
                    # Try to connect to local IPFS daemon as fallback
                    self.client = ipfshttpclient.connect()
                except ipfshttpclient.exceptions.ConnectionError:
                    # No IPFS connection available, but HTTP API fallback will be used
                    pass
        else:
            try:
                # Try to connect to local IPFS daemon
                self.client = ipfshttpclient.connect()
            except ipfshttpclient.exceptions.ConnectionError:
                # No local IPFS daemon connection available
                pass

        # Initialize encryption settings
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
                f"Warning: Encryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
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

    def _upload_via_http_api(self, file_path: str, max_retries: int = 3) -> str:
        """
        Upload a file to IPFS using the HTTP API.

        This is a fallback method when ipfshttpclient is not available.

        Args:
            file_path: Path to the file to upload
            max_retries: Maximum number of retry attempts (default: 3)

        Returns:
            str: Content Identifier (CID) of the uploaded file

        Raises:
            ConnectionError: If the upload fails
        """
        if not self.base_url:
            raise ConnectionError("No IPFS API URL provided for HTTP upload")

        # Retry logic
        retries = 0
        last_error = None

        while retries < max_retries:
            try:
                # Show progress for large files
                file_size = os.path.getsize(file_path)
                if file_size > 1024 * 1024:  # If file is larger than 1MB
                    print(f"  Uploading {file_size/1024/1024:.2f} MB file...")

                # Prepare the file for upload
                with open(file_path, "rb") as file:
                    files = {
                        "file": (
                            os.path.basename(file_path),
                            file,
                            "application/octet-stream",
                        )
                    }

                    # Make HTTP POST request to the IPFS HTTP API with a timeout
                    print(
                        f"  Sending request to {self.base_url}/api/v0/add... (attempt {retries+1}/{max_retries})"
                    )
                    upload_url = f"{self.base_url}/api/v0/add"
                    response = requests.post(
                        upload_url,
                        files=files,
                        timeout=120,  # 2 minute timeout for uploads
                    )
                    response.raise_for_status()

                    # Parse the response JSON
                    result = response.json()
                    print(f"  Upload successful! CID: {result['Hash']}")
                    return result["Hash"]

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException,
            ) as e:
                # Save the error and retry
                last_error = e
                retries += 1
                wait_time = 2**retries  # Exponential backoff: 2, 4, 8 seconds
                print(f"  Upload attempt {retries} failed: {str(e)}")
                if retries < max_retries:
                    print(f"  Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
            except Exception as e:
                # For other exceptions, don't retry
                raise ConnectionError(f"Failed to upload file via HTTP API: {str(e)}")

        # If we've exhausted all retries
        if last_error:
            error_type = type(last_error).__name__
            if isinstance(last_error, requests.exceptions.Timeout):
                raise ConnectionError(
                    f"Timeout when uploading to {self.base_url} after {max_retries} attempts. The server is not responding."
                )
            elif isinstance(last_error, requests.exceptions.ConnectionError):
                raise ConnectionError(
                    f"Failed to connect to IPFS node at {self.base_url} after {max_retries} attempts: {str(last_error)}"
                )
            else:
                raise ConnectionError(
                    f"Failed to upload file via HTTP API after {max_retries} attempts. Last error ({error_type}): {str(last_error)}"
                )

        # This should never happen, but just in case
        raise ConnectionError(
            f"Failed to upload file to {self.base_url} after {max_retries} attempts for unknown reasons."
        )

    def upload_file(
        self,
        file_path: str,
        include_formatted_size: bool = True,
        encrypt: Optional[bool] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Upload a file to IPFS with optional encryption.

        Args:
            file_path: Path to the file to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)
            encrypt: Whether to encrypt the file (overrides default)
            max_retries: Maximum number of retry attempts (default: 3)

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

            # Upload to IPFS
            if self.client:
                # Use IPFS client
                result = self.client.add(upload_path)
                cid = result["Hash"]
            elif self.base_url:
                # Fallback to using HTTP API
                cid = self._upload_via_http_api(upload_path, max_retries=max_retries)
            else:
                # No connection or API URL available
                raise ConnectionError(
                    "No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running."
                )

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

    def upload_directory(
        self,
        dir_path: str,
        include_formatted_size: bool = True,
        encrypt: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Upload a directory to IPFS with optional encryption of files.

        Args:
            dir_path: Path to the directory to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)
            encrypt: Whether to encrypt files (overrides default)

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
                if self.client:
                    result = self.client.add(temp_dir, recursive=True)
                    if isinstance(result, list):
                        cid = result[-1]["Hash"]
                    else:
                        cid = result["Hash"]
                elif self.base_url:
                    cid = self._upload_directory_via_http_api(temp_dir)
                else:
                    raise ConnectionError("No IPFS connection available")
            finally:
                # Clean up the temporary directory
                import shutil

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
            if self.client:
                # Use IPFS client
                result = self.client.add(dir_path, recursive=True)
                if isinstance(result, list):
                    # Get the last item, which should be the directory itself
                    cid = result[-1]["Hash"]
                else:
                    cid = result["Hash"]
            elif self.base_url:
                # Fallback to using HTTP API
                cid = self._upload_directory_via_http_api(dir_path)
            else:
                # No connection or API URL available
                raise ConnectionError(
                    "No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running."
                )

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

    def _upload_directory_via_http_api(
        self, dir_path: str, max_retries: int = 3
    ) -> str:
        """
        Upload a directory to IPFS using the HTTP API.

        This is a limited implementation and may not support all directory features.

        Args:
            dir_path: Path to the directory to upload
            max_retries: Maximum number of retry attempts (default: 3)

        Returns:
            str: Content Identifier (CID) of the uploaded directory

        Raises:
            ConnectionError: If the upload fails
        """
        if not self.base_url:
            raise ConnectionError("No IPFS API URL provided for HTTP upload")

        # Retry logic
        retries = 0
        last_error = None

        while retries < max_retries:
            try:
                # This is a simplified approach - we'll upload the directory with recursive flag
                files = []

                print(f"  Preparing directory contents for upload...")
                # Collect all files in the directory
                for root, _, filenames in os.walk(dir_path):
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        rel_path = os.path.relpath(file_path, dir_path)

                        with open(file_path, "rb") as f:
                            file_content = f.read()

                        # Add the file to the multipart request
                        files.append(
                            (
                                "file",
                                (rel_path, file_content, "application/octet-stream"),
                            )
                        )

                # Create a request with the directory flag
                upload_url = f"{self.base_url}/api/v0/add?recursive=true&wrap-with-directory=true"

                print(
                    f"  Sending directory upload request to {self.base_url}/api/v0/add... (attempt {retries+1}/{max_retries})"
                )
                print(f"  Uploading {len(files)} files...")

                # Make HTTP POST request with timeout
                response = requests.post(
                    upload_url,
                    files=files,
                    timeout=300,  # 5 minute timeout for directory uploads
                )
                response.raise_for_status()

                # The IPFS API returns a JSON object for each file, one per line
                # The last one should be the directory itself
                lines = response.text.strip().split("\n")
                if not lines:
                    raise ConnectionError("Empty response from IPFS API")

                last_item = json.loads(lines[-1])
                print(f"  Directory upload successful! CID: {last_item['Hash']}")
                return last_item["Hash"]

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException,
            ) as e:
                # Save the error and retry
                last_error = e
                retries += 1
                wait_time = 2**retries  # Exponential backoff: 2, 4, 8 seconds
                print(f"  Upload attempt {retries} failed: {str(e)}")
                if retries < max_retries:
                    print(f"  Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
            except Exception as e:
                # For other exceptions, don't retry
                raise ConnectionError(
                    f"Failed to upload directory via HTTP API: {str(e)}"
                )

        # If we've exhausted all retries
        if last_error:
            error_type = type(last_error).__name__
            if isinstance(last_error, requests.exceptions.Timeout):
                raise ConnectionError(
                    f"Timeout when uploading directory to {self.base_url} after {max_retries} attempts. The server is not responding."
                )
            elif isinstance(last_error, requests.exceptions.ConnectionError):
                raise ConnectionError(
                    f"Failed to connect to IPFS node at {self.base_url} after {max_retries} attempts: {str(last_error)}"
                )
            else:
                raise ConnectionError(
                    f"Failed to upload directory via HTTP API after {max_retries} attempts. Last error ({error_type}): {str(last_error)}"
                )

        # This should never happen, but just in case
        raise ConnectionError(
            f"Failed to upload directory to {self.base_url} after {max_retries} attempts for unknown reasons."
        )

    def format_size(self, size_bytes: int) -> str:
        """
        Format a size in bytes to a human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            str: Human-readable size string (e.g., '1.23 MB', '456.78 KB')
        """
        if size_bytes >= 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
        elif size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        else:
            return f"{size_bytes} bytes"

    def format_cid(self, cid: str) -> str:
        """
        Format a CID for display.

        This method handles both regular CIDs and hex-encoded CIDs.

        Args:
            cid: Content Identifier (CID) to format

        Returns:
            str: Formatted CID string
        """
        # If it already looks like a proper CID, return it as is
        if cid.startswith(("Qm", "bafy", "bafk", "bafyb", "bafzb", "b")):
            return cid

        # Check if it's a hex string
        if all(c in "0123456789abcdefABCDEF" for c in cid):
            # First try the special case where the hex string is actually ASCII encoded
            try:
                # Try to decode the hex as ASCII characters
                hex_bytes = bytes.fromhex(cid)
                ascii_str = hex_bytes.decode("ascii")

                # If the decoded string starts with a valid CID prefix, return it
                if ascii_str.startswith(("Qm", "bafy", "bafk", "bafyb", "bafzb", "b")):
                    return ascii_str
            except Exception:
                pass

            # If the above doesn't work, try the standard CID decoding
            try:
                import base58
                import binascii

                # Try to decode hex to binary then to base58 for CIDv0
                try:
                    binary_data = binascii.unhexlify(cid)
                    if (
                        len(binary_data) > 2
                        and binary_data[0] == 0x12
                        and binary_data[1] == 0x20
                    ):
                        # This looks like a CIDv0 (Qm...)
                        decoded_cid = base58.b58encode(binary_data).decode("utf-8")
                        return decoded_cid
                except Exception:
                    pass

                # If not successful, just return hex with 0x prefix as fallback
                return f"0x{cid}"
            except ImportError:
                # If base58 is not available, return hex with prefix
                return f"0x{cid}"

        # Default case - return as is
        return cid

    def download_file(
        self,
        cid: str,
        output_path: str,
        decrypt: Optional[bool] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Download a file from IPFS with optional decryption.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
            decrypt: Whether to decrypt the file (overrides default)
            max_retries: Maximum number of retry attempts (default: 3)

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

        # Determine if we should decrypt
        should_decrypt = self.encrypt_by_default if decrypt is None else decrypt

        # Check if decryption is available if requested
        if should_decrypt and not self.encryption_available:
            raise ValueError(
                "Decryption requested but not available. Check that PyNaCl is installed and a valid encryption key is provided."
            )

        # Create a temporary file if we'll be decrypting
        temp_file_path = None
        try:
            if should_decrypt:
                # Create a temporary file for the encrypted data
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                temp_file_path = temp_file.name
                temp_file.close()
                download_path = temp_file_path
            else:
                download_path = output_path

            # Download the file with retry logic
            retries = 0
            last_error = None

            while retries < max_retries:
                try:
                    # Download the file
                    url = f"{self.gateway}/ipfs/{cid}"
                    response = requests.get(url, stream=True)
                    response.raise_for_status()

                    os.makedirs(
                        os.path.dirname(os.path.abspath(download_path)), exist_ok=True
                    )

                    with open(download_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    # If we reach here, download was successful
                    break

                except (requests.exceptions.RequestException, IOError) as e:
                    # Save the error and retry
                    last_error = e
                    retries += 1

                    if retries < max_retries:
                        wait_time = 2**retries  # Exponential backoff: 2, 4, 8 seconds
                        print(f"Download attempt {retries} failed: {str(e)}")
                        print(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        # Raise the last error if we've exhausted all retries
                        raise

            # Decrypt if needed
            if should_decrypt:
                try:
                    # Read the encrypted data
                    with open(temp_file_path, "rb") as f:
                        encrypted_data = f.read()

                    # Decrypt the data
                    decrypted_data = self.decrypt_data(encrypted_data)

                    # Write the decrypted data to the output path
                    os.makedirs(
                        os.path.dirname(os.path.abspath(output_path)), exist_ok=True
                    )
                    with open(output_path, "wb") as f:
                        f.write(decrypted_data)

                    # Use output_path for size measurement
                    file_size_bytes = len(decrypted_data)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt file: {str(e)}")
            else:
                file_size_bytes = os.path.getsize(output_path)

            elapsed_time = time.time() - start_time

            return {
                "success": True,
                "output_path": output_path,
                "size_bytes": file_size_bytes,
                "size_formatted": self.format_size(file_size_bytes),
                "elapsed_seconds": round(elapsed_time, 2),
                "decrypted": should_decrypt,
            }

        finally:
            # Clean up temporary file if created
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

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
            max_display_bytes: Maximum number of bytes to include in the preview (default: 1024)
            format_output: Whether to attempt to decode the content as text (default: True)
            decrypt: Whether to decrypt the file (overrides default)

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

        # Get the content
        if self.client:
            content = self.client.cat(cid)
        else:
            url = f"{self.gateway}/ipfs/{cid}"
            response = requests.get(url)
            response.raise_for_status()
            content = response.content

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
        formatted_cid = self.format_cid(cid)
        gateway_url = f"{self.gateway}/ipfs/{cid}"

        try:
            if self.client:
                # We'll try to get the file stats
                self.client.ls(cid)
                exists = True
            else:
                # Try to access through gateway
                url = f"{self.gateway}/ipfs/{cid}"
                response = requests.head(url)
                exists = response.status_code == 200
        except (ipfshttpclient.exceptions.ErrorResponse, requests.RequestException):
            exists = False

        return {
            "exists": exists,
            "cid": cid,
            "formatted_cid": formatted_cid,
            "gateway_url": gateway_url if exists else None,
        }

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

        Raises:
            ConnectionError: If no IPFS connection is available
        """
        formatted_cid = self.format_cid(cid)

        if not self.client and self.base_url:
            # Try using HTTP API for pinning
            try:
                url = f"{self.base_url}/api/v0/pin/add?arg={cid}"
                response = requests.post(url)
                response.raise_for_status()
                success = True
                message = "Successfully pinned via HTTP API"
            except requests.RequestException as e:
                success = False
                message = f"Failed to pin: {str(e)}"
        elif not self.client:
            raise ConnectionError(
                "No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running."
            )

        try:
            if self.client:
                self.client.pin.add(cid)
                success = True
                message = "Successfully pinned"
            else:
                success = False
                message = "No IPFS client available"
        except ipfshttpclient.exceptions.ErrorResponse as e:
            success = False
            message = f"Failed to pin: {str(e)}"

        return {
            "success": success,
            "cid": cid,
            "formatted_cid": formatted_cid,
            "message": message,
        }

    def erasure_code_file(
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
            print(f"Processing file: {file_name} ({file_size/1024/1024:.2f} MB)")
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
        chunks = []
        chunk_positions = []
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i : i + chunk_size]
            chunks.append(chunk)
            chunk_positions.append(i)

        # Pad the last chunk if necessary
        if chunks and len(chunks[-1]) < chunk_size:
            pad_size = chunk_size - len(chunks[-1])
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
                    print(f"  Encoded {i+1}/{len(chunks)} chunks")
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
            print(f"Uploading {len(chunks) * m} erasure-coded chunks to IPFS...")

        chunk_uploads = 0
        chunk_data = []

        # Create a temporary directory for the chunks
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write and upload each encoded chunk
            for original_idx, encoded_chunks in enumerate(all_encoded_chunks):
                for share_idx, share_data in enumerate(encoded_chunks):
                    # Create a name for this chunk that includes needed info
                    chunk_name = f"{file_id}_chunk_{original_idx}_{share_idx}.ec"
                    chunk_path = os.path.join(temp_dir, chunk_name)

                    # Write the chunk to a temp file
                    with open(chunk_path, "wb") as f:
                        f.write(share_data)

                    # Upload the chunk to IPFS
                    try:
                        chunk_cid = self.upload_file(
                            chunk_path, max_retries=max_retries
                        )

                        # Store info about this chunk
                        chunk_info = {
                            "name": chunk_name,
                            "cid": chunk_cid,
                            "original_chunk": original_idx,
                            "share_idx": share_idx,
                            "size": len(share_data),
                        }
                        chunk_data.append(chunk_info)

                        chunk_uploads += 1
                        if verbose and chunk_uploads % 10 == 0:
                            print(
                                f"  Uploaded {chunk_uploads}/{len(chunks) * m} chunks"
                            )
                    except Exception as e:
                        print(f"Error uploading chunk {chunk_name}: {str(e)}")

            # Add all chunk info to metadata
            metadata["chunks"] = chunk_data

            # Step 5: Create and upload the metadata file
            metadata_path = os.path.join(temp_dir, f"{file_id}_metadata.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            if verbose:
                print(f"Uploading metadata file...")

            # Upload the metadata file to IPFS
            metadata_cid_result = self.upload_file(
                metadata_path, max_retries=max_retries
            )

            # Extract just the CID string from the result dictionary
            metadata_cid = metadata_cid_result["cid"]
            metadata["metadata_cid"] = metadata_cid

            if verbose:
                print(f"Erasure coding complete!")
                print(f"Metadata CID: {metadata_cid}")
                print(f"Original file size: {file_size/1024/1024:.2f} MB")
                print(f"Total chunks: {len(chunks) * m}")
                print(f"Minimum chunks needed: {k * len(chunks)}")

            return metadata

    def reconstruct_from_erasure_code(
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
            self.download_file(metadata_cid, metadata_path, max_retries=max_retries)

            if verbose:
                metadata_download_time = time.time() - start_time
                print(f"Metadata downloaded in {metadata_download_time:.2f} seconds")

            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            # Step 2: Extract key information
            original_file = metadata["original_file"]
            erasure_params = metadata["erasure_coding"]
            chunks_info = metadata["chunks"]

            k = erasure_params["k"]
            m = erasure_params["m"]
            is_encrypted = erasure_params.get("encrypted", False)
            chunk_size = erasure_params.get("chunk_size", 1024 * 1024)

            if verbose:
                print(
                    f"File: {original_file['name']} ({original_file['size']/1024/1024:.2f} MB)"
                )
                print(
                    f"Erasure coding parameters: k={k}, m={m} (need {k} of {m} chunks to reconstruct)"
                )
                if is_encrypted:
                    print(f"Encrypted: Yes")

            # Step 3: Group chunks by their original chunk index
            chunks_by_original = {}
            for chunk in chunks_info:
                orig_idx = chunk["original_chunk"]
                if orig_idx not in chunks_by_original:
                    chunks_by_original[orig_idx] = []
                chunks_by_original[orig_idx].append(chunk)

            # Step 4: For each original chunk, download at least k shares
            if verbose:
                total_original_chunks = len(chunks_by_original)
                total_chunks_to_download = total_original_chunks * k
                print(
                    f"Downloading and reconstructing {total_chunks_to_download} chunks..."
                )

            reconstructed_chunks = []
            chunks_downloaded = 0
            chunks_failed = 0

            for orig_idx in sorted(chunks_by_original.keys()):
                available_chunks = chunks_by_original[orig_idx]

                if len(available_chunks) < k:
                    raise ValueError(
                        f"Not enough chunks available for original chunk {orig_idx}. "
                        f"Need {k}, but only have {len(available_chunks)}."
                    )

                # We only need k chunks, so take the first k
                chunks_to_download = available_chunks[:k]

                # Download the chunks
                downloaded_shares = []
                share_indexes = []

                for chunk in chunks_to_download:
                    chunk_path = os.path.join(temp_dir, chunk["name"])
                    try:
                        # Extract the CID string from the chunk's cid dictionary
                        chunk_cid = (
                            chunk["cid"]["cid"]
                            if isinstance(chunk["cid"], dict) and "cid" in chunk["cid"]
                            else chunk["cid"]
                        )
                        self.download_file(
                            chunk_cid, chunk_path, max_retries=max_retries
                        )
                        chunks_downloaded += 1

                        # Read the chunk data
                        with open(chunk_path, "rb") as f:
                            share_data = f.read()

                        downloaded_shares.append(share_data)
                        share_indexes.append(chunk["share_idx"])

                    except Exception as e:
                        if verbose:
                            print(f"Error downloading chunk {chunk['name']}: {str(e)}")
                        chunks_failed += 1
                        # Continue to the next chunk

                # If we don't have enough chunks, try to download more
                if len(downloaded_shares) < k:
                    raise ValueError(
                        f"Failed to download enough chunks for original chunk {orig_idx}. "
                        f"Need {k}, but only downloaded {len(downloaded_shares)}."
                    )

                # Reconstruct this chunk
                decoder = zfec.Decoder(k, m)
                reconstructed_data = decoder.decode(downloaded_shares, share_indexes)

                # If we used the sub-block approach during encoding, we need to recombine the sub-blocks
                if isinstance(reconstructed_data, list):
                    # Combine the sub-blocks back into a single chunk
                    reconstructed_chunk = b"".join(reconstructed_data)
                else:
                    # The simple case where we didn't use sub-blocks
                    reconstructed_chunk = reconstructed_data

                reconstructed_chunks.append(reconstructed_chunk)

                # Print progress
                if verbose:
                    progress_pct = (orig_idx + 1) / total_original_chunks * 100
                    print(
                        f"  Progress: {orig_idx + 1}/{total_original_chunks} chunks ({progress_pct:.1f}%)"
                    )

            if verbose:
                download_time = time.time() - start_time
                print(
                    f"Downloaded {chunks_downloaded} chunks in {download_time:.2f} seconds"
                )
                if chunks_failed > 0:
                    print(
                        f"Failed to download {chunks_failed} chunks (not needed for reconstruction)"
                    )

            # Step 5: Combine the reconstructed chunks into a file
            if verbose:
                print(f"Combining reconstructed chunks...")

            # Concatenate all chunks
            file_data = b"".join(reconstructed_chunks)

            # Remove padding from the last chunk
            if original_file["size"] < len(file_data):
                file_data = file_data[: original_file["size"]]

            # Step 6: Decrypt if necessary
            if is_encrypted:
                if not self.encryption_available:
                    raise ValueError(
                        "File is encrypted but encryption is not available. "
                        "Install PyNaCl and configure an encryption key."
                    )

                if verbose:
                    print(f"Decrypting file data...")

                file_data = self.decrypt_data(file_data)

            # Step 7: Write to the output file
            with open(output_file, "wb") as f:
                f.write(file_data)

            # Step 8: Verify hash if available
            if "hash" in original_file:
                actual_hash = hashlib.sha256(file_data).hexdigest()
                expected_hash = original_file["hash"]

                if actual_hash != expected_hash:
                    print(f"Warning: File hash mismatch!")
                    print(f"  Expected: {expected_hash}")
                    print(f"  Actual:   {actual_hash}")
                elif verbose:
                    print(f"Hash verification successful!")

            total_time = time.time() - start_time
            if verbose:
                print(f"Reconstruction complete in {total_time:.2f} seconds!")
                print(f"File saved to: {output_file}")

            return output_file

        finally:
            # Clean up temporary directory if we created it
            if temp_dir_obj is not None:
                temp_dir_obj.cleanup()

    def store_erasure_coded_file(
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

        Returns:
            dict: Result including metadata CID and transaction hash

        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If processing fails
        """
        # Step 1: Erasure code the file and upload chunks
        metadata = self.erasure_code_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            max_retries=max_retries,
            verbose=verbose,
        )

        # Step 2: Import substrate client if we need it
        if substrate_client is None:
            from hippius_sdk.substrate import SubstrateClient, FileInput

            substrate_client = SubstrateClient()
        else:
            # Just get the FileInput class
            from hippius_sdk.substrate import FileInput

        original_file = metadata["original_file"]
        metadata_cid = metadata["metadata_cid"]

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
            print(f"Adding all chunks to storage request...")

        for i, chunk in enumerate(metadata["chunks"]):
            # Extract the CID string from the chunk's cid dictionary
            chunk_cid = (
                chunk["cid"]["cid"]
                if isinstance(chunk["cid"], dict) and "cid" in chunk["cid"]
                else chunk["cid"]
            )
            chunk_file_input = FileInput(file_hash=chunk_cid, file_name=chunk["name"])
            all_file_inputs.append(chunk_file_input)

            # Print progress for large numbers of chunks
            if verbose and (i + 1) % 50 == 0:
                print(
                    f"  Prepared {i + 1}/{len(metadata['chunks'])} chunks for storage"
                )

        # Step 5: Submit the storage request for all files
        try:
            if verbose:
                print(
                    f"Submitting storage request for 1 metadata file and {len(metadata['chunks'])} chunks..."
                )

            tx_hash = substrate_client.storage_request(
                files=all_file_inputs, miner_ids=miner_ids
            )

            if verbose:
                print(f"Successfully stored all files in marketplace!")
                print(f"Transaction hash: {tx_hash}")
                print(f"Metadata CID: {metadata_cid}")
                print(
                    f"Total files stored: {len(all_file_inputs)} (1 metadata + {len(metadata['chunks'])} chunks)"
                )

            return {
                "metadata": metadata,
                "metadata_cid": metadata_cid,
                "transaction_hash": tx_hash,
                "total_files_stored": len(all_file_inputs),
            }

        except Exception as e:
            print(f"Error storing files in marketplace: {str(e)}")
            # Return the metadata even if storage fails
            return {"metadata": metadata, "metadata_cid": metadata_cid, "error": str(e)}
