"""
IPFS operations for the Hippius SDK.
"""

import os
import json
import requests
from typing import Dict, Any, Optional, Union, List
import ipfshttpclient
import time


class IPFSClient:
    """Client for interacting with IPFS."""

    def __init__(self, gateway: str = "https://ipfs.io", api_url: Optional[str] = "https://relay-fr.hippius.network"):
        """
        Initialize the IPFS client.

        Args:
            gateway: IPFS gateway URL for downloading content
            api_url: IPFS API URL for uploading content. Defaults to Hippius relay node.
                    Set to None to try to connect to a local IPFS daemon.
        """
        self.gateway = gateway.rstrip("/")
        self.api_url = api_url
        self.client = None
        
        # Extract base URL from API URL for HTTP fallback
        self.base_url = api_url
        
        # Connect to IPFS daemon
        if api_url:
            try:
                # Only attempt to use ipfshttpclient if the URL is in multiaddr format (starts with /)
                if api_url.startswith('/'):
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
                with open(file_path, 'rb') as file:
                    files = {'file': (os.path.basename(file_path), file, 'application/octet-stream')}
                    
                    # Make HTTP POST request to the IPFS HTTP API with a timeout
                    print(f"  Sending request to {self.base_url}/api/v0/add... (attempt {retries+1}/{max_retries})")
                    upload_url = f"{self.base_url}/api/v0/add"
                    response = requests.post(
                        upload_url, 
                        files=files, 
                        timeout=120  # 2 minute timeout for uploads
                    )
                    response.raise_for_status()
                    
                    # Parse the response JSON
                    result = response.json()
                    print(f"  Upload successful! CID: {result['Hash']}")
                    return result["Hash"]
                    
            except (requests.exceptions.Timeout, 
                    requests.exceptions.ConnectionError, 
                    requests.exceptions.RequestException) as e:
                # Save the error and retry
                last_error = e
                retries += 1
                wait_time = 2 ** retries  # Exponential backoff: 2, 4, 8 seconds
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
                raise ConnectionError(f"Timeout when uploading to {self.base_url} after {max_retries} attempts. The server is not responding.")
            elif isinstance(last_error, requests.exceptions.ConnectionError):
                raise ConnectionError(f"Failed to connect to IPFS node at {self.base_url} after {max_retries} attempts: {str(last_error)}")
            else:
                raise ConnectionError(f"Failed to upload file via HTTP API after {max_retries} attempts. Last error ({error_type}): {str(last_error)}")
        
        # This should never happen, but just in case
        raise ConnectionError(f"Failed to upload file to {self.base_url} after {max_retries} attempts for unknown reasons.")
    
    def upload_file(self, file_path: str, include_formatted_size: bool = True) -> Dict[str, Any]:
        """
        Upload a file to IPFS.

        Args:
            file_path: Path to the file to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - cid: Content Identifier (CID) of the uploaded file
                - filename: Name of the uploaded file
                - size_bytes: Size of the file in bytes
                - size_formatted: Human-readable file size (if include_formatted_size is True)
        
        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")
        
        # Get file info before upload
        filename = os.path.basename(file_path)
        size_bytes = os.path.getsize(file_path)
        
        # Upload to IPFS
        if self.client:
            # Use IPFS client
            result = self.client.add(file_path)
            cid = result["Hash"]
        elif self.base_url:
            # Fallback to using HTTP API
            cid = self._upload_via_http_api(file_path)
        else:
            # No connection or API URL available
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
        
        # Format the result
        result = {
            "cid": cid,
            "filename": filename,
            "size_bytes": size_bytes,
        }
        
        # Add formatted size if requested
        if include_formatted_size:
            result["size_formatted"] = self.format_size(size_bytes)
        
        return result
    
    def _upload_directory_via_http_api(self, dir_path: str, max_retries: int = 3) -> str:
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
                        
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        
                        # Add the file to the multipart request
                        files.append(
                            ('file', (rel_path, file_content, 'application/octet-stream'))
                        )
                
                # Create a request with the directory flag
                upload_url = f"{self.base_url}/api/v0/add?recursive=true&wrap-with-directory=true"
                
                print(f"  Sending directory upload request to {self.base_url}/api/v0/add... (attempt {retries+1}/{max_retries})")
                print(f"  Uploading {len(files)} files...")
                
                # Make HTTP POST request with timeout
                response = requests.post(
                    upload_url, 
                    files=files, 
                    timeout=300  # 5 minute timeout for directory uploads
                )
                response.raise_for_status()
                
                # The IPFS API returns a JSON object for each file, one per line
                # The last one should be the directory itself
                lines = response.text.strip().split('\n')
                if not lines:
                    raise ConnectionError("Empty response from IPFS API")
                    
                last_item = json.loads(lines[-1])
                print(f"  Directory upload successful! CID: {last_item['Hash']}")
                return last_item["Hash"]
                
            except (requests.exceptions.Timeout, 
                    requests.exceptions.ConnectionError, 
                    requests.exceptions.RequestException) as e:
                # Save the error and retry
                last_error = e
                retries += 1
                wait_time = 2 ** retries  # Exponential backoff: 2, 4, 8 seconds
                print(f"  Upload attempt {retries} failed: {str(e)}")
                if retries < max_retries:
                    print(f"  Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
            except Exception as e:
                # For other exceptions, don't retry
                raise ConnectionError(f"Failed to upload directory via HTTP API: {str(e)}")
        
        # If we've exhausted all retries
        if last_error:
            error_type = type(last_error).__name__
            if isinstance(last_error, requests.exceptions.Timeout):
                raise ConnectionError(f"Timeout when uploading directory to {self.base_url} after {max_retries} attempts. The server is not responding.")
            elif isinstance(last_error, requests.exceptions.ConnectionError):
                raise ConnectionError(f"Failed to connect to IPFS node at {self.base_url} after {max_retries} attempts: {str(last_error)}")
            else:
                raise ConnectionError(f"Failed to upload directory via HTTP API after {max_retries} attempts. Last error ({error_type}): {str(last_error)}")
        
        # This should never happen, but just in case
        raise ConnectionError(f"Failed to upload directory to {self.base_url} after {max_retries} attempts for unknown reasons.")
    
    def upload_directory(self, dir_path: str, include_formatted_size: bool = True) -> Dict[str, Any]:
        """
        Upload a directory to IPFS.

        Args:
            dir_path: Path to the directory to upload
            include_formatted_size: Whether to include formatted size in the result (default: True)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - cid: Content Identifier (CID) of the uploaded directory
                - dirname: Name of the uploaded directory
                - file_count: Number of files in the directory
                - total_size_bytes: Total size of all files in bytes
                - size_formatted: Human-readable total size (if include_formatted_size is True)
        
        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory {dir_path} not found")
        
        # Get directory info
        dirname = os.path.basename(dir_path)
        total_size_bytes = 0
        file_count = 0
        
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
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
        
        # Format the result
        result = {
            "cid": cid,
            "dirname": dirname,
            "file_count": file_count,
            "total_size_bytes": total_size_bytes,
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
        if cid.startswith(('Qm', 'bafy', 'bafk', 'bafyb', 'bafzb', 'b')):
            return cid
        
        # Check if it's a hex string
        if all(c in '0123456789abcdefABCDEF' for c in cid):
            # First try the special case where the hex string is actually ASCII encoded
            try:
                # Try to decode the hex as ASCII characters
                hex_bytes = bytes.fromhex(cid)
                ascii_str = hex_bytes.decode('ascii')
                
                # If the decoded string starts with a valid CID prefix, return it
                if ascii_str.startswith(('Qm', 'bafy', 'bafk', 'bafyb', 'bafzb', 'b')):
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
                    if len(binary_data) > 2 and binary_data[0] == 0x12 and binary_data[1] == 0x20:
                        # This looks like a CIDv0 (Qm...)
                        decoded_cid = base58.b58encode(binary_data).decode('utf-8')
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
    
    def download_file(self, cid: str, output_path: str) -> Dict[str, Any]:
        """
        Download a file from IPFS.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
        
        Returns:
            Dict[str, Any]: Dictionary containing download results:
                - success: Whether the download was successful
                - output_path: Path where the file was saved
                - size_bytes: Size of the downloaded file in bytes
                - size_formatted: Human-readable file size
                - elapsed_seconds: Time taken for the download in seconds
        
        Raises:
            requests.RequestException: If the download fails
        """
        start_time = time.time()
        
        url = f"{self.gateway}/ipfs/{cid}"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        elapsed_time = time.time() - start_time
        file_size_bytes = os.path.getsize(output_path)
        
        return {
            "success": True,
            "output_path": output_path,
            "size_bytes": file_size_bytes,
            "size_formatted": self.format_size(file_size_bytes),
            "elapsed_seconds": round(elapsed_time, 2)
        }
    
    def cat(self, cid: str, max_display_bytes: int = 1024, format_output: bool = True) -> Dict[str, Any]:
        """
        Get the content of a file from IPFS.

        Args:
            cid: Content Identifier (CID) of the file
            max_display_bytes: Maximum number of bytes to include in the preview (default: 1024)
            format_output: Whether to attempt to decode the content as text (default: True)

        Returns:
            Dict[str, Any]: Dictionary containing:
                - content: Complete binary content of the file
                - size_bytes: Size of the content in bytes
                - size_formatted: Human-readable size
                - preview: First part of the content (limited by max_display_bytes)
                - is_text: Whether the content seems to be text
                - text_preview: Text preview if is_text is True (up to max_display_bytes)
                - hex_preview: Hex preview if is_text is False (up to max_display_bytes)
        
        Raises:
            requests.RequestException: If fetching the content fails
        """
        if self.client:
            content = self.client.cat(cid)
        else:
            url = f"{self.gateway}/ipfs/{cid}"
            response = requests.get(url)
            response.raise_for_status()
            content = response.content
        
        size_bytes = len(content)
        
        result = {
            "content": content,
            "size_bytes": size_bytes,
            "size_formatted": self.format_size(size_bytes),
        }
        
        # Add preview
        if format_output:
            # Limit preview size
            preview = content[:max_display_bytes]
            result["preview"] = preview
            
            # Try to decode as text
            try:
                text_preview = preview.decode('utf-8')
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
            "gateway_url": gateway_url if exists else None
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
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
        
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
            "message": message
        }
