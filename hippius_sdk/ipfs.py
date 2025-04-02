"""
IPFS operations for the Hippius SDK.
"""

import os
import json
import requests
from typing import Dict, Any, Optional, Union, List
import ipfshttpclient


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
    
    def _upload_via_http_api(self, file_path: str) -> str:
        """
        Upload a file to IPFS using the HTTP API.
        
        This is a fallback method when ipfshttpclient is not available.
        
        Args:
            file_path: Path to the file to upload
            
        Returns:
            str: Content Identifier (CID) of the uploaded file
            
        Raises:
            ConnectionError: If the upload fails
        """
        if not self.base_url:
            raise ConnectionError("No IPFS API URL provided for HTTP upload")
        
        try:
            # Prepare the file for upload
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file, 'application/octet-stream')}
                
                # Make HTTP POST request to the IPFS HTTP API
                upload_url = f"{self.base_url}/api/v0/add"
                response = requests.post(upload_url, files=files)
                response.raise_for_status()
                
                # Parse the response JSON
                result = response.json()
                return result["Hash"]
        except Exception as e:
            raise ConnectionError(f"Failed to upload file via HTTP API: {str(e)}")
    
    def upload_file(self, file_path: str) -> str:
        """
        Upload a file to IPFS.

        Args:
            file_path: Path to the file to upload

        Returns:
            str: Content Identifier (CID) of the uploaded file
        
        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")
        
        if self.client:
            # Use IPFS client
            result = self.client.add(file_path)
            return result["Hash"]
        elif self.base_url:
            # Fallback to using HTTP API
            return self._upload_via_http_api(file_path)
        else:
            # No connection or API URL available
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
    
    def _upload_directory_via_http_api(self, dir_path: str) -> str:
        """
        Upload a directory to IPFS using the HTTP API.
        
        This is a limited implementation and may not support all directory features.
        
        Args:
            dir_path: Path to the directory to upload
            
        Returns:
            str: Content Identifier (CID) of the uploaded directory
            
        Raises:
            ConnectionError: If the upload fails
        """
        if not self.base_url:
            raise ConnectionError("No IPFS API URL provided for HTTP upload")
        
        try:
            # This is a simplified approach - we'll upload the directory with recursive flag
            files = []
            
            # Create a request with the directory flag
            upload_url = f"{self.base_url}/api/v0/add?recursive=true&wrap-with-directory=true"
            
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
            
            # Make HTTP POST request
            response = requests.post(upload_url, files=files)
            response.raise_for_status()
            
            # The IPFS API returns a JSON object for each file, one per line
            # The last one should be the directory itself
            lines = response.text.strip().split('\n')
            if not lines:
                raise ConnectionError("Empty response from IPFS API")
                
            last_item = json.loads(lines[-1])
            return last_item["Hash"]
            
        except Exception as e:
            raise ConnectionError(f"Failed to upload directory via HTTP API: {str(e)}")
    
    def upload_directory(self, dir_path: str) -> str:
        """
        Upload a directory to IPFS.

        Args:
            dir_path: Path to the directory to upload

        Returns:
            str: Content Identifier (CID) of the uploaded directory
        
        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory {dir_path} not found")
        
        if self.client:
            # Use IPFS client
            result = self.client.add(dir_path, recursive=True)
            if isinstance(result, list):
                # Get the last item, which should be the directory itself
                return result[-1]["Hash"]
            return result["Hash"]
        elif self.base_url:
            # Fallback to using HTTP API
            return self._upload_directory_via_http_api(dir_path)
        else:
            # No connection or API URL available
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
    
    def download_file(self, cid: str, output_path: str) -> None:
        """
        Download a file from IPFS.

        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
        
        Raises:
            requests.RequestException: If the download fails
        """
        url = f"{self.gateway}/ipfs/{cid}"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def cat(self, cid: str) -> bytes:
        """
        Get the content of a file from IPFS.

        Args:
            cid: Content Identifier (CID) of the file

        Returns:
            bytes: Content of the file
        
        Raises:
            requests.RequestException: If fetching the content fails
        """
        if self.client:
            return self.client.cat(cid)
        else:
            url = f"{self.gateway}/ipfs/{cid}"
            response = requests.get(url)
            response.raise_for_status()
            return response.content
    
    def exists(self, cid: str) -> bool:
        """
        Check if a CID exists on IPFS.

        Args:
            cid: Content Identifier (CID) to check

        Returns:
            bool: True if the CID exists, False otherwise
        """
        try:
            if self.client:
                # We'll try to get the file stats
                self.client.ls(cid)
                return True
            else:
                # Try to access through gateway
                url = f"{self.gateway}/ipfs/{cid}"
                response = requests.head(url)
                return response.status_code == 200
        except (ipfshttpclient.exceptions.ErrorResponse, requests.RequestException):
            return False
    
    def pin(self, cid: str) -> bool:
        """
        Pin a CID to IPFS to keep it available.

        Args:
            cid: Content Identifier (CID) to pin

        Returns:
            bool: True if pinning was successful, False otherwise
        
        Raises:
            ConnectionError: If no IPFS connection is available
        """
        if not self.client and self.base_url:
            # Try using HTTP API for pinning
            try:
                url = f"{self.base_url}/api/v0/pin/add?arg={cid}"
                response = requests.post(url)
                response.raise_for_status()
                return True
            except requests.RequestException as e:
                raise ConnectionError(f"Failed to pin CID via HTTP API: {str(e)}")
        elif not self.client:
            raise ConnectionError("No IPFS connection available. Please provide a valid api_url or ensure a local IPFS daemon is running.")
        
        try:
            self.client.pin.add(cid)
            return True
        except ipfshttpclient.exceptions.ErrorResponse:
            return False
