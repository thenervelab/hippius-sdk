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
    ):
        """
        Initialize the Hippius client.
        
        Args:
            ipfs_gateway: IPFS gateway URL for downloading content
            ipfs_api_url: IPFS API URL for uploading content. Defaults to Hippius relay node.
            substrate_url: WebSocket URL of the Hippius substrate node
            substrate_seed_phrase: Seed phrase for Substrate account
        """
        self.ipfs = IPFSClient(gateway=ipfs_gateway, api_url=ipfs_api_url)
        
        # Initialize Substrate client
        try:
            self.substrate_client = SubstrateClient(url=substrate_url, seed_phrase=substrate_seed_phrase)
        except Exception as e:
            print(f"Warning: Could not initialize Substrate client: {e}")
            self.substrate_client = None
    
    def upload_file(self, file_path: str) -> Dict[str, Any]:
        """
        Upload a file to IPFS.
        
        Args:
            file_path: Path to the file to upload
        
        Returns:
            Dict[str, Any]: Dictionary containing file details including:
                - cid: Content Identifier of the uploaded file
                - filename: Name of the file
                - size_bytes: Size of the file in bytes
                - size_formatted: Human-readable file size
        
        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        # Use the enhanced IPFSClient method directly
        return self.ipfs.upload_file(file_path)
    
    def upload_directory(self, dir_path: str) -> Dict[str, Any]:
        """
        Upload a directory to IPFS.
        
        Args:
            dir_path: Path to the directory to upload
        
        Returns:
            Dict[str, Any]: Dictionary containing directory details including:
                - cid: Content Identifier of the uploaded directory
                - dirname: Name of the directory
                - file_count: Number of files uploaded
                - total_size_bytes: Total size in bytes
                - size_formatted: Human-readable total size
        
        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        # Use the enhanced IPFSClient method directly
        return self.ipfs.upload_directory(dir_path)
    
    def download_file(self, cid: str, output_path: str) -> Dict[str, Any]:
        """
        Download a file from IPFS.
        
        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
        
        Returns:
            Dict[str, Any]: Dictionary containing download details including:
                - success: Whether the download was successful
                - output_path: Path where the file was saved
                - size_bytes: Size of the downloaded file in bytes
                - size_formatted: Human-readable file size
                - elapsed_seconds: Time taken for the download
        
        Raises:
            requests.RequestException: If the download fails
        """
        return self.ipfs.download_file(cid, output_path)
    
    def cat(self, cid: str, max_display_bytes: int = 1024, format_output: bool = True) -> Dict[str, Any]:
        """
        Get the content of a file from IPFS.
        
        Args:
            cid: Content Identifier (CID) of the file
            max_display_bytes: Maximum number of bytes to include in the preview
            format_output: Whether to attempt to decode the content as text
            
        Returns:
            Dict[str, Any]: Dictionary containing content details including:
                - content: Complete binary content of the file
                - size_bytes: Size of the content in bytes
                - size_formatted: Human-readable size
                - is_text: Whether the content seems to be text
                - text_preview/hex_preview: Preview of the content
        """
        return self.ipfs.cat(cid, max_display_bytes, format_output)
    
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
