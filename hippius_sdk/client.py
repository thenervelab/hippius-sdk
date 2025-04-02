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
            Dict[str, Any]: Dictionary containing CID
        
        Raises:
            FileNotFoundError: If the file doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        # Upload to IPFS
        cid = self.ipfs.upload_file(file_path)
        
        result = {
            "cid": cid,
            "filename": os.path.basename(file_path),
            "size_bytes": os.path.getsize(file_path),
        }
        
        return result
    
    def upload_directory(self, dir_path: str) -> Dict[str, Any]:
        """
        Upload a directory to IPFS.
        
        Args:
            dir_path: Path to the directory to upload
        
        Returns:
            Dict[str, Any]: Dictionary containing CID
        
        Raises:
            FileNotFoundError: If the directory doesn't exist
            ConnectionError: If no IPFS connection is available
        """
        # Upload to IPFS
        cid = self.ipfs.upload_directory(dir_path)
        
        result = {
            "cid": cid,
            "dirname": os.path.basename(dir_path),
        }
        
        return result
    
    def download_file(self, cid: str, output_path: str) -> None:
        """
        Download a file from IPFS.
        
        Args:
            cid: Content Identifier (CID) of the file to download
            output_path: Path where the downloaded file will be saved
        
        Raises:
            requests.RequestException: If the download fails
        """
        self.ipfs.download_file(cid, output_path)
    
    def cat(self, cid: str) -> bytes:
        """
        Get the content of a file from IPFS.
        
        Args:
            cid: Content Identifier (CID) of the file
            
        Returns:
            bytes: Content of the file
        """
        return self.ipfs.cat(cid)
    
    def exists(self, cid: str) -> bool:
        """
        Check if a CID exists on IPFS.
        
        Args:
            cid: Content Identifier (CID) to check
            
        Returns:
            bool: True if the CID exists, False otherwise
        """
        return self.ipfs.exists(cid)
    
    def pin(self, cid: str) -> bool:
        """
        Pin a CID to IPFS to keep it available.
        
        Args:
            cid: Content Identifier (CID) to pin
            
        Returns:
            bool: True if pinning was successful, False otherwise
        """
        return self.ipfs.pin(cid)
