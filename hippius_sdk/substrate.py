"""
Substrate operations for the Hippius SDK.

Note: This functionality is coming soon and not implemented yet.
"""

import os
import json
from typing import Dict, Any, Optional, List, Union
from substrateinterface import SubstrateInterface, Keypair
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class FileInput:
    """File input for storage requests"""
    
    def __init__(self, file_hash: str, file_name: str):
        """
        Initialize a file input
        
        Args:
            file_hash: IPFS hash (CID) of the file
            file_name: Name of the file
        """
        self.file_hash = file_hash
        self.file_name = file_name
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary representation"""
        return {
            "fileHash": self.file_hash,
            "fileName": self.file_name
        }


class SubstrateClient:
    """
    Client for interacting with the Hippius Substrate blockchain.
    
    Note: This functionality is not fully implemented yet and is under active development.
    """
    
    def __init__(self, url: str = None, seed_phrase: Optional[str] = None):
        """
        Initialize the Substrate client.
        
        Args:
            url: WebSocket URL of the Hippius substrate node
                If not provided, uses SUBSTRATE_URL from environment
            seed_phrase: Seed phrase for the account (mnemonic)
                If not provided, uses SUBSTRATE_SEED_PHRASE from environment
        """
        if not url:
            url = os.getenv("SUBSTRATE_URL", "wss://rpc.hippius.network")
        
        # Store URL and initialize variables
        self.url = url
        self._substrate = None
        self._keypair = None
        
        # Set seed phrase if provided or available in environment
        if seed_phrase:
            self.set_seed_phrase(seed_phrase)
        elif os.getenv("SUBSTRATE_SEED_PHRASE"):
            self.set_seed_phrase(os.getenv("SUBSTRATE_SEED_PHRASE"))
            
        # Don't connect immediately to avoid exceptions during initialization
        # Connection will happen lazily when needed
    
    def connect(self) -> None:
        """
        Connect to the Substrate node.
        
        Initializes the connection to the Substrate node and creates a keypair from the seed phrase.
        """
        try:
            print(f"Connecting to Substrate node at {self.url}...")
            self._substrate = SubstrateInterface(
                url=self.url,
                ss58_format=42,  # Substrate default
                type_registry_preset='substrate-node-template'
            )
            
            # Only create keypair if seed phrase is available
            if hasattr(self, '_seed_phrase') and self._seed_phrase:
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                print(f"Connected successfully. Account address: {self._keypair.ss58_address}")
            else:
                print("Connected successfully (read-only mode, no keypair)")
                
            return True
            
        except Exception as e:
            print(f"Failed to connect to Substrate node: {e}")
            raise ConnectionError(f"Could not connect to Substrate node at {self.url}: {e}")
        
        return False
    
    def set_seed_phrase(self, seed_phrase: str) -> None:
        """
        Set or update the seed phrase used for signing transactions.
        
        Args:
            seed_phrase: Mnemonic seed phrase for the account
        """
        if not seed_phrase or not seed_phrase.strip():
            raise ValueError("Seed phrase cannot be empty")
            
        # Store the seed phrase
        self._seed_phrase = seed_phrase.strip()
        
        # Try to create the keypair if possible
        try:
            if hasattr(self, '_substrate') and self._substrate:
                # If we already have a connection, create the keypair
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                print(f"Keypair created for account: {self._keypair.ss58_address}")
            else:
                print(f"Seed phrase set (keypair will be created when connecting)")
        except Exception as e:
            print(f"Warning: Could not create keypair from seed phrase: {e}")
            print(f"Keypair will be created when needed")
    
    def storage_request(self, files: List[Union[FileInput, Dict[str, str]]], miner_ids: List[str] = None) -> str:
        """
        Submit a storage request for IPFS files to the marketplace.
        
        This method batches all files into a single transaction to efficiently store
        multiple files at once.
        
        Args:
            files: List of FileInput objects or dictionaries with fileHash and fileName
            miner_ids: List of miner IDs to store the files (optional)
        
        Returns:
            str: Transaction hash
        
        Example:
            >>> client.storage_request([
            ...     FileInput("QmHash1", "file1.txt"),
            ...     FileInput("QmHash2", "file2.jpg")
            ... ])
        """
        # Convert any dict inputs to FileInput objects
        file_inputs = []
        for file in files:
            if isinstance(file, dict):
                file_inputs.append(FileInput(
                    file_hash=file.get("fileHash") or file.get("cid"),
                    file_name=file.get("fileName") or file.get("filename") or "unknown"
                ))
            else:
                file_inputs.append(file)
        
        # Print what is being submitted
        print(f"Submitting storage request for {len(file_inputs)} files as a batch:")
        for file in file_inputs:
            print(f"  - {file.file_name}: {file.file_hash}")
        
        if miner_ids:
            print(f"Targeted miners: {', '.join(miner_ids)}")
        else:
            print("No specific miners targeted (using default selection)")
        
        try:
            # Initialize Substrate connection
            if not hasattr(self, '_substrate') or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset='substrate-node-template'
                )
                print(f"Connected to Substrate node at {self.url}")
            
            # Create keypair from seed phrase if not already created
            if not hasattr(self, '_keypair') or self._keypair is None:
                if not hasattr(self, '_seed_phrase') or not self._seed_phrase:
                    raise ValueError("Seed phrase must be set before making transactions")
                
                print("Creating keypair from seed phrase...")
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                print(f"Keypair created for address: {self._keypair.ss58_address}")
            
            # Prepare storage request call
            print("Preparing marketplace.storageRequest batch call...")
            
            # Format files for the batch call - all files are included in a single array
            formatted_files = []
            for file_input in file_inputs:
                formatted_files.append({
                    'file_hash': file_input.file_hash,
                    'file_name': file_input.file_name
                })
            
            # Create call parameters with all files in a single batch
            call_params = {
                'files_input': formatted_files,
                'miner_ids': miner_ids if miner_ids else []  # Always include miner_ids, empty array if not specified
            }
            
            # Create the call to the marketplace
            print(f"Call parameters: {json.dumps(call_params, indent=2)}")
            call = self._substrate.compose_call(
                call_module='Marketplace',
                call_function='storage_request',
                call_params=call_params
            )
            
            # Get payment info to estimate the fee
            payment_info = self._substrate.get_payment_info(
                call=call,
                keypair=self._keypair
            )
            
            estimated_fee = payment_info.get('partialFee', 0) 
            print(f"Estimated transaction fee: {estimated_fee}")
            
            # Create a signed extrinsic
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call,
                keypair=self._keypair
            )
            
            print(f"Submitting batch transaction for {len(formatted_files)} files...")
            
            # Submit the transaction
            response = self._substrate.submit_extrinsic(
                extrinsic=extrinsic,
                wait_for_inclusion=True
            )
            
            # Get the transaction hash
            tx_hash = response.extrinsic_hash
            
            print(f"Batch transaction submitted successfully!")
            print(f"Transaction hash: {tx_hash}")
            print(f"All {len(formatted_files)} files have been stored in a single transaction")
            
            return tx_hash
            
        except ValueError as e:
            # Handle configuration errors
            print(f"Error: {e}")
            raise
        except Exception as e:
            print(f"Error interacting with Substrate: {e}")
            raise
            
        return "simulated-tx-hash"
    
    def store_cid(self, cid: str, filename: str = None, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Store a CID on the blockchain.
        
        Args:
            cid: Content Identifier (CID) to store
            filename: Original filename (optional)
            metadata: Additional metadata to store with the CID
        
        Returns:
            str: Transaction hash
        """
        file_input = FileInput(file_hash=cid, file_name=filename or "unnamed_file")
        return self.storage_request([file_input])
    
    def get_cid_metadata(self, cid: str) -> Dict[str, Any]:
        """
        Retrieve metadata for a CID from the blockchain.
        
        Args:
            cid: Content Identifier (CID) to query
        
        Returns:
            Dict[str, Any]: Metadata associated with the CID
        """
        raise NotImplementedError("Substrate functionality is not implemented yet.")
    
    def get_account_cids(self, account_address: str) -> List[str]:
        """
        Get all CIDs associated with an account.
        
        Args:
            account_address: Substrate account address
        
        Returns:
            List[str]: List of CIDs owned by the account
        """
        raise NotImplementedError("Substrate functionality is not implemented yet.")
    
    def delete_cid(self, cid: str) -> str:
        """
        Delete a CID from the blockchain (mark as removed).
        
        Args:
            cid: Content Identifier (CID) to delete
        
        Returns:
            str: Transaction hash
        """
        raise NotImplementedError("Substrate functionality is not implemented yet.")
    
    def get_storage_fee(self, file_size_mb: float) -> float:
        """
        Get the estimated storage fee for a file of given size.
        
        Args:
            file_size_mb: File size in megabytes
        
        Returns:
            float: Estimated fee in native tokens
        """
        raise NotImplementedError("Substrate functionality is not implemented yet.")
    
    def get_account_balance(self, account_address: Optional[str] = None) -> Dict[str, float]:
        """
        Get the balance of an account.
        
        Args:
            account_address: Substrate account address (uses keypair address if not specified)
        
        Returns:
            Dict[str, float]: Account balances (free, reserved, total)
        """
        raise NotImplementedError("Substrate functionality is not implemented yet.")
        
    def get_free_credits(self, account_address: Optional[str] = None) -> float:
        """
        Get the free credits available for an account in the marketplace.
        
        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
        
        Returns:
            float: Free credits amount (with 18 decimal places)
        
        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If account has no credits
        """
        try:
            # Initialize Substrate connection if not already connected
            if not hasattr(self, '_substrate') or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset='substrate-node-template'
                )
                print(f"Connected to Substrate node at {self.url}")
            
            # Use provided account address or default to keypair address
            if not account_address:
                if not hasattr(self, '_keypair') or self._keypair is None:
                    if not hasattr(self, '_seed_phrase') or not self._seed_phrase:
                        raise ValueError("No account address provided and no seed phrase is set")
                    
                    print("Creating keypair from seed phrase to get account address...")
                    self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                
                account_address = self._keypair.ss58_address
                print(f"Using keypair address: {account_address}")
            
            # Query the blockchain for free credits
            print(f"Querying free credits for account: {account_address}")
            result = self._substrate.query(
                module='Credits',
                storage_function='FreeCredits',
                params=[account_address]
            )
            
            # If credits exist, convert to a float with 18 decimal places
            if result.value is not None:
                # Convert from blockchain u128 to float (divide by 10^18)
                credits_raw = int(result.value)
                credits_float = credits_raw / 1_000_000_000_000_000_000  # 18 zeros for decimals
                print(f"Free credits: {credits_float} ({credits_raw} raw value)")
                return credits_float
            else:
                print(f"No credits found for account: {account_address}")
                raise ValueError(f"No credits found for account: {account_address}")
                
        except Exception as e:
            error_msg = f"Error querying free credits: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)
