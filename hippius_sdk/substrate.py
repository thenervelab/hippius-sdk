import datetime
import json
import os
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Union

from dotenv import load_dotenv
from mnemonic import Mnemonic
from substrateinterface import Keypair, SubstrateInterface

from hippius_sdk.config import (
    get_account_address,
    get_active_account,
    get_all_config,
    get_config_value,
    get_seed_phrase,
    set_active_account,
    set_seed_phrase,
)
from hippius_sdk.utils import hex_to_ipfs_cid

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
        return {"fileHash": self.file_hash, "fileName": self.file_name}


class SubstrateClient:
    """
    Client for interacting with the Hippius Substrate blockchain.

    Provides functionality for storage requests and other blockchain operations.
    Note: This functionality is not fully implemented yet and is under active development.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        seed_phrase: Optional[str] = None,
        password: Optional[str] = None,
        account_name: Optional[str] = None,
    ):
        """
        Initialize the Substrate client.

        Args:
            url: WebSocket URL of the Hippius substrate node (from config if None)
            seed_phrase: Seed phrase for the account (mnemonic) (from config if None)
            password: Optional password to decrypt the seed phrase if it's encrypted
            account_name: Optional name of the account to use (uses active account if None)
        """
        # Load configuration values if not explicitly provided
        if url is None:
            url = get_config_value("substrate", "url", "wss://rpc.hippius.network")

        # Store URL and initialize variables
        self.url = url
        self._substrate = None
        self._keypair = None
        self._account_name = account_name or get_active_account()
        self._account_address = None
        self._read_only = False

        # Get the account address for read-only operations
        addr = get_account_address(self._account_name)
        if addr:
            self._account_address = addr

        # Set seed phrase if provided or available in configuration
        if seed_phrase:
            self.set_seed_phrase(seed_phrase)
        else:
            # Only try to get the seed phrase if we need it for the current operation
            # We'll defer this to when it's actually needed
            self._seed_phrase = None
            self._seed_phrase_password = password

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
                type_registry_preset="substrate-node-template",
            )

            # Only create keypair if seed phrase is available
            if hasattr(self, "_seed_phrase") and self._seed_phrase:
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                self._account_address = self._keypair.ss58_address
                print(
                    f"Connected successfully. Account address: {self._keypair.ss58_address}"
                )
                self._read_only = False
            elif self._account_address:
                print(
                    f"Connected successfully in read-only mode. Account address: {self._account_address}"
                )
                self._read_only = True
            else:
                print("Connected successfully (read-only mode, no account)")
                self._read_only = True

            return True

        except Exception as e:
            print(f"Failed to connect to Substrate node: {e}")
            raise ConnectionError(
                f"Could not connect to Substrate node at {self.url}: {e}"
            )

        return False

    def _ensure_keypair(self) -> bool:
        """
        Ensure we have a keypair for signing transactions.
        Will prompt for password if needed.

        Returns:
            bool: True if keypair is available, False if it couldn't be created
        """
        if self._keypair:
            return True

        # If we have a seed phrase, create the keypair
        if hasattr(self, "_seed_phrase") and self._seed_phrase:
            try:
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                self._account_address = self._keypair.ss58_address
                print(f"Keypair created for account: {self._keypair.ss58_address}")
                self._read_only = False
                return True
            except Exception as e:
                print(f"Warning: Could not create keypair from seed phrase: {e}")
                return False

        # Otherwise, try to get the seed phrase from config
        try:
            config_seed = get_seed_phrase(
                self._seed_phrase_password, self._account_name
            )
            if config_seed:
                self._seed_phrase = config_seed
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
                self._account_address = self._keypair.ss58_address
                print(f"Keypair created for account: {self._keypair.ss58_address}")
                self._read_only = False
                return True
            else:
                print("No seed phrase available. Cannot sign transactions.")
                return False
        except Exception as e:
            print(f"Warning: Could not get seed phrase from config: {e}")
            return False

    def generate_mnemonic(self) -> str:
        """
        Generate a new random 12-word mnemonic phrase.

        Returns:
            str: A 12-word mnemonic seed phrase
        """
        try:
            mnemo = Mnemonic("english")
            return mnemo.generate(strength=128)  # 128 bits = 12 words
        except Exception as e:
            raise ValueError(f"Error generating mnemonic: {e}")

    def create_account(
        self, name: str, encode: bool = False, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new account with a generated seed phrase.

        Args:
            name: Name for the new account
            encode: Whether to encrypt the seed phrase with a password
            password: Optional password for encryption (will prompt if not provided and encode=True)

        Returns:
            Dict[str, Any]: Dictionary with new account details
        """
        # Check if account name already exists
        config = get_all_config()
        if name in config["substrate"].get("accounts", {}):
            raise ValueError(f"Account with name '{name}' already exists")

        # Generate a new mnemonic seed phrase
        mnemonic = self.generate_mnemonic()

        # Create a keypair from the mnemonic
        keypair = Keypair.create_from_mnemonic(mnemonic)
        ss58_address = keypair.ss58_address

        # Save the seed phrase to configuration
        if encode:
            result = set_seed_phrase(
                mnemonic, encode=True, password=password, account_name=name
            )
        else:
            result = set_seed_phrase(mnemonic, encode=False, account_name=name)

        if not result:
            raise RuntimeError("Failed to save account to configuration")

        # Set this as the active account
        set_active_account(name)

        # Update the client's state to use this account
        self._account_name = name
        self._account_address = ss58_address
        self._seed_phrase = mnemonic
        self._keypair = keypair
        self._read_only = False

        # Return the new account details
        return {
            "name": name,
            "address": ss58_address,
            "mnemonic": mnemonic,
            "is_active": True,
            "creation_date": datetime.datetime.now().isoformat(),
        }

    def export_account(
        self, account_name: Optional[str] = None, file_path: Optional[str] = None
    ) -> str:
        """
        Export an account to a JSON file.

        Args:
            account_name: Name of the account to export (uses active account if None)
            file_path: Path to save the exported account file (auto-generated if None)

        Returns:
            str: Path to the exported account file
        """
        # Determine which account to export
        name_to_use = account_name or self._account_name or get_active_account()
        if not name_to_use:
            raise ValueError("No account specified and no active account")

        # Get the seed phrase and address
        seed_phrase = get_seed_phrase(account_name=name_to_use)
        if not seed_phrase:
            raise ValueError(
                f"Could not retrieve seed phrase for account '{name_to_use}'"
            )

        address = get_account_address(name_to_use)
        if not address:
            # Generate the address from the seed phrase
            keypair = Keypair.create_from_mnemonic(seed_phrase)
            address = keypair.ss58_address

        # Create the export data structure
        export_data = {
            "name": name_to_use,
            "address": address,
            "mnemonic": seed_phrase,
            "meta": {
                "exported_at": datetime.datetime.now().isoformat(),
                "description": "Hippius SDK exported account",
            },
        }

        # Determine the file path if not provided
        if not file_path:
            file_path = f"{name_to_use}_account_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Write the export file
        try:
            with open(file_path, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"Account '{name_to_use}' exported to {file_path}")
            return file_path
        except Exception as e:
            raise ValueError(f"Failed to export account: {e}")

    def import_account(
        self, file_path: str, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Import an account from a JSON file.

        Args:
            file_path: Path to the account export file
            password: Optional password to use for encrypting the imported seed phrase

        Returns:
            Dict[str, Any]: Dictionary with imported account details
        """
        try:
            # Read the export file
            with open(file_path, "r") as f:
                import_data = json.load(f)

            # Validate the import data structure
            required_fields = ["name", "address", "mnemonic"]
            for field in required_fields:
                if field not in import_data:
                    raise ValueError(
                        f"Invalid account file format: missing '{field}' field"
                    )

            # Extract account details
            name = import_data["name"]
            address = import_data["address"]
            mnemonic = import_data["mnemonic"]

            # Check if the account name already exists
            config = get_all_config()
            if name in config["substrate"].get("accounts", {}):
                # Modify the name to avoid conflicts
                original_name = name
                name = f"{name}_imported_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                print(
                    f"Account name '{original_name}' already exists, using '{name}' instead"
                )

            # Save the account to configuration
            if password:
                # Encrypt the seed phrase with the provided password
                result = set_seed_phrase(
                    mnemonic, encode=True, password=password, account_name=name
                )
            else:
                # Store the seed phrase in plain text
                result = set_seed_phrase(mnemonic, encode=False, account_name=name)

            if not result:
                raise RuntimeError("Failed to save imported account to configuration")

            # Set this as the active account
            set_active_account(name)

            # Update the client's state to use this account
            self._account_name = name
            self._account_address = address
            self._seed_phrase = mnemonic
            self._keypair = Keypair.create_from_mnemonic(mnemonic)
            self._read_only = False

            # Return the imported account details
            return {
                "name": name,
                "address": address,
                "is_active": True,
                "imported_at": datetime.datetime.now().isoformat(),
                "original_name": import_data.get("name"),
            }
        except Exception as e:
            raise ValueError(f"Failed to import account: {e}")

    async def get_account_info(
        self, account_name: Optional[str] = None, include_history: bool = False
    ) -> Dict[str, Any]:
        """
        Get detailed information about an account.

        Args:
            account_name: Name of the account to get info for (uses active account if None)
            include_history: Whether to include usage history in the results

        Returns:
            Dict[str, Any]: Detailed account information
        """
        # Determine which account to get info for
        name_to_use = account_name or self._account_name or get_active_account()
        if not name_to_use:
            raise ValueError("No account specified and no active account")

        # Get the configuration to extract account data
        config = get_all_config()

        # Check if the account exists
        if name_to_use not in config["substrate"].get("accounts", {}):
            raise ValueError(f"Account '{name_to_use}' not found")

        # Get account data from config
        account_data = config["substrate"]["accounts"][name_to_use]
        is_active = name_to_use == config["substrate"].get("active_account")
        is_encoded = account_data.get("seed_phrase_encoded", False)
        address = account_data.get("ss58_address")

        # Create the account info object
        account_info = {
            "name": name_to_use,
            "address": address,
            "is_active": is_active,
            "seed_phrase_encrypted": is_encoded,
        }

        # Query storage statistics for this account
        try:
            # Get files stored by this account - use await since this is an async method
            files = await self.get_user_files_from_profile(address)

            # Calculate storage statistics
            total_files = len(files)
            total_size_bytes = sum(file.get("file_size", 0) for file in files)

            # Add storage stats to account info
            account_info["storage_stats"] = {
                "files": total_files,
                "bytes_used": total_size_bytes,
                "size_formatted": self._format_size(total_size_bytes)
                if total_size_bytes
                else "0 B",
            }

            # Include file list if requested
            if include_history:
                account_info["files"] = files

                # Try to get account balance
                try:
                    account_info["balance"] = await self.get_account_balance(address)
                except Exception as e:
                    # Ignore balance errors, it's optional information
                    print(f"Could not fetch balance: {e}")
                    pass

                # Try to get free credits
                try:
                    account_info["free_credits"] = await self.get_free_credits(address)
                except Exception as e:
                    # Ignore credits errors, it's optional information
                    print(f"Could not fetch free credits: {e}")
                    pass
        except Exception as e:
            # Add a note about the error but don't fail the whole operation
            account_info["storage_stats"] = {
                "error": f"Could not fetch storage statistics: {str(e)}"
            }

        return account_info

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def set_seed_phrase(self, seed_phrase: str) -> None:
        """
        Set or update the seed phrase used for signing transactions.

        Args:
            seed_phrase: Mnemonic seed phrase for the account
        """
        if not seed_phrase or not seed_phrase.strip():
            raise ValueError("Seed phrase cannot be empty")

        # Store the seed phrase in memory for this session
        self._seed_phrase = seed_phrase.strip()
        self._read_only = False

        # Try to create the keypair if possible
        try:
            self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
            self._account_address = self._keypair.ss58_address
            print(f"Keypair created for account: {self._keypair.ss58_address}")
        except Exception as e:
            print(f"Warning: Could not create keypair from seed phrase: {e}")
            print(f"Keypair will be created when needed")

    async def storage_request(
        self, files: List[Union[FileInput, Dict[str, str]]], miner_ids: List[str] = None
    ) -> str:
        """
        Submit a storage request for IPFS files to the marketplace.

        This method creates a JSON file with the list of files to pin, uploads it to IPFS,
        and submits the CID of this file to the chain.

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
        # Check if we have a keypair for signing transactions
        if not self._ensure_keypair():
            raise ValueError("Seed phrase must be set before making transactions")

        # Convert any dict inputs to FileInput objects
        file_inputs = []
        for file in files:
            if isinstance(file, dict):
                file_inputs.append(
                    FileInput(
                        file_hash=file.get("fileHash") or file.get("cid"),
                        file_name=file.get("fileName")
                        or file.get("filename")
                        or "unknown",
                    )
                )
            else:
                file_inputs.append(file)

        # Print what is being submitted
        print(f"Preparing storage request for {len(file_inputs)} files:")
        for file in file_inputs:
            print(f"  - {file.file_name}: {file.file_hash}")

        if miner_ids:
            print(f"Targeted miners: {', '.join(miner_ids)}")
        else:
            print("No specific miners targeted (using default selection)")

        try:
            # Initialize Substrate connection
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Step 1: Create a JSON file with the list of files to pin
            file_list = []
            for file_input in file_inputs:
                file_list.append(
                    {"filename": file_input.file_name, "cid": file_input.file_hash}
                )

            # Convert to JSON
            files_json = json.dumps(file_list, indent=2)
            print(f"Created file list with {len(file_list)} entries")

            # Step 2: Upload the JSON file to IPFS
            # Defer import to avoid circular imports
            from hippius_sdk.ipfs import IPFSClient

            ipfs_client = IPFSClient()

            # Create a temporary file with the JSON content
            with tempfile.NamedTemporaryFile(
                mode="w+", suffix=".json", delete=False
            ) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(files_json)

            try:
                print("Uploading file list to IPFS...")
                upload_result = await ipfs_client.upload_file(temp_file_path)
                files_list_cid = upload_result["cid"]
                print(f"File list uploaded to IPFS with CID: {files_list_cid}")
            finally:
                # Clean up the temporary file
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

            # Step 3: Submit the CID of the JSON file to the chain
            # Create call parameters with the CID of the JSON file
            call_params = {
                "files_input": [
                    {
                        "file_hash": files_list_cid,
                        "file_name": f"files_list_{uuid.uuid4()}",  # Generate a unique ID
                    }
                ],
                "miner_ids": miner_ids if miner_ids else [],
            }

            # Create the call to the marketplace
            print(f"Call parameters: {json.dumps(call_params, indent=2)}")
            try:
                call = self._substrate.compose_call(
                    call_module="Marketplace",
                    call_function="storage_request",
                    call_params=call_params,
                )
            except Exception as e:
                print(f"Warning: Error composing call: {e}")
                print("Attempting to use IpfsPallet.storeFile instead...")

                # Try with IpfsPallet.storeFile as an alternative
                alt_call_params = {
                    "fileHash": files_list_cid,
                    "fileName": f"files_list_{uuid.uuid4()}",  # Generate a unique ID
                }
                call = self._substrate.compose_call(
                    call_module="IpfsPallet",
                    call_function="storeFile",
                    call_params=alt_call_params,
                )

            # Get payment info to estimate the fee
            payment_info = self._substrate.get_payment_info(
                call=call, keypair=self._keypair
            )

            print(f"Payment info: {json.dumps(payment_info, indent=2)}")

            # Convert partialFee from Substrate (10^18 units) to a more readable format
            estimated_fee = payment_info.get("partialFee", 0)
            estimated_fee_formatted = (
                float(estimated_fee) / 1_000_000_000_000_000_000 if estimated_fee else 0
            )
            print(
                f"Estimated transaction fee: {estimated_fee} ({estimated_fee_formatted:.10f} tokens)"
            )

            # Create a signed extrinsic
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call, keypair=self._keypair
            )

            print(
                f"Submitting transaction to store {len(file_list)} files via file list CID..."
            )

            # Submit the transaction
            response = self._substrate.submit_extrinsic(
                extrinsic=extrinsic, wait_for_inclusion=True
            )

            # Get the transaction hash
            tx_hash = response.extrinsic_hash

            print(f"Transaction submitted successfully!")
            print(f"Transaction hash: {tx_hash}")
            print(f"File list CID: {files_list_cid}")
            print(f"All {len(file_list)} files will be stored through this request")

            return tx_hash

        except ValueError as e:
            # Handle configuration errors
            print(f"Error: {e}")
            raise
        except Exception as e:
            print(f"Error interacting with Substrate: {e}")
            raise

        return "simulated-tx-hash"

    async def store_cid(
        self, cid: str, filename: str = None, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
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
        return await self.storage_request([file_input])

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
        # This requires a keypair for signing
        if not self._ensure_keypair():
            raise ValueError("Seed phrase must be set before making transactions")

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

    async def get_account_balance(
        self, account_address: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Get the balance of an account.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)

        Returns:
            Dict[str, float]: Account balances (free, reserved, total)
        """
        try:
            # Initialize Substrate connection if not already connected
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                    print(f"Using account address: {account_address}")
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address
                    print(f"Using keypair address: {account_address}")

            # Query the blockchain for account balance
            print(f"Querying balance for account: {account_address}")
            result = self._substrate.query(
                module="System",
                storage_function="Account",
                params=[account_address],
            )

            # If account exists, extract the balance information
            if result.value:
                data = result.value
                print(data)
                # Extract balance components
                free_balance = data.get("data", {}).get("free", 0)
                reserved_balance = data.get("data", {}).get("reserved", 0)
                frozen_balance = data.get("data", {}).get("frozen", 0)

                # Convert from blockchain units to float (divide by 10^18)
                divisor = 1_000_000_000_000_000_000  # 18 zeros for decimals

                free = float(free_balance) / divisor
                reserved = float(reserved_balance) / divisor
                frozen = float(frozen_balance) / divisor

                # Calculate total (free + reserved - frozen)
                total = free + reserved - frozen

                return {
                    "free": free,
                    "reserved": reserved,
                    "frozen": frozen,
                    "total": total,
                    "raw": {
                        "free": free_balance,
                        "reserved": reserved_balance,
                        "frozen": frozen_balance,
                    },
                }
            else:
                print(f"No account data found for: {account_address}")
                return {
                    "free": 0.0,
                    "reserved": 0.0,
                    "frozen": 0.0,
                    "total": 0.0,
                    "raw": {"free": 0, "reserved": 0, "frozen": 0},
                }

        except Exception as e:
            error_msg = f"Error querying account balance: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)

    async def watch_account_balance(
        self, account_address: Optional[str] = None, interval: int = 5
    ) -> None:
        """
        Watch account balance in real-time, updating at specified intervals.

        The function runs until interrupted with Ctrl+C.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
            interval: Polling interval in seconds (default: 5)
        """
        try:
            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address

            print(f"Watching balance for account: {account_address}")
            print(f"Updates every {interval} seconds. Press Ctrl+C to stop.")
            print("-" * 80)

            # Keep track of previous balance to show changes
            previous_balance = None

            try:
                while True:
                    # Get current time for display
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Get current balance
                    try:
                        balance = await self.get_account_balance(account_address)

                        # Clear screen (ANSI escape sequence)
                        print("\033c", end="")

                        # Display header
                        print(f"Account Balance Watch for: {account_address}")
                        print(f"Last update: {current_time}")
                        print("-" * 80)

                        # Display current balance
                        print(f"Free:     {balance['free']:.6f}")
                        print(f"Reserved: {balance['reserved']:.6f}")
                        print(f"Frozen:   {balance['frozen']:.6f}")
                        print(f"Total:    {balance['total']:.6f}")

                        # Show changes since last update if available
                        if previous_balance:
                            print("\nChanges since last update:")
                            free_change = balance["free"] - previous_balance["free"]
                            reserved_change = (
                                balance["reserved"] - previous_balance["reserved"]
                            )
                            total_change = balance["total"] - previous_balance["total"]

                            # Format changes with + or - sign
                            print(f"Free:     {free_change:+.6f}")
                            print(f"Reserved: {reserved_change:+.6f}")
                            print(f"Total:    {total_change:+.6f}")

                        # Store current balance for next comparison
                        previous_balance = balance

                        # Show instructions at the bottom
                        print(
                            "\nUpdating every",
                            interval,
                            "seconds. Press Ctrl+C to stop.",
                        )

                    except Exception as e:
                        # Show error but continue watching
                        print(f"Error: {e}")
                        print(f"Will try again in {interval} seconds...")

                    # Wait for next update
                    time.sleep(interval)

            except KeyboardInterrupt:
                print("\nBalance watch stopped.")

        except Exception as e:
            print(f"Error in watch_account_balance: {e}")

    async def get_free_credits(self, account_address: Optional[str] = None) -> float:
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
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                    print(f"Using account address: {account_address}")
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address
                    print(f"Using keypair address: {account_address}")

            # Query the blockchain for free credits
            print(f"Querying free credits for account: {account_address}")
            result = self._substrate.query(
                module="Credits",
                storage_function="FreeCredits",
                params=[account_address],
            )

            # If credits exist, convert to a float with 18 decimal places
            if result.value is not None:
                # Convert from blockchain u128 to float (divide by 10^18)
                credits_raw = int(result.value)
                credits_float = (
                    credits_raw / 1_000_000_000_000_000_000
                )  # 18 zeros for decimals
                print(f"Free credits: {credits_float} ({credits_raw} raw value)")
                return credits_float
            else:
                print(f"No credits found for account: {account_address}")
                raise ValueError(f"No credits found for account: {account_address}")

        except Exception as e:
            error_msg = f"Error querying free credits: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)

    def get_user_file_hashes(self, account_address: Optional[str] = None) -> List[str]:
        """
        Get all file hashes (CIDs) stored by a user in the marketplace.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH

        Returns:
            List[str]: List of CIDs stored by the user

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails or no files found
        """
        try:
            # Initialize Substrate connection if not already connected
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                    print(f"Using account address: {account_address}")
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address
                    print(f"Using keypair address: {account_address}")

            # Query the blockchain for user file hashes
            print(f"Querying file hashes for account: {account_address}")
            result = self._substrate.query(
                module="Marketplace",
                storage_function="UserFileHashes",
                params=[account_address],
            )

            # If files exist, convert to a list of CIDs
            if result.value:
                # The result is already a list of bytes, convert each to string
                file_hashes = [cid.hex() for cid in result.value]
                print(f"Found {len(file_hashes)} files stored by this account")
                return file_hashes
            else:
                print(f"No files found for account: {account_address}")
                return []

        except Exception as e:
            error_msg = f"Error querying user file hashes: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)

    async def get_user_files(
        self,
        account_address: Optional[str] = None,
        truncate_miners: bool = True,
        max_miners: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Get detailed information about all files stored by a user in the marketplace.

        This method uses a custom JSON-RPC endpoint to get comprehensive file information.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
            truncate_miners: Whether to truncate long miner IDs for display (default: True)
            max_miners: Maximum number of miners to include in the response (default: 3, 0 for all)

        Returns:
            List[Dict[str, Any]]: List of file objects with the following structure:
                {
                    "file_hash": str,         # The IPFS CID of the file
                    "file_name": str,         # The name of the file
                    "miner_ids": List[str],   # List of miner IDs that have pinned the file
                    "miner_ids_full": List[str], # Complete list of miner IDs (if truncated)
                    "miner_count": int,       # Total number of miners
                    "file_size": int,         # Size of the file in bytes
                    "size_formatted": str     # Human-readable file size
                }

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails
        """
        # For backward compatibility, this method now calls get_user_files_from_profile
        # with appropriate conversions
        return await self.get_user_files_from_profile(account_address)

    async def get_user_files_from_profile(
        self,
        account_address: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get user files by fetching the user profile CID from ipfsPallet and then retrieving
        the profile JSON from IPFS.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH

        Returns:
            List[Dict[str, Any]]: List of file objects from the user profile

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails or profile cannot be retrieved
        """
        try:
            # Initialize Substrate connection if not already connected
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                    print(f"Using account address: {account_address}")
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address
                    print(f"Using keypair address: {account_address}")

            # Query the blockchain for the user profile CID
            print(f"Querying user profile for account: {account_address}")
            result = self._substrate.query(
                module="IpfsPallet",
                storage_function="UserProfile",
                params=[account_address],
            )

            # Check if a profile was found
            if not result.value:
                print(f"No profile found for account: {account_address}")
                return []

            # The result is a hex-encoded IPFS CID
            # Handle both cases: bytes (needs .hex()) and string (already hex)
            if isinstance(result.value, bytes):
                hex_cid = result.value.hex()
            else:
                # If it's already a string, use it directly
                hex_cid = result.value

                # Remove '0x' prefix if present
                if hex_cid.startswith("0x"):
                    hex_cid = hex_cid[2:]

            print(f"Found user profile CID (hex): {hex_cid}")

            # Convert the hex CID to a readable IPFS CID
            profile_cid = self._hex_to_ipfs_cid(hex_cid)
            print(f"Decoded IPFS CID: {profile_cid}")

            # Fetch the profile JSON from IPFS
            # Defer import to avoid circular imports
            from hippius_sdk.ipfs import IPFSClient

            ipfs_client = IPFSClient()

            print(f"Fetching user profile from IPFS: {profile_cid}")
            profile_data = await ipfs_client.cat(profile_cid)

            # Parse the JSON content
            if not profile_data.get("is_text", False):
                raise ValueError("User profile is not in text format")

            profile_json = json.loads(profile_data.get("content", "{}"))
            print(f"Successfully retrieved user profile")

            # Extract the file list from the profile
            # The profile might be either a dictionary with a 'files' key or a direct list of files
            files = []
            if isinstance(profile_json, dict):
                files = profile_json.get("files", [])
            elif isinstance(profile_json, list):
                # The profile itself might be a list of files
                files = profile_json
            else:
                print(f"Warning: Unexpected profile structure: {type(profile_json)}")

            print(f"Found {len(files)} files in user profile")

            # Process the files to match the expected format
            processed_files = []
            for file in files:
                # Make sure file is a dictionary
                if not isinstance(file, dict):
                    # Skip non-dictionary entries silently
                    continue

                # Convert numeric arrays to strings if needed
                # Handle file_hash: could be an array of ASCII/UTF-8 code points
                file_hash = None
                raw_file_hash = file.get("file_hash")
                if isinstance(raw_file_hash, list) and all(
                    isinstance(n, int) for n in raw_file_hash
                ):
                    try:
                        # Convert array of numbers to bytes, then to a string
                        file_hash = bytes(raw_file_hash).decode("utf-8")
                    except Exception:
                        pass
                else:
                    # Try different field names for the CID that might be in the profile
                    file_hash = (
                        file.get("cid")
                        or file.get("hash")
                        or file.get("fileHash")
                        or raw_file_hash
                    )

                # Handle file_name: could be an array of ASCII/UTF-8 code points
                file_name = None
                raw_file_name = file.get("file_name")
                if isinstance(raw_file_name, list) and all(
                    isinstance(n, int) for n in raw_file_name
                ):
                    try:
                        # Convert array of numbers to bytes, then to a string
                        file_name = bytes(raw_file_name).decode("utf-8")
                    except Exception:
                        pass
                else:
                    # Try different field names for the filename
                    file_name = (
                        file.get("filename")
                        or file.get("name")
                        or file.get("fileName")
                        or raw_file_name
                    )

                # Try different field names for the size
                file_size = (
                    file.get("size")
                    or file.get("fileSize")
                    or file.get("file_size")
                    or file.get("file_size_in_bytes")
                    or 0
                )

                processed_file = {
                    "file_hash": file_hash,
                    "file_name": file_name,
                    # Add any other fields available in the profile
                    "miner_ids": file.get(
                        "miner_ids", []
                    ),  # Try to get miners if available
                    "miner_count": len(file.get("miner_ids", [])),  # Count the miners
                    "file_size": file_size or 0,
                }

                # Add formatted file size if available
                if file_size:
                    size_bytes = file_size
                    if size_bytes >= 1024 * 1024:
                        processed_file[
                            "size_formatted"
                        ] = f"{size_bytes / (1024 * 1024):.2f} MB"
                    else:
                        processed_file["size_formatted"] = f"{size_bytes / 1024:.2f} KB"
                else:
                    processed_file["size_formatted"] = "Unknown"

                processed_files.append(processed_file)

            return processed_files

        except Exception as e:
            error_msg = f"Error retrieving user files from profile: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)

    def get_pinning_status(
        self, account_address: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get the status of file pinning requests for an account.

        This method queries the blockchain for all storage requests made by the user
        to check their pinning status.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5HoreGVb17XhY3wanDvzoAWS7yHYbc5uMteXqRNTiZ6Txkqq

        Returns:
            List[Dict[str, Any]]: List of storage requests with their status information:
                {
                    "cid": str,              # The IPFS CID of the file
                    "file_name": str,        # The name of the file
                    "total_replicas": int,   # Total number of replicas requested
                    "owner": str,            # Owner's address
                    "created_at": int,       # Block number when request was created
                    "last_charged_at": int,  # Block number when last charged
                    "miner_ids": List[str],  # List of miners assigned to pin the file
                    "selected_validator": str, # Selected validator address
                    "is_assigned": bool,     # Whether request has been assigned to miners
                }

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails or no requests found
        """
        try:
            # Initialize Substrate connection if not already connected
            if not hasattr(self, "_substrate") or self._substrate is None:
                print("Initializing Substrate connection...")
                self._substrate = SubstrateInterface(
                    url=self.url,
                    ss58_format=42,  # Substrate default
                    type_registry_preset="substrate-node-template",
                )
                print(f"Connected to Substrate node at {self.url}")

            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                    print(f"Using account address: {account_address}")
                else:
                    # Try to get the address from the keypair (requires seed phrase)
                    if not self._ensure_keypair():
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address
                    print(f"Using keypair address: {account_address}")

            # Query the blockchain for storage requests
            print(f"Querying storage requests for account: {account_address}")
            try:
                # First, try with query_map which is more suitable for iterating over collections
                result = self._substrate.query_map(
                    module="IpfsPallet",
                    storage_function="UserStorageRequests",
                    params=[account_address],
                )
                results_list = list(result)
            except Exception as e:
                print(f"Error with query_map: {e}")
                try:
                    # Try again with query to double check storage function requirements
                    result = self._substrate.query(
                        module="IpfsPallet",
                        storage_function="UserStorageRequests",
                        params=[
                            account_address,
                            None,
                        ],  # Try with a None second parameter
                    )

                    # If the query returns a nested structure, extract it
                    if result.value and isinstance(result.value, list):
                        # Convert to a list format similar to query_map for processing
                        results_list = []
                        for item in result.value:
                            if isinstance(item, list) and len(item) >= 2:
                                key = item[0]
                                value = item[1]
                                results_list.append((key, value))
                    else:
                        # If it's not a nested structure, use a simpler format
                        results_list = [(None, result.value)] if result.value else []
                except Exception as e_inner:
                    print(f"Error with fallback query: {e_inner}")
                    # If both methods fail, return an empty list
                    results_list = []

            # Process the storage requests
            storage_requests = []

            if not results_list:
                print(f"No storage requests found for account: {account_address}")
                return []

            print(f"Found {len(results_list)} storage request entries")

            for i, (key, value) in enumerate(results_list):
                try:
                    # For debugging, print raw data
                    print(f"Entry {i+1}:")
                    print(f"  Raw key: {key}, type: {type(key)}")
                    print(f"  Raw value: {value}, type: {type(value)}")

                    # Extract file hash from key if possible
                    file_hash_hex = None
                    if key is not None:
                        if hasattr(key, "hex"):
                            file_hash_hex = key.hex()
                        elif isinstance(key, bytes):
                            file_hash_hex = key.hex()
                        elif isinstance(key, str) and key.startswith("0x"):
                            file_hash_hex = key[2:]
                        else:
                            file_hash_hex = str(key)

                    # Try to extract value data
                    request_data = None
                    if isinstance(value, dict):
                        request_data = value
                    elif hasattr(value, "get"):
                        request_data = value
                    elif hasattr(value, "__dict__"):
                        # Convert object to dict
                        request_data = {
                            k: getattr(value, k)
                            for k in dir(value)
                            if not k.startswith("_") and not callable(getattr(value, k))
                        }

                    # If we can't extract data, just use value as string for debugging
                    if request_data is None:
                        request_data = {"raw_value": str(value)}

                    # Create formatted request with available data
                    formatted_request = {"raw_key": str(key), "raw_value": str(value)}

                    # Directly extract file_name from the value if it's a dict-like object
                    if hasattr(value, "get"):
                        if value.get("file_name"):
                            formatted_request["file_name"] = value.get("file_name")
                        elif value.get("fileName"):
                            formatted_request["file_name"] = value.get("fileName")

                    # Add CID if we have it
                    if file_hash_hex:
                        file_cid = self._hex_to_ipfs_cid(file_hash_hex)
                        formatted_request["cid"] = file_cid

                    # Add other fields from request_data if available
                    for source_field, target_field in [
                        ("fileName", "file_name"),
                        ("totalReplicas", "total_replicas"),
                        ("owner", "owner"),
                        ("createdAt", "created_at"),
                        ("lastChargedAt", "last_charged_at"),
                        ("minerIds", "miner_ids"),
                        ("selectedValidator", "selected_validator"),
                        ("isAssigned", "is_assigned"),
                        # Add variants that might appear differently in the chain storage
                        ("file_name", "file_name"),
                        ("file_hash", "file_hash"),
                        ("total_replicas", "total_replicas"),
                    ]:
                        if source_field in request_data:
                            formatted_request[target_field] = request_data[source_field]
                        # Fallback to attribute access for different types of objects
                        elif hasattr(value, source_field):
                            formatted_request[target_field] = getattr(
                                value, source_field
                            )

                    storage_requests.append(formatted_request)

                except Exception as e:
                    print(f"Error processing request entry {i+1}: {e}")

            print(f"Successfully processed {len(storage_requests)} storage requests")
            return storage_requests

        except Exception as e:
            error_msg = f"Error querying storage requests: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)

    def _hex_to_ipfs_cid(self, hex_string: str) -> str:
        """
        Convert a hex-encoded IPFS CID to a regular IPFS CID.

        Args:
            hex_string: Hex string representation of an IPFS CID

        Returns:
            str: Regular IPFS CID
        """
        return hex_to_ipfs_cid(hex_string)
