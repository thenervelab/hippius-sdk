import datetime
import json
import os
import pprint
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
from hippius_sdk.errors import (
    HippiusAlreadyDeletedError,
    HippiusFailedSubstrateDelete,
    HippiusNotFoundError,
    HippiusSubstrateAuthError,
    HippiusSubstrateConnectionError,
)
from hippius_sdk.utils import (
    format_size,
    hex_to_ipfs_cid,
    initialize_substrate_connection,
)

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
        password: Optional[str] = None,
        account_name: Optional[str] = None,
        seed_phrase: Optional[str] = None,
    ):
        """
        Initialize the Substrate client.

        Args:
            url: WebSocket URL of the Hippius substrate node (from config if None)
            password: Optional password to decrypt the seed phrase if it's encrypted
            account_name: Optional name of the account to use (uses active account if None)
            seed_phrase: Optional unencrypted seed phrase to use directly (bypasses config)
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
        self._seed_phrase_password = password

        # Get the account address for read-only operations
        addr = get_account_address(self._account_name)
        if addr:
            self._account_address = addr

        self._seed_phrase = seed_phrase  # Use passed seed phrase if provided

        # Don't connect immediately to avoid exceptions during initialization
        # Connection will happen lazily when needed

    def connect(self, seed_phrase: Optional[str] = None) -> None:
        """
        Connect to the Substrate node.

        Initializes the connection to the Substrate node and creates a keypair from the seed phrase.

        Args:
            seed_phrase: Optional seed phrase for the connection
        """
        try:
            print(f"Connecting to Substrate node at {self.url}...")
            self._substrate = SubstrateInterface(
                url=self.url,
                ss58_format=42,  # Substrate default
                type_registry_preset="substrate-node-template",
            )

            # Create keypair if seed_phrase is provided or try to get from config
            if self._ensure_keypair(seed_phrase):
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

        except Exception as e:
            print(f"Failed to connect to Substrate node: {e}")
            raise ConnectionError(
                f"Could not connect to Substrate node at {self.url}: {e}"
            )

    def _ensure_keypair(self, seed_phrase: Optional[str] = None) -> bool:
        """
        Ensure we have a keypair for signing transactions.
        Will use the provided seed_phrase if given, otherwise get it from config.

        Args:
            seed_phrase: Optional seed phrase to use for creating keypair

        Returns:
            bool: True if keypair is available, False if it couldn't be created
        """
        # If we already have a keypair and no new seed phrase was provided, use existing keypair
        if self._keypair and not seed_phrase:
            return True

        # If a seed phrase was provided, use it to create a keypair
        if seed_phrase:
            try:
                self._keypair = Keypair.create_from_mnemonic(seed_phrase)
                self._account_address = self._keypair.ss58_address
                self._read_only = False
                return True
            except Exception as e:
                print(
                    f"Warning: Could not create keypair from provided seed phrase: {e}"
                )
                return False

        # Otherwise, try to get the seed phrase from config
        config_seed = get_seed_phrase(self._seed_phrase_password, self._account_name)
        if config_seed:
            try:
                self._keypair = Keypair.create_from_mnemonic(config_seed)
                self._account_address = self._keypair.ss58_address
                self._read_only = False
                return True
            except Exception as e:
                print(f"Warning: Could not create keypair from config seed phrase: {e}")
                return False
        else:
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

    def generate_seed_phrase(self) -> str:
        """
        Generate a new random seed phrase (alias for generate_mnemonic).

        Returns:
            str: A 12-word mnemonic seed phrase
        """
        return self.generate_mnemonic()

    def set_seed_phrase(self, seed_phrase: str) -> None:
        """
        Set or update the seed phrase used for signing transactions.

        Note: This method is kept for backward compatibility.
        The preferred approach is to pass seed_phrase to individual methods.

        Args:
            seed_phrase: Mnemonic seed phrase for the account
        """
        if not seed_phrase or not seed_phrase.strip():
            raise ValueError("Seed phrase cannot be empty")

        # Store the seed phrase in memory for this session (deprecated)
        self._seed_phrase = seed_phrase.strip()

        # Create the keypair for future operations
        self._ensure_keypair(seed_phrase)

    def create_account(
        self, name: str, encode: bool = False, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new account with a generated seed phrase.

        Args:
            name: Name for the new account
            encode: Whether to encrypt the seed phrase with a password.
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
        # Set seed phrase using the method to ensure proper state update
        self.set_seed_phrase(mnemonic)
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
            # Set seed phrase using the method to ensure proper state update
            self.set_seed_phrase(mnemonic)
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
                "size_formatted": format_size(total_size_bytes)
                if total_size_bytes
                else "0 bytes",
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

    async def storage_request(
        self,
        files: List[Union[FileInput, Dict[str, str]]],
        miner_ids: List[str] = None,
        seed_phrase: Optional[str] = None,
    ) -> str:
        """
        Submit a storage request for IPFS files to the marketplace.

        This method creates a JSON file with the list of files to pin, uploads it to IPFS,
        and submits the CID of this file to the chain.

        Args:
            files: List of FileInput objects or dictionaries with fileHash and fileName
            miner_ids: List of miner IDs to store the files (optional)
            seed_phrase: Optional seed phrase to use for this transaction (uses config if None)

        Returns:
            str: Transaction hash

        Example:
            >>> client.storage_request([
            ...     FileInput("QmHash1", "file1.txt"),
            ...     FileInput("QmHash2", "file2.jpg")
            ... ])
        """
        # Check if we have a keypair for signing transactions
        if not self._ensure_keypair(seed_phrase):
            raise ValueError(
                "Valid seed phrase must be provided or available in config"
            )

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
        for file in file_inputs:
            print(f"  - {file.file_name}: {file.file_hash}")

        # Initialize Substrate connection with seed phrase
        if not self._substrate:
            self.connect(seed_phrase)

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
        call = self._substrate.compose_call(
            call_module="Marketplace",
            call_function="storage_request",
            call_params=call_params,
        )

        # Get payment info to estimate the fee
        payment_info = self._substrate.get_payment_info(
            call=call,
            keypair=self._keypair,
        )

        print(f"]Payment info: {json.dumps(payment_info, indent=2)}")

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

        return tx_hash

    async def store_cid(
        self,
        cid: str,
        filename: str = None,
        seed_phrase: Optional[str] = None,
    ) -> str:
        """
        Store a CID on the blockchain.

        Args:
            cid: Content Identifier (CID) to store
            filename: Original filename (optional)
            seed_phrase: Optional seed phrase to use for this transaction (uses config if None)

        Returns:
            str: Transaction hash
        """
        file_input = FileInput(file_hash=cid, file_name=filename or "unnamed_file")
        return await self.storage_request([file_input], seed_phrase=seed_phrase)

    async def get_account_balance(
        self, account_address: Optional[str] = None, seed_phrase: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Get the balance of an account.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            Dict[str, float]: Account balances (free, reserved, total)
        """
        try:
            # Initialize Substrate connection and get account address
            substrate, derived_address = initialize_substrate_connection(
                self, seed_phrase
            )

            # Use provided account address or the one derived from initialization
            if not account_address:
                if derived_address:
                    account_address = derived_address
                else:
                    raise ValueError("No account address available")

            # Query the blockchain for account balance
            result = self._substrate.query(
                module="System",
                storage_function="Account",
                params=[account_address],
            )

            # If account exists, extract the balance information
            if result.value:
                data = result.value
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
                return {
                    "free": 0.0,
                    "reserved": 0.0,
                    "frozen": 0.0,
                    "total": 0.0,
                    "raw": {"free": 0, "reserved": 0, "frozen": 0},
                }

        except Exception as e:
            raise ValueError(f"Error querying account balance: {str(e)}")

    async def watch_account_balance(
        self,
        account_address: Optional[str] = None,
        interval: int = 5,
        seed_phrase: Optional[str] = None,
    ) -> None:
        """
        Watch account balance in real-time, updating at specified intervals.

        The function runs until interrupted with Ctrl+C.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
            interval: Polling interval in seconds (default: 5)
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)
        """
        try:
            # Use provided account address or default to keypair/configured address
            if not account_address:
                if self._account_address:
                    account_address = self._account_address
                else:
                    # Try to get the address from the keypair (with seed phrase if provided)
                    if not self._ensure_keypair(seed_phrase):
                        raise ValueError("No account address available")
                    account_address = self._keypair.ss58_address

            # Keep track of previous balance to show changes
            previous_balance = None

            try:
                while True:
                    # Get current time for display
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Get current balance
                    try:
                        balance = await self.get_account_balance(
                            account_address, seed_phrase
                        )

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

    async def get_free_credits(
        self, account_address: Optional[str] = None, seed_phrase: Optional[str] = None
    ) -> float:
        """
        Get the free credits available for an account in the marketplace.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            float: Free credits amount (with 18 decimal places)

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If account has no credits
        """
        try:
            # Initialize Substrate connection and get account address
            substrate, derived_address = initialize_substrate_connection(
                self, seed_phrase
            )

            # Use provided account address or the one derived from initialization
            if not account_address:
                if derived_address:
                    account_address = derived_address
                else:
                    raise ValueError("No account address available")

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

    def get_user_file_hashes(
        self, account_address: Optional[str] = None, seed_phrase: Optional[str] = None
    ) -> List[str]:
        """
        Get all file hashes (CIDs) stored by a user in the marketplace.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            List[str]: List of CIDs stored by the user

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails or no files found
        """
        try:
            # Initialize Substrate connection and get account address
            substrate, derived_address = initialize_substrate_connection(
                self, seed_phrase
            )

            # Use provided account address or the one derived from initialization
            if not account_address:
                if derived_address:
                    account_address = derived_address
                else:
                    raise ValueError("No account address available")

            # Query the blockchain for user file hashes
            result = self._substrate.query(
                module="Marketplace",
                storage_function="UserFileHashes",
                params=[account_address],
            )

            # If files exist, convert to a list of CIDs
            if result.value:
                # The result is already a list of bytes, convert each to string
                file_hashes = [cid.hex() for cid in result.value]
                return file_hashes
            else:
                return []

        except Exception as e:
            raise ValueError(f"Error querying user file hashes: {str(e)}")

    async def get_user_files(
        self,
        account_address: Optional[str] = None,
        truncate_miners: bool = True,
        max_miners: int = 3,
        seed_phrase: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get detailed information about all files stored by a user in the marketplace.

        This method uses a custom JSON-RPC endpoint to get comprehensive file information.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
            truncate_miners: Whether to truncate long miner IDs for display (default: True)
            max_miners: Maximum number of miners to include in the response (default: 3, 0 for all)
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            List[Dict[str, Any]]: List of file objects with the following structure:
                {
                    "file_hash": str,         # The IPFS CID of the file
                    "file_name": str,         # The name of the file
                    "miner_ids": List[str],   # List of miner IDs that have pinned the file
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
        return await self.get_user_files_from_profile(account_address, seed_phrase)

    async def get_user_files_from_profile(
        self,
        account_address: Optional[str] = None,
        seed_phrase: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get user files by fetching the user profile CID from ipfsPallet and then retrieving
        the profile JSON from IPFS.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            List[Dict[str, Any]]: List of file objects from the user profile

        Raises:
            ConnectionError: If connection to Substrate fails
            ValueError: If query fails or profile cannot be retrieved
        """
        try:
            # Initialize Substrate connection and get account address
            substrate, derived_address = initialize_substrate_connection(
                self, seed_phrase
            )

            # Use provided account address or the one derived from initialization
            if not account_address:
                if derived_address:
                    account_address = derived_address
                else:
                    raise ValueError("No account address available")

            # Query the blockchain for the user profile CID
            profile_hex_cid = self._substrate.query(
                module="IpfsPallet",
                storage_function="UserProfile",
                params=[account_address],
            ).value

            if not profile_hex_cid:
                return []

            profile_cid = self._hex_to_ipfs_cid(profile_hex_cid)

            # Fetch the profile JSON from IPFS
            # Defer import to avoid circular imports
            from hippius_sdk.ipfs import IPFSClient

            ipfs_client = IPFSClient()
            profile_content = (await ipfs_client.cat(profile_cid))["content"]
            files = json.loads(profile_content)
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
                    except Exception as e:
                        print(e)

                # Handle file_name: could be an array of ASCII/UTF-8 code points
                # Try different field names for the size
                file_size = (
                    file.get("size")
                    or file.get("fileSize")
                    or file.get("file_size")
                    or file.get("file_size_in_bytes")
                    or 0
                )

                processed_file = {
                    "cid": self._hex_to_ipfs_cid(file_hash),
                    "file_hash": file_hash,
                    "file_name": file.get("file_name"),
                    "miner_ids": file.get("miner_ids", []),
                    "miner_count": len(file.get("miner_ids", [])),  # Count the miners
                    "file_size": file_size or 0,
                    "selected_validator": file["selected_validator"],
                }

                # Add formatted file size if available
                if file_size:
                    processed_file["size_formatted"] = format_size(file_size)
                else:
                    processed_file["size_formatted"] = "Unknown"

                processed_files.append(processed_file)

            return processed_files

        except Exception as e:
            raise ValueError(f"Error retrieving user files from profile: {str(e)}")

    def get_pinning_status(
        self, account_address: Optional[str] = None, seed_phrase: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get the status of file pinning requests for an account.

        This method queries the blockchain for all storage requests made by the user
        to check their pinning status.

        Args:
            account_address: Substrate account address (uses keypair address if not specified)
                             Format: 5HoreGVb17XhY3wanDvzoAWS7yHYbc5uMteXqRNTiZ6Txkqq
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

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
        # Initialize Substrate connection and get account address
        substrate, derived_address = initialize_substrate_connection(self, seed_phrase)

        # Use provided account address or the one derived from initialization
        if not account_address:
            if derived_address:
                account_address = derived_address
            else:
                raise ValueError("No account address available")

        # Query the blockchain for storage requests
        print(f"Querying storage requests for account: {account_address}")
        storage_requests = []

        # First, try with query_map which is more suitable for iterating over collections
        result = self._substrate.query_map(
            module="IpfsPallet",
            storage_function="UserStorageRequests",
            params=[account_address],
        )

        results_list = list(result)
        for key, substrate_result in results_list:
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

            if file_hash_hex:
                file_cid = self._hex_to_ipfs_cid(file_hash_hex)
                substrate_result.value["cid"] = file_cid

            storage_requests.append(substrate_result.value)

        return storage_requests

    def _hex_to_ipfs_cid(self, hex_string: str) -> str:
        """
        Convert a hex-encoded IPFS CID to a regular IPFS CID.

        Args:
            hex_string: Hex string representation of an IPFS CID

        Returns:
            str: Regular IPFS CID
        """
        return hex_to_ipfs_cid(hex_string)

    async def check_storage_request_exists(
        self, cid: str, seed_phrase: Optional[str] = None
    ) -> bool:
        """
        Check if a storage request exists for the given CID in the user's storage requests.

        Args:
            cid: Content Identifier (CID) to check
            seed_phrase: Optional seed phrase to use for this operation (uses config if None)

        Returns:
            bool: True if the CID exists in the user's storage requests, False otherwise
        """
        substrate, derived_address = initialize_substrate_connection(self, seed_phrase)

        if not derived_address:
            # If we don't have a derived address, try to get the keypair
            if not self._ensure_keypair(seed_phrase):
                raise ValueError("No account address available")
            derived_address = self._keypair.ss58_address

        # Get user storage requests to check if this CID is still stored
        try:
            # Get all user storage requests
            user_files = await self.get_user_files(derived_address)

            # Check if the CID is in the list
            for file in user_files:
                if file.get("cid") == cid or file.get("file_hash") == cid:
                    return True

            # If we didn't find it, try one more approach by querying pinning status
            try:
                pinning_status = self.get_pinning_status(derived_address)
                for request in pinning_status:
                    if request.get("cid") == cid:
                        return True
            except:
                # If pinning status check fails, assume it doesn't exist
                pass

            # If we get here, the CID was not found
            return False
        except Exception:
            # If we encounter an error checking, we'll assume it exists to be safe
            return True

    async def cancel_storage_request(
        self, cid: str, seed_phrase: Optional[str] = None
    ) -> str:
        """
        Cancel a storage request by CID from the Hippius blockchain.

        Args:
            cid: Content Identifier (CID) of the file to cancel
            seed_phrase: Optional seed phrase to use for this transaction (uses config if None)

        Returns:
            str: Transaction hash or status message
        """
        # Initialize Substrate connection with seed phrase if needed
        if not self._substrate:
            self.connect(seed_phrase)

        call = self._substrate.compose_call(
            call_module="Marketplace",
            call_function="storage_unpin_request",
            call_params={
                "file_hash": cid,
            },
        )

        # Get payment info and show estimated transaction fee
        payment_info = self._substrate.get_payment_info(
            call=call, keypair=self._keypair
        )
        print(f"Payment info: {json.dumps(payment_info, indent=2)}")
        fee = payment_info.get("partialFee", 0)
        fee_tokens = fee / 10**12 if fee > 0 else 0
        print(f"Estimated transaction fee: {fee} ({fee_tokens:.10f} tokens)")

        try:
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call, keypair=self._keypair
            )
            response = self._substrate.submit_extrinsic(
                extrinsic, wait_for_inclusion=True
            )
            print(f"Transaction hash: {response.extrinsic_hash}")
            return response.extrinsic_hash
        except Exception as e:
            # If the transaction failed, raise our custom exception
            raise HippiusFailedSubstrateDelete(
                f"Failed to cancel storage request: {str(e)}"
            )
