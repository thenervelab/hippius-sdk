"""
Substrate operations for the Hippius SDK.

Note: This functionality is coming soon and not implemented yet.
"""

import os
import json
import uuid
from typing import Dict, Any, Optional, List, Union
from substrateinterface import SubstrateInterface, Keypair
from dotenv import load_dotenv
from hippius_sdk.config import (
    get_config_value,
    get_seed_phrase,
    set_seed_phrase,
    get_account_address,
    get_active_account,
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

    def storage_request(
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
            import tempfile
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
                upload_result = ipfs_client.upload_file(temp_file_path)
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
            call = self._substrate.compose_call(
                call_module="Marketplace",
                call_function="storage_request",
                call_params=call_params,
            )

            # Get payment info to estimate the fee
            payment_info = self._substrate.get_payment_info(
                call=call, keypair=self._keypair
            )

            estimated_fee = payment_info.get("partialFee", 0)
            print(f"Estimated transaction fee: {estimated_fee}")

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

    def store_cid(
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

    def get_account_balance(
        self, account_address: Optional[str] = None
    ) -> Dict[str, float]:
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

    def get_user_files(
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
        return self.get_user_files_from_profile(account_address)

    def get_user_files_from_profile(
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
            from hippius_sdk.ipfs import IPFSClient

            ipfs_client = IPFSClient()

            print(f"Fetching user profile from IPFS: {profile_cid}")
            profile_data = ipfs_client.cat(profile_cid)

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
                    "file_size": file_size,
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

    def _hex_to_ipfs_cid(self, hex_string: str) -> str:
        """
        Convert a hex-encoded IPFS CID to a regular IPFS CID.

        Args:
            hex_string: Hex string representation of an IPFS CID

        Returns:
            str: Regular IPFS CID
        """
        # First, try to decode as ASCII if it's a hex representation of ASCII characters
        try:
            if hex_string.startswith("0x"):
                hex_string = hex_string[2:]

            bytes_data = bytes.fromhex(hex_string)
            ascii_str = bytes_data.decode("ascii")

            # If the decoded string starts with a valid CID prefix, return it
            if ascii_str.startswith(("Qm", "bafy", "bafk", "bafyb", "bafzb", "b")):
                return ascii_str
        except Exception:
            # If ASCII decoding fails, continue with other methods
            pass

        # Try to decode as a binary CID
        try:
            import base58

            if hex_string.startswith("0x"):
                hex_string = hex_string[2:]

            binary_data = bytes.fromhex(hex_string)

            # Check if it matches CIDv0 pattern (starts with 0x12, 0x20)
            if (
                len(binary_data) > 2
                and binary_data[0] == 0x12
                and binary_data[1] == 0x20
            ):
                # CIDv0 (Qm...)
                return base58.b58encode(binary_data).decode("utf-8")

            # If it doesn't match CIDv0, for CIDv1 just return the hex without 0x prefix
            # since adding 0x breaks IPFS gateway URLs
            return hex_string
        except ImportError:
            # If base58 is not available
            print("Warning: base58 module not available for proper CID conversion")
            return hex_string
        except Exception as e:
            print(f"Error converting hex to CID: {e}")
            return hex_string
