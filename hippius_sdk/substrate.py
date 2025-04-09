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

            # Prepare the JSON-RPC request
            request = {
                "jsonrpc": "2.0",
                "method": "get_user_files",
                "params": [account_address],
                "id": 1,
            }

            print(f"Querying detailed file information for account: {account_address}")

            # Make the JSON-RPC call
            response = self._substrate.rpc_request(
                method="get_user_files", params=[account_address]
            )

            # Check for errors in the response
            if "error" in response:
                error_msg = (
                    f"RPC error: {response['error'].get('message', 'Unknown error')}"
                )
                print(error_msg)
                raise ValueError(error_msg)

            # Extract the result
            files = response.get("result", [])
            print(f"Found {len(files)} files stored by this account")

            # Helper function to convert ASCII code arrays to strings
            def ascii_to_string(value):
                if isinstance(value, list) and all(isinstance(x, int) for x in value):
                    return "".join(chr(code) for code in value)
                return str(value)

            # Helper function to properly format CIDs
            def format_cid(cid_str):
                # If it already looks like a proper CID, return it as is
                if cid_str.startswith(("Qm", "bafy", "bafk", "bafyb", "bafzb", "b")):
                    return cid_str

                # Check if it's a hex string
                if all(c in "0123456789abcdefABCDEF" for c in cid_str):
                    # First try the special case where the hex string is actually ASCII encoded
                    try:
                        # Try to decode the hex as ASCII characters
                        # (This is the case with some substrate responses where the CID is hex-encoded ASCII)
                        hex_bytes = bytes.fromhex(cid_str)
                        ascii_str = hex_bytes.decode("ascii")

                        # If the decoded string starts with a valid CID prefix, return it
                        if ascii_str.startswith(
                            ("Qm", "bafy", "bafk", "bafyb", "bafzb", "b")
                        ):
                            return ascii_str
                    except Exception:
                        pass

                    # If the above doesn't work, try the standard CID decoding
                    try:
                        import base58
                        import binascii

                        # Try to decode hex to binary then to base58 for CIDv0
                        try:
                            binary_data = binascii.unhexlify(cid_str)
                            if (
                                len(binary_data) > 2
                                and binary_data[0] == 0x12
                                and binary_data[1] == 0x20
                            ):
                                # This looks like a CIDv0 (Qm...)
                                decoded_cid = base58.b58encode(binary_data).decode(
                                    "utf-8"
                                )
                                return decoded_cid
                        except Exception:
                            pass

                        # If not successful, just return hex with 0x prefix as fallback
                        return f"0x{cid_str}"
                    except ImportError:
                        # If base58 is not available, return hex with prefix
                        return f"0x{cid_str}"

                # Default case - return as is
                return cid_str

            # Helper function to format file sizes
            def format_file_size(size_bytes):
                if size_bytes >= 1024 * 1024:
                    return f"{size_bytes / (1024 * 1024):.2f} MB"
                else:
                    return f"{size_bytes / 1024:.2f} KB"

            # Helper function to format miner IDs for display
            def format_miner_id(miner_id):
                if (
                    truncate_miners
                    and isinstance(miner_id, str)
                    and miner_id.startswith("1")
                    and len(miner_id) > 40
                ):
                    # Truncate long peer IDs
                    return f"{miner_id[:12]}...{miner_id[-4:]}"
                return miner_id

            # Process the response
            processed_files = []
            for file in files:
                processed_file = {"file_size": file.get("file_size", 0)}

                # Add formatted file size
                processed_file["size_formatted"] = format_file_size(
                    processed_file["file_size"]
                )

                # Convert file_hash from byte array to string
                if "file_hash" in file:
                    cid_str = ascii_to_string(file["file_hash"])
                    processed_file["file_hash"] = format_cid(cid_str)

                # Convert file_name from byte array to string
                if "file_name" in file:
                    processed_file["file_name"] = ascii_to_string(file["file_name"])

                # Convert miner_ids from byte arrays to strings
                if "miner_ids" in file and isinstance(file["miner_ids"], list):
                    all_miners = [
                        ascii_to_string(miner_id) for miner_id in file["miner_ids"]
                    ]
                    processed_file["miner_ids_full"] = all_miners
                    processed_file["miner_count"] = len(all_miners)

                    # Truncate miner list if requested
                    if max_miners > 0 and len(all_miners) > max_miners:
                        displayed_miners = all_miners[:max_miners]
                    else:
                        displayed_miners = all_miners

                    # Format and store the displayed miners
                    processed_file["miner_ids"] = [
                        {"id": miner_id, "formatted": format_miner_id(miner_id)}
                        for miner_id in displayed_miners
                    ]
                else:
                    processed_file["miner_ids"] = []
                    processed_file["miner_ids_full"] = []
                    processed_file["miner_count"] = 0

                processed_files.append(processed_file)

            return processed_files

        except Exception as e:
            error_msg = f"Error querying user files: {str(e)}"
            print(error_msg)
            raise ValueError(error_msg)
