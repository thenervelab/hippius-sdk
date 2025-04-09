from typing import Dict, List, Optional
import json
import os
import uuid
import time

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

from hippius_sdk.config import get_config_value, get_keypair
from hippius_sdk.utils import ensure_directory_exists


class AccountManager:
    """
    Manages Hippius blockchain accounts including coldkeys, hotkeys, and proxy relationships.
    """

    def __init__(self, substrate_interface=None, config_directory=None):
        """
        Initialize the AccountManager.

        Args:
            substrate_interface: Existing SubstrateInterface or None to create one
            config_directory: Custom config directory or None for default
        """
        # Initialize substrate interface if not provided
        if substrate_interface:
            self.substrate = substrate_interface
        else:
            node_url = get_config_value("substrate", "url")
            self.substrate = SubstrateInterface(url=node_url)

        # Set up config directory
        self.config_directory = config_directory
        if not self.config_directory:
            home_dir = os.path.expanduser("~")
            self.config_directory = os.path.join(home_dir, ".hippius")

        ensure_directory_exists(self.config_directory)
        self.accounts_file = os.path.join(self.config_directory, "accounts.json")

        # Initialize or load accounts data
        self._initialize_accounts_file()

    def _initialize_accounts_file(self):
        """Initialize the accounts file if it doesn't exist."""
        if not os.path.exists(self.accounts_file):
            with open(self.accounts_file, "w") as f:
                json.dump(
                    {"coldkeys": {}, "hotkeys": {}, "relationships": []}, f, indent=2
                )

    def _load_accounts_data(self) -> Dict:
        """Load the accounts data from the file."""
        with open(self.accounts_file, "r") as f:
            return json.load(f)

    def _save_accounts_data(self, data: Dict):
        """Save the accounts data to the file."""
        with open(self.accounts_file, "w") as f:
            json.dump(data, f, indent=2)

    def create_coldkey(
        self,
        name: str = "hippius_coldkey",
        mnemonic: Optional[str] = None,
        encrypt: bool = True,
        password: Optional[str] = None,
    ) -> Dict:
        """
        Create a new coldkey or import one from a mnemonic.

        Args:
            name: Name for the coldkey (default: "hippius_coldkey")
            mnemonic: Optional mnemonic seed phrase to use
            encrypt: Whether to encrypt the mnemonic with a password
            password: Optional password (if None and encrypt=True, will prompt)

        Returns:
            Dict with coldkey information
        """
        # Create keypair
        if mnemonic:
            keypair = Keypair.create_from_mnemonic(mnemonic)
        else:
            keypair = Keypair.create_from_uri(f"//{name}_{uuid.uuid4()}")
            # Ensure we capture the mnemonic if generated
            mnemonic = keypair.mnemonic if hasattr(keypair, "mnemonic") else None

        # Save to accounts.json
        data = self._load_accounts_data()

        # Initialize coldkey info
        coldkey_info = {
            "name": name,
            "address": keypair.ss58_address,
            "created_at": time.time(),
            "public_key": keypair.public_key.hex(),
            "encrypted": encrypt,
        }

        # Handle encryption of mnemonic
        if mnemonic:
            if encrypt:
                # Import getpass here to avoid circular imports
                import getpass

                # Get password if not provided
                if password is None:
                    password = getpass.getpass("Enter password to encrypt mnemonic: ")
                    password_confirm = getpass.getpass("Confirm password: ")

                    if password != password_confirm:
                        raise ValueError("Passwords do not match")

                # Encrypt the mnemonic
                # We'll encrypt locally and store in our account.json file
                from hippius_sdk.config import encrypt_with_password

                encrypted_data, salt = encrypt_with_password(mnemonic, password)

                coldkey_info["mnemonic"] = encrypted_data
                coldkey_info["salt"] = salt

                # Also store in the main config for compatibility
                from hippius_sdk.config import set_seed_phrase

                set_seed_phrase(
                    seed_phrase=mnemonic,
                    encode=True,
                    password=password,
                    account_name=f"{name}_{keypair.ss58_address}",
                )

                print(f"Mnemonic encrypted and stored securely.")
                print(
                    f"You will need your password to sign transactions with this account."
                )
            else:
                # Store without encryption (not recommended)
                coldkey_info["mnemonic"] = mnemonic
                print("WARNING: Mnemonic stored without encryption.")
                print("Consider using --encrypt for better security.")

                # Also store in the main config for compatibility
                from hippius_sdk.config import set_seed_phrase

                set_seed_phrase(
                    seed_phrase=mnemonic,
                    encode=False,
                    account_name=f"{name}_{keypair.ss58_address}",
                )

        data["coldkeys"][keypair.ss58_address] = coldkey_info
        self._save_accounts_data(data)

        # Display information to the user
        print(f"Coldkey created successfully!")
        print(f"Name:    {name}")
        print(f"Address: {keypair.ss58_address}")

        return coldkey_info

    def create_hotkey(
        self, name: Optional[str] = None, coldkey_address: Optional[str] = None
    ) -> Dict:
        """
        Create a new hotkey and associate it with a coldkey.

        Args:
            name: Optional custom name for the hotkey
            coldkey_address: SS58 address of the coldkey to associate with.
                If None, will attempt to use the only coldkey if only one exists,
                or will raise an error if multiple coldkeys exist.

        Returns:
            Dict with hotkey information

        Raises:
            ValueError: If no coldkey is provided and multiple coldkeys exist,
                or if the specified coldkey doesn't exist
        """
        # Load account data first to check coldkeys
        data = self._load_accounts_data()

        # Verify we have a valid coldkey to associate with
        if not coldkey_address:
            # If no coldkey specified, check if we have only one coldkey
            available_coldkeys = list(data["coldkeys"].keys())

            if not available_coldkeys:
                raise ValueError(
                    "No coldkey provided and no coldkeys found. "
                    "Please create a coldkey first with: hippius account coldkey create"
                )
            elif len(available_coldkeys) == 1:
                # If only one coldkey exists, use it automatically
                coldkey_address = available_coldkeys[0]
                coldkey_name = data["coldkeys"][coldkey_address]["name"]
                print(f"Automatically associating with the only available coldkey:")
                print(f"  Name: {coldkey_name}")
                print(f"  Address: {coldkey_address}")
            else:
                # If multiple coldkeys exist, we need the user to specify
                coldkey_list = "\n  ".join(
                    [f"{k} ({data['coldkeys'][k]['name']})" for k in available_coldkeys]
                )
                raise ValueError(
                    f"No coldkey provided and multiple coldkeys exist. "
                    f"Please specify which coldkey to associate with using --coldkey.\n"
                    f"Available coldkeys:\n  {coldkey_list}"
                )
        elif coldkey_address not in data["coldkeys"]:
            raise ValueError(f"Coldkey {coldkey_address} not found")

        # Generate a name if not provided
        if not name:
            # Get the next available hotkey number for this coldkey
            existing_relationships = [
                r["hotkey"]
                for r in data["relationships"]
                if r["coldkey"] == coldkey_address
            ]

            existing_hotkeys = [
                data["hotkeys"][addr]
                for addr in existing_relationships
                if addr in data["hotkeys"]
            ]

            # Use the coldkey's name as a prefix for better organization
            coldkey_name = data["coldkeys"][coldkey_address]["name"]
            hotkey_prefix = f"{coldkey_name}_hotkey_"

            # Find the next number
            next_number = 1
            if existing_hotkeys:
                numbers = []
                for k in existing_hotkeys:
                    # Extract number from name if it follows our pattern
                    if (
                        k["name"].startswith(hotkey_prefix)
                        and k["name"][len(hotkey_prefix) :].isdigit()
                    ):
                        numbers.append(int(k["name"][len(hotkey_prefix) :]))

                if numbers:
                    next_number = max(numbers) + 1

            name = f"{hotkey_prefix}{next_number}"

        # Create keypair
        keypair = Keypair.create_from_uri(f"//{name}_{uuid.uuid4()}")

        # Save hotkey info
        hotkey_info = {
            "name": name,
            "address": keypair.ss58_address,
            "created_at": time.time(),
            "public_key": keypair.public_key.hex(),
            "mnemonic": keypair.mnemonic if hasattr(keypair, "mnemonic") else None,
            "coldkey": coldkey_address,  # Store the associated coldkey for clarity
        }

        data["hotkeys"][keypair.ss58_address] = hotkey_info

        # Create relationship with coldkey
        relationship = {
            "coldkey": coldkey_address,
            "hotkey": keypair.ss58_address,
            "created_at": time.time(),
        }
        data["relationships"].append(relationship)

        # Save updated data
        self._save_accounts_data(data)

        # Display information to the user
        print(f"Hotkey created successfully!")
        print(f"Name:    {name}")
        print(f"Address: {keypair.ss58_address}")
        print(
            f"Associated with coldkey: {coldkey_address} ({data['coldkeys'][coldkey_address]['name']})"
        )
        print(
            f"Note: This is only a local association. To create a blockchain proxy relationship,"
        )
        print(
            f"use: hippius account proxy create --coldkey {coldkey_address} --hotkey {keypair.ss58_address}"
        )

        return hotkey_info

    def list_coldkeys(self) -> List[Dict]:
        """List all stored coldkeys."""
        data = self._load_accounts_data()
        return list(data["coldkeys"].values())

    def list_hotkeys(self, coldkey_address: Optional[str] = None) -> List[Dict]:
        """
        List all stored hotkeys, optionally filtered by associated coldkey.

        Args:
            coldkey_address: If provided, only return hotkeys associated with this coldkey

        Returns:
            List of hotkey information dictionaries with coldkey association information
        """
        data = self._load_accounts_data()

        # Build a mapping of hotkey address to associated coldkey
        hotkey_to_coldkey = {}
        for relationship in data.get("relationships", []):
            hotkey = relationship.get("hotkey")
            coldkey = relationship.get("coldkey")
            if hotkey and coldkey:
                hotkey_to_coldkey[hotkey] = coldkey

        # Filter hotkeys based on coldkey_address if provided
        if coldkey_address:
            # Verify the coldkey exists
            if coldkey_address not in data["coldkeys"]:
                raise ValueError(f"Coldkey {coldkey_address} not found")

            # Get all hotkeys associated with this coldkey
            related_hotkey_addresses = [
                hotkey
                for hotkey, coldkey in hotkey_to_coldkey.items()
                if coldkey == coldkey_address
            ]

            # Return the hotkey information with added coldkey association
            result = []
            for addr in related_hotkey_addresses:
                if addr in data["hotkeys"]:
                    hotkey_info = data["hotkeys"][addr].copy()
                    # Make sure the coldkey association is included in the info
                    hotkey_info["associated_coldkey"] = coldkey_address
                    hotkey_info["coldkey_name"] = data["coldkeys"][coldkey_address][
                        "name"
                    ]
                    result.append(hotkey_info)

            return result
        else:
            # Return all hotkeys with their coldkey associations
            result = []
            for addr, info in data["hotkeys"].items():
                hotkey_info = info.copy()
                # Add coldkey association information if available
                if addr in hotkey_to_coldkey:
                    coldkey = hotkey_to_coldkey[addr]
                    hotkey_info["associated_coldkey"] = coldkey
                    if coldkey in data["coldkeys"]:
                        hotkey_info["coldkey_name"] = data["coldkeys"][coldkey]["name"]
                result.append(hotkey_info)

            return result

    def create_proxy_relationship(
        self,
        coldkey_address: str,
        hotkey_address: str,
        proxy_type: str = "NonTransfer",
        delay: int = 0,
        password: Optional[str] = None,
    ) -> Dict:
        """
        Create a proxy relationship between coldkey and hotkey on the blockchain.

        Args:
            coldkey_address: The SS58 address of the coldkey (delegator)
            hotkey_address: The SS58 address of the hotkey (delegate)
            proxy_type: The proxy type (default: "NonTransfer")
            delay: Delay in blocks before the proxy becomes active
            password: Optional password for decrypting the coldkey mnemonic

        Returns:
            Dict with transaction details
        """
        # Verify the accounts exist
        data = self._load_accounts_data()
        if coldkey_address not in data["coldkeys"]:
            raise ValueError(f"Coldkey {coldkey_address} not found")

        if hotkey_address not in data["hotkeys"]:
            raise ValueError(f"Hotkey {hotkey_address} not found")

        # Get the mnemonic for the coldkey and create a keypair
        try:
            # Try first with our own method which handles our encrypted storage
            mnemonic = self.get_coldkey_mnemonic(coldkey_address, password)
            keypair = Keypair.create_from_mnemonic(mnemonic)
        except Exception as e:
            print(f"Could not retrieve coldkey mnemonic: {str(e)}")
            print("Falling back to global config keypair...")

            # Fall back to the config system's get_keypair as a backup
            from hippius_sdk.config import get_keypair

            keypair = get_keypair(ss58_address=coldkey_address)

        # Create proxy
        call = self.substrate.compose_call(
            call_module="Proxy",
            call_function="addProxy",
            call_params={
                "delegate": hotkey_address,
                "proxyType": proxy_type,
                "delay": delay,
            },
        )

        # Create and sign extrinsic
        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        # Submit and get result
        try:
            response = self.substrate.submit_extrinsic(
                extrinsic=extrinsic, wait_for_inclusion=True
            )

            result = {
                "success": True,
                "transaction_hash": response.extrinsic_hash,
                "block_hash": response.block_hash,
                "coldkey": coldkey_address,
                "hotkey": hotkey_address,
                "proxy_type": proxy_type,
                "delay": delay,
            }

            # Update local records
            relationship = {
                "coldkey": coldkey_address,
                "hotkey": hotkey_address,
                "proxy_type": proxy_type,
                "delay": delay,
                "created_at": time.time(),
                "transaction_hash": response.extrinsic_hash,
            }
            data["relationships"].append(relationship)
            self._save_accounts_data(data)

            return result

        except SubstrateRequestException as e:
            return {
                "success": False,
                "error": str(e),
                "coldkey": coldkey_address,
                "hotkey": hotkey_address,
            }

    def list_proxies(self, coldkey_address: Optional[str] = None) -> List[Dict]:
        """
        List proxy relationships from the blockchain, optionally filtered by coldkey.

        Args:
            coldkey_address: If provided, only return proxies for this coldkey

        Returns:
            List of proxy relationship information dictionaries
        """
        # Query the chain for registered proxies
        chain_proxies = []

        # If coldkey specified, only query for that address
        addresses_to_query = [coldkey_address] if coldkey_address else []

        # If no specific coldkey, get all coldkeys from our records
        if not coldkey_address:
            data = self._load_accounts_data()
            addresses_to_query = list(data["coldkeys"].keys())

        # Query chain for each address
        for address in addresses_to_query:
            try:
                result = self.substrate.query(
                    module="Proxy", storage_function="Proxies", params=[address]
                )

                # Format depends on the specific chain implementation
                if result and result.value:
                    proxies_data = result.value[0]  # Typically [proxies, deposit]

                    for proxy in proxies_data:
                        chain_proxies.append(
                            {
                                "coldkey": address,
                                "hotkey": proxy["delegate"],
                                "proxy_type": proxy["proxyType"],
                                "delay": proxy["delay"],
                                "source": "blockchain",
                            }
                        )
            except Exception as e:
                print(f"Error querying proxies for {address}: {str(e)}")

        return chain_proxies

    def remove_proxy(
        self,
        coldkey_address: str,
        hotkey_address: str,
        password: Optional[str] = None,
        proxy_type: str = "NonTransfer",
        delay: int = 0,
    ) -> Dict:
        """
        Remove a proxy relationship from the blockchain.

        Args:
            coldkey_address: The SS58 address of the coldkey (delegator)
            hotkey_address: The SS58 address of the hotkey (delegate)
            password: Optional password for decrypting the coldkey mnemonic
            proxy_type: The proxy type (default: "NonTransfer")
            delay: Delay value used when creating the proxy

        Returns:
            Dict with transaction details
        """
        # Get the mnemonic for the coldkey and create a keypair
        try:
            # Try first with our own method which handles our encrypted storage
            mnemonic = self.get_coldkey_mnemonic(coldkey_address, password)
            keypair = Keypair.create_from_mnemonic(mnemonic)
        except Exception as e:
            print(f"Could not retrieve coldkey mnemonic: {str(e)}")
            print("Falling back to global config keypair...")

            # Fall back to the config system's get_keypair as a backup
            from hippius_sdk.config import get_keypair

            keypair = get_keypair(ss58_address=coldkey_address)

        # Remove proxy
        call = self.substrate.compose_call(
            call_module="Proxy",
            call_function="removeProxy",
            call_params={
                "delegate": hotkey_address,
                "proxyType": proxy_type,
                "delay": delay,
            },
        )

        # Create and sign extrinsic
        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        # Submit and get result
        try:
            response = self.substrate.submit_extrinsic(
                extrinsic=extrinsic, wait_for_inclusion=True
            )

            # Update local records
            data = self._load_accounts_data()
            data["relationships"] = [
                r
                for r in data["relationships"]
                if not (
                    r["coldkey"] == coldkey_address and r["hotkey"] == hotkey_address
                )
            ]
            self._save_accounts_data(data)

            return {
                "success": True,
                "transaction_hash": response.extrinsic_hash,
                "block_hash": response.block_hash,
                "coldkey": coldkey_address,
                "hotkey": hotkey_address,
            }

        except SubstrateRequestException as e:
            return {
                "success": False,
                "error": str(e),
                "coldkey": coldkey_address,
                "hotkey": hotkey_address,
            }

    def get_coldkey_mnemonic(
        self, coldkey_address: str, password: Optional[str] = None
    ) -> str:
        """
        Get a coldkey's mnemonic, decrypting it if necessary.

        Args:
            coldkey_address: The SS58 address of the coldkey
            password: Optional password for decryption (if None and needed, will prompt)

        Returns:
            str: The mnemonic seed phrase

        Raises:
            ValueError: If the coldkey doesn't exist or the password is incorrect
        """
        # Load the coldkey data
        data = self._load_accounts_data()

        if coldkey_address not in data["coldkeys"]:
            raise ValueError(f"Coldkey {coldkey_address} not found")

        coldkey_info = data["coldkeys"][coldkey_address]

        # Check if the mnemonic is encrypted
        if coldkey_info.get("encrypted", False):
            # If encrypted, we need to decrypt it
            if "mnemonic" not in coldkey_info or "salt" not in coldkey_info:
                # Try to get from main config as fallback
                from hippius_sdk.config import get_seed_phrase

                account_name = f"{coldkey_info['name']}_{coldkey_address}"

                mnemonic = get_seed_phrase(password=password, account_name=account_name)
                if mnemonic:
                    return mnemonic

                raise ValueError(
                    f"Mnemonic for coldkey {coldkey_address} is marked as encrypted "
                    f"but encryption data is missing"
                )

            # Import needed modules for decryption
            import getpass
            from hippius_sdk.config import decrypt_with_password

            # Get password if not provided
            if password is None:
                password = getpass.getpass("Enter password to decrypt mnemonic: ")

            # Decrypt the mnemonic
            try:
                encrypted_data = coldkey_info["mnemonic"]
                salt = coldkey_info["salt"]
                mnemonic = decrypt_with_password(encrypted_data, salt, password)
                return mnemonic
            except Exception as e:
                raise ValueError(f"Failed to decrypt mnemonic: {str(e)}")
        else:
            # If not encrypted, just return the mnemonic
            if "mnemonic" not in coldkey_info:
                raise ValueError(f"No mnemonic found for coldkey {coldkey_address}")

            return coldkey_info["mnemonic"]
