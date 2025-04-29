#!/usr/bin/env python3
"""
Command Line Interface tools for Hippius SDK.

This module provides CLI tools for working with the Hippius SDK, including
utilities for encryption key generation, file operations, and marketplace interactions.
"""

import argparse
import asyncio
import base64
import concurrent.futures
import getpass
import inspect
import json
import os
import sys
import time

from dotenv import load_dotenv

# Import SDK components
from hippius_sdk import (
    HippiusClient,
    decrypt_seed_phrase,
    delete_account,
    encrypt_seed_phrase,
    get_account_address,
    get_active_account,
    get_all_config,
    get_config_value,
    get_seed_phrase,
    initialize_from_env,
    list_accounts,
    load_config,
    reset_config,
    save_config,
    set_active_account,
    set_config_value,
    set_seed_phrase,
)

try:
    import nacl.secret
    import nacl.utils
except ImportError:
    ENCRYPTION_AVAILABLE = False
else:
    ENCRYPTION_AVAILABLE = True

load_dotenv()
initialize_from_env()


def get_default_address():
    """Get the default address for read-only operations"""
    config = load_config()
    return config["substrate"].get("default_address")


def generate_key():
    """Generate a random encryption key for NaCl secretbox."""
    if not ENCRYPTION_AVAILABLE:
        print(
            "Error: PyNaCl is required for encryption. Install it with: pip install pynacl"
        )
        sys.exit(1)

    # Generate a random key
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # Encode to base64 for .env file
    encoded_key = base64.b64encode(key).decode()

    return encoded_key


def key_generation_cli():
    """CLI entry point for encryption key generation."""
    parser = argparse.ArgumentParser(
        description="Generate a secure encryption key for Hippius SDK"
    )
    parser.add_argument("--copy", action="store_true", help="Copy the key to clipboard")
    args = parser.parse_args()

    # Generate the key
    encoded_key = generate_key()

    # Copy to clipboard if requested
    if args.copy:
        try:
            import pyperclip

            pyperclip.copy(encoded_key)
            print("Key copied to clipboard!")
        except ImportError:
            print(
                "Warning: Could not copy to clipboard. Install pyperclip with: pip install pyperclip"
            )

    # Print instructions
    print("\nGenerated a new encryption key for Hippius SDK")
    print(f"Key: {encoded_key}")
    print("\nAdd this to your .env file:")
    print(f"HIPPIUS_ENCRYPTION_KEY={encoded_key}")
    print("\nOr configure it in your code:")
    print("import base64")
    print(f'encryption_key = base64.b64decode("{encoded_key}")')
    print(
        "client = HippiusClient(encrypt_by_default=True, encryption_key=encryption_key)"
    )


def create_client(args):
    """Create a HippiusClient instance from command line arguments."""
    # Process encryption flags
    encrypt = None
    if hasattr(args, "encrypt") and args.encrypt:
        encrypt = True
    elif hasattr(args, "no_encrypt") and args.no_encrypt:
        encrypt = False

    decrypt = None
    if hasattr(args, "decrypt") and args.decrypt:
        decrypt = True
    elif hasattr(args, "no_decrypt") and args.no_decrypt:
        decrypt = False

    # Process encryption key if provided
    encryption_key = None
    if hasattr(args, "encryption_key") and args.encryption_key:
        try:
            encryption_key = base64.b64decode(args.encryption_key)
            if hasattr(args, "verbose") and args.verbose:
                print(f"Using provided encryption key")
        except Exception as e:
            print(f"Warning: Could not decode encryption key: {e}")
            print(f"Using default encryption key from configuration if available")

    # Get API URL based on local_ipfs flag if the flag exists
    api_url = None
    if hasattr(args, "local_ipfs") and args.local_ipfs:
        api_url = "http://localhost:5001"
    elif hasattr(args, "api_url"):
        api_url = args.api_url
    elif hasattr(args, "ipfs_api"):
        api_url = args.ipfs_api

    # Get gateway URL
    gateway = None
    if hasattr(args, "gateway"):
        gateway = args.gateway
    elif hasattr(args, "ipfs_gateway"):
        gateway = args.ipfs_gateway

    # Get substrate URL
    substrate_url = args.substrate_url if hasattr(args, "substrate_url") else None

    # Initialize client with provided parameters
    client = HippiusClient(
        ipfs_gateway=gateway,
        ipfs_api_url=api_url,
        substrate_url=substrate_url,
        substrate_seed_phrase=(
            args.seed_phrase if hasattr(args, "seed_phrase") else None
        ),
        seed_phrase_password=args.password if hasattr(args, "password") else None,
        account_name=args.account if hasattr(args, "account") else None,
        encrypt_by_default=encrypt,
        encryption_key=encryption_key,
    )

    return client


async def handle_download(client, cid, output_path, decrypt=None):
    """Handle the download command"""
    print(f"Downloading {cid} to {output_path}...")

    # Use the enhanced download method which returns formatted information
    result = await client.download_file(cid, output_path, decrypt=decrypt)

    print(f"Download successful in {result['elapsed_seconds']} seconds!")
    print(f"Saved to: {result['output_path']}")
    print(f"Size: {result['size_bytes']:,} bytes ({result['size_formatted']})")

    if result.get("decrypted"):
        print("File was decrypted during download")

    return 0


async def handle_exists(client, cid):
    """Handle the exists command"""
    print(f"Checking if CID {cid} exists on IPFS...")
    result = await client.exists(cid)

    # Use the formatted CID from the result
    formatted_cid = result["formatted_cid"]
    exists = result["exists"]

    print(f"CID {formatted_cid} exists: {exists}")

    if exists and result.get("gateway_url"):
        print(f"Gateway URL: {result['gateway_url']}")
        print("\nTo download this file, you can run:")
        print(f"  hippius download {formatted_cid} <output_path>")

    return 0


async def handle_cat(client, cid, max_size, decrypt=None):
    """Handle the cat command"""
    print(f"Retrieving content of CID {cid}...")
    try:
        # Use the enhanced cat method with formatting
        result = await client.cat(cid, max_display_bytes=max_size, decrypt=decrypt)

        # Display file information
        print(
            f"Content size: {result['size_bytes']:,} bytes ({result['size_formatted']})"
        )

        if result.get("decrypted"):
            print("Content was decrypted")

        # Display content based on type
        if result["is_text"]:
            print("\nContent (text):")
            print(result["text_preview"])
            if result["size_bytes"] > max_size:
                print(
                    f"\n... (showing first {max_size} bytes of {result['size_bytes']} total) ..."
                )
        else:
            print("\nBinary content (hex):")
            print(result["hex_preview"])
            if result["size_bytes"] > max_size:
                print(
                    f"\n... (showing first {max_size} bytes of {result['size_bytes']} total) ..."
                )

    except Exception as e:
        print(f"Error retrieving content: {e}")
        return 1

    return 0


async def handle_store(client, file_path, miner_ids, encrypt=None):
    """Handle the store command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return 1

    print(f"Uploading {file_path} to IPFS...")
    start_time = time.time()

    # Use the enhanced upload_file method that returns formatted information
    result = await client.upload_file(file_path, encrypt=encrypt)

    ipfs_elapsed_time = time.time() - start_time

    print(f"IPFS upload successful in {ipfs_elapsed_time:.2f} seconds!")
    print(f"CID: {result['cid']}")
    print(f"Filename: {result['filename']}")
    print(f"Size: {result['size_bytes']:,} bytes ({result['size_formatted']})")

    if result.get("encrypted"):
        print("File was encrypted before upload")

    # Store the file on Substrate
    print("\nStoring the file on Substrate...")
    start_time = time.time()

    try:
        # Check if we have credits
        try:
            if hasattr(client.substrate_client, "get_free_credits"):
                credits = client.substrate_client.get_free_credits()
                print(f"Account credits: {credits}")
                if credits <= 0:
                    print(
                        f"Warning: Account has no free credits (current: {credits}). Transaction may fail."
                    )
        except Exception as e:
            print(f"Warning: Could not check free credits: {e}")

        # Create a file input object for the marketplace
        file_input = {"fileHash": result["cid"], "fileName": result["filename"]}

        # Store on Substrate - now it's an async call
        tx_hash = await client.substrate_client.storage_request([file_input], miner_ids)

        substrate_elapsed_time = time.time() - start_time
        print(
            f"Substrate storage request completed in {substrate_elapsed_time:.2f} seconds!"
        )

        # Suggestion to verify
        print("\nTo verify the IPFS upload, you can run:")
        print(f"  hippius exists {result['cid']}")
        print(f"  hippius cat {result['cid']}")

    except NotImplementedError as e:
        print(f"\nNote: {e}")
    except Exception as e:
        print(f"\nError storing file on Substrate: {e}")
        return 1

    return 0


async def handle_store_dir(client, dir_path, miner_ids, encrypt=None):
    """Handle the store-dir command"""
    if not os.path.isdir(dir_path):
        print(f"Error: Directory {dir_path} not found")
        return 1

    print(f"Uploading directory {dir_path} to IPFS...")
    start_time = time.time()

    # We'll manually upload each file first to get individual CIDs
    all_files = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, dir_path)
            all_files.append((file_path, rel_path))

    print(f"Found {len(all_files)} files to upload")

    # Upload each file individually to get all CIDs
    individual_cids = []
    for file_path, rel_path in all_files:
        try:
            print(f"  Uploading: {rel_path}")
            file_result = await client.upload_file(file_path, encrypt=encrypt)
            individual_cids.append(
                {
                    "path": rel_path,
                    "cid": file_result["cid"],
                    "filename": file_result["filename"],
                    "size_bytes": file_result["size_bytes"],
                    "size_formatted": file_result.get("size_formatted", ""),
                    "encrypted": file_result.get("encrypted", False),
                }
            )
            print(
                f"    CID: {individual_cids[-1]['cid']} ({individual_cids[-1]['size_formatted']})"
            )
            if file_result.get("encrypted"):
                print(f"    Encrypted: Yes")
        except Exception as e:
            print(f"    Error uploading {rel_path}: {e}")

    # Now upload the entire directory
    result = await client.upload_directory(dir_path, encrypt=encrypt)

    ipfs_elapsed_time = time.time() - start_time

    print(f"\nIPFS directory upload successful in {ipfs_elapsed_time:.2f} seconds!")
    print(f"Directory CID: {result['cid']}")
    print(f"Directory name: {result['dirname']}")
    print(f"Total files: {result.get('file_count', len(individual_cids))}")
    print(f"Total size: {result.get('size_formatted', 'Unknown')}")

    if result.get("encrypted"):
        print("Files were encrypted before upload")

    # Print summary of all individual file CIDs
    print(f"\nAll individual file CIDs ({len(individual_cids)}):")
    for item in individual_cids:
        print(f"  {item['path']}: {item['cid']} ({item['size_formatted']})")

    # Suggestion to verify
    print("\nTo verify the IPFS directory upload, you can run:")
    print(f"  hippius exists {result['cid']}")

    # Store all files on Substrate
    print("\nStoring all files on Substrate...")
    start_time = time.time()

    try:
        # Create file input objects for the marketplace
        file_inputs = []
        for item in individual_cids:
            file_inputs.append({"fileHash": item["cid"], "fileName": item["filename"]})

        # Store all files in a single batch request
        tx_hash = await client.substrate_client.storage_request(file_inputs, miner_ids)

        substrate_elapsed_time = time.time() - start_time
        print(
            f"Substrate storage request completed in {substrate_elapsed_time:.2f} seconds!"
        )

    except NotImplementedError as e:
        print(f"\nNote: {e}")
    except Exception as e:
        print(f"\nError storing files on Substrate: {e}")
        return 1

    return 0


async def handle_credits(client, account_address):
    """Handle the credits command"""
    print("Checking free credits for the account...")
    try:
        # Get the account address we're querying
        if account_address is None:
            # If no address provided, first try to get from keypair (if available)
            if (
                hasattr(client.substrate_client, "_keypair")
                and client.substrate_client._keypair is not None
            ):
                account_address = client.substrate_client._keypair.ss58_address
            else:
                # Try to get the default address
                default_address = get_default_address()
                if default_address:
                    account_address = default_address
                else:
                    has_default = get_default_address() is not None

                    print(
                        "Error: No account address provided, and client has no keypair."
                    )

                    if has_default:
                        print(
                            "Please provide an account address with '--account_address' or the default address may be invalid."
                        )
                    else:
                        print(
                            "Please provide an account address with '--account_address' or set a default with:"
                        )
                        print("  hippius address set-default <your_account_address>")

                    return 1

        credits = await client.substrate_client.get_free_credits(account_address)
        print(f"\nFree credits: {credits:.6f}")
        raw_value = int(
            credits * 1_000_000_000_000_000_000
        )  # Convert back to raw for display
        print(f"Raw value: {raw_value:,}")
        print(f"Account address: {account_address}")
    except Exception as e:
        print(f"Error checking credits: {e}")
        return 1

    return 0


async def handle_files(client, account_address, show_all_miners=False):
    """
    Display files stored by a user in a nice format.

    This command only reads data and doesn't require seed phrase decryption.
    """
    try:
        # Get the account address we're querying
        if account_address is None:
            # If no address provided, first try to get from keypair (if available)
            if (
                hasattr(client.substrate_client, "_keypair")
                and client.substrate_client._keypair is not None
            ):
                account_address = client.substrate_client._keypair.ss58_address
            else:
                # Try to get the default address
                default_address = get_default_address()
                if default_address:
                    account_address = default_address
                else:
                    has_default = get_default_address() is not None

                    print(
                        "Error: No account address provided, and client has no keypair."
                    )

                    if has_default:
                        print(
                            "Please provide an account address with '--account_address' or the default address may be invalid."
                        )
                    else:
                        print(
                            "Please provide an account address with '--account_address' or set a default with:"
                        )
                        print("  hippius address set-default <your_account_address>")
                    return 1

        # Get files for the account using the new profile-based method
        print(f"Retrieving files for account: {account_address}")
        files = await client.substrate_client.get_user_files_from_profile(
            account_address
        )

        # Check if any files were found
        if not files:
            print(f"No files found for account: {account_address}")
            return 0

        print(f"\nFound {len(files)} files for account: {account_address}")
        print("-" * 80)

        for i, file in enumerate(files, 1):
            try:
                print(f"File {i}:")

                # Display file hash/CID
                file_hash = file.get("file_hash", "Unknown")
                if file_hash is not None:
                    formatted_cid = client.format_cid(file_hash)
                    print(f"  CID: {formatted_cid}")
                else:
                    print(f"  CID: Unknown (None)")

                # Display file name
                file_name = file.get("file_name", "Unnamed")
                print(
                    f"  File name: {file_name if file_name is not None else 'Unnamed'}"
                )

                # Display file size
                if "size_formatted" in file and file["size_formatted"] is not None:
                    size_formatted = file["size_formatted"]
                    file_size = file.get("file_size", 0)
                    if file_size is not None and file_size > 0:
                        print(f"  File size: {file_size:,} bytes ({size_formatted})")
                    else:
                        print(f"  File size: {size_formatted}")
                else:
                    print(f"  File size: Unknown")

                # Display miners (if available)
                miner_ids = file.get("miner_ids", [])
                miner_count = file.get("miner_count", 0)

                if miner_ids and show_all_miners:
                    print(f"  Stored by {len(miner_ids)} miners:")
                    for miner in miner_ids:
                        miner_id = (
                            miner.get("id", miner) if isinstance(miner, dict) else miner
                        )
                        formatted = (
                            miner.get("formatted", miner_id)
                            if isinstance(miner, dict)
                            else miner_id
                        )
                        print(f"    - {formatted}")
                elif miner_count:
                    print(f"  Stored by {miner_count} miners")
                else:
                    print(f"  Storage information not available")

                print("-" * 80)
            except Exception as e:
                print(f"  Error displaying file {i}: {e}")
                print("-" * 80)
                continue

        # Add tip for downloading
        if files:
            print("\nTo download a file, use:")
            print(f"  hippius download <CID> <output_filename>")

    except Exception as e:
        print(f"Error retrieving files: {e}")
        return 1

    return 0


async def handle_ec_files(
    client, account_address, show_all_miners=False, show_chunks=False
):
    """Handle the ec-files command to show only erasure-coded files"""
    print("Looking for erasure-coded files...")
    try:
        # Get the account address we're querying
        if account_address is None:
            # If no address provided, first try to get from keypair (if available)
            if (
                hasattr(client.substrate_client, "_keypair")
                and client.substrate_client._keypair is not None
            ):
                account_address = client.substrate_client._keypair.ss58_address
            else:
                # Try to get the default address
                default_address = get_default_address()
                if default_address:
                    account_address = default_address
                else:
                    has_default = get_default_address() is not None

                    print(
                        "Error: No account address provided, and client has no keypair."
                    )

                    if has_default:
                        print(
                            "Please provide an account address with '--account_address' or the default address may be invalid."
                        )
                    else:
                        print(
                            "Please provide an account address with '--account_address' or set a default with:"
                        )
                        print("  hippius address set-default <your_account_address>")
                    return 1

        # First, get all user files using the profile method
        files = await client.substrate_client.get_user_files_from_profile(
            account_address
        )

        # Filter for metadata files (ending with .ec_metadata)
        ec_metadata_files = []
        for file in files:
            file_name = file.get("file_name", "")
            if (
                file_name
                and isinstance(file_name, str)
                and file_name.endswith(".ec_metadata")
            ):
                ec_metadata_files.append(file)

        if not ec_metadata_files:
            print(f"No erasure-coded files found for account {account_address}")
            return 0

        print(f"\nFound {len(ec_metadata_files)} erasure-coded files:")
        print("-" * 80)

        for i, file in enumerate(ec_metadata_files, 1):
            try:
                print(f"EC File {i}:")

                # Get the metadata CID
                metadata_cid = file.get("file_hash", "Unknown")
                if metadata_cid is not None and metadata_cid != "Unknown":
                    formatted_cid = client.format_cid(metadata_cid)
                    print(f"  Metadata CID: {formatted_cid}")

                    # Fetch and parse the metadata to get original file info
                    try:
                        # Use the formatted CID, not the raw hex-encoded version
                        metadata = await client.ipfs_client.cat(formatted_cid)

                        # Check if we have text content
                        if metadata.get("is_text", False):
                            # Parse the metadata content as JSON
                            import json

                            metadata_json = json.loads(metadata.get("content", "{}"))

                            # Extract original file info
                            # Check both possible formats
                            original_file = metadata_json.get("original_file", {})

                            if original_file:
                                # New format
                                print(
                                    f"  Original file name: {original_file.get('name', 'Unknown')}"
                                )

                                # Show file size
                                original_size = original_file.get("size", 0)
                                if original_size:
                                    size_formatted = client.format_size(original_size)
                                    print(
                                        f"  Original file size: {original_size:,} bytes ({size_formatted})"
                                    )
                                else:
                                    print(f"  Original file size: Unknown")

                                # Show hash/CID of original file if available
                                original_hash = original_file.get("hash", "")
                                if original_hash:
                                    print(f"  Original file hash: {original_hash}")

                                # Show extension if available
                                extension = original_file.get("extension", "")
                                if extension:
                                    print(f"  File extension: {extension}")
                            else:
                                # Try older format
                                original_name = metadata_json.get(
                                    "original_name", "Unknown"
                                )
                                print(f"  Original file name: {original_name}")

                                original_size = metadata_json.get("original_size", 0)
                                if original_size:
                                    size_formatted = client.format_size(original_size)
                                    print(
                                        f"  Original file size: {original_size:,} bytes ({size_formatted})"
                                    )
                                else:
                                    print(f"  Original file size: Unknown")

                            # Show erasure coding parameters if available
                            ec_params = metadata_json.get("erasure_coding", {})
                            if ec_params:
                                k = ec_params.get("k", 0)
                                m = ec_params.get("m", 0)
                                if k and m:
                                    print(
                                        f"  Erasure coding: k={k}, m={m} (need {k} of {k+m} parts)"
                                    )
                            else:
                                # Check old format
                                k = metadata_json.get("k", 0)
                                m = metadata_json.get("m", 0)
                                if k and m:
                                    print(
                                        f"  Erasure coding: k={k}, m={m} (need {k} of {k+m} parts)"
                                    )

                            # Show encryption status if available
                            encrypted = metadata_json.get("encrypted", False)
                            print(f"  Encrypted: {'Yes' if encrypted else 'No'}")

                            # Count chunks
                            chunks = metadata_json.get("chunks", [])
                            if chunks:
                                print(f"  Total chunks: {len(chunks)}")

                                # Show chunk details if requested
                                if show_chunks:
                                    print(f"  Chunks:")
                                    for j, chunk in enumerate(chunks):
                                        chunk_cid = (
                                            chunk
                                            if isinstance(chunk, str)
                                            else chunk.get("cid", "Unknown")
                                        )
                                        print(f"    Chunk {j+1}: {chunk_cid}")
                        else:
                            # Couldn't parse metadata as text
                            print(f"  Error: Metadata is not in text format")
                    except Exception as e:
                        print(f"  Error fetching metadata: {e}")
                else:
                    print(f"  Metadata CID: Unknown (None)")

                # Display file name (metadata file name)
                file_name = file.get("file_name", "Unnamed")
                print(
                    f"  Metadata file name: {file_name if file_name is not None else 'Unnamed'}"
                )

                # Show reconstruction command
                if metadata_cid is not None and metadata_cid != "Unknown":
                    print(f"  Reconstruction command:")
                    # Try to extract original name from metadata file name
                    original_name = (
                        file_name.replace(".ec_metadata", "") if file_name else "file"
                    )
                    print(
                        f"    hippius reconstruct {formatted_cid} reconstructed_{original_name}"
                    )
                else:
                    print(f"  Reconstruction command not available (missing CID)")

                print("-" * 80)
            except Exception as e:
                print(f"  Error displaying EC file {i}: {e}")
                print("-" * 80)
                continue

        # Add helpful tips
        print("\nTo reconstruct a file, use:")
        print(f"  hippius reconstruct <Metadata_CID> <output_filename>")

    except Exception as e:
        print(f"Error retrieving erasure-coded files: {e}")
        return 1

    return 0


async def handle_erasure_code(
    client,
    file_path,
    k,
    m,
    chunk_size,
    miner_ids,
    encrypt=None,
    publish=False,
    verbose=True,
):
    """Handle the erasure-code command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return 1

    # Check if the input is a directory
    if os.path.isdir(file_path):
        print(f"Error: {file_path} is a directory, not a file.")
        print("\nErasure coding requires a single file as input. You have two options:")
        print("\n1. Archive the directory first:")
        print(f"   zip -r {file_path}.zip {file_path}/")
        print(f"   hippius erasure-code {file_path}.zip --k {k} --m {m}")
        print("\n2. Apply erasure coding to each file individually:")
        print("   # To code each file in the directory:")

        # Count the files to give the user an idea of how many files would be processed
        file_count = 0
        for root, _, files in os.walk(file_path):
            file_count += len(files)

        if file_count > 0:
            print(
                f"\n   Found {file_count} files in the directory. Example command for individual files:"
            )
            # Show example for one file if available
            for root, _, files in os.walk(file_path):
                if files:
                    example_file = os.path.join(root, files[0])
                    print(f'   hippius erasure-code "{example_file}" --k {k} --m {m}')
                    break

            # Ask if user wants to automatically apply to all files
            print(
                "\nWould you like to automatically apply erasure coding to each file in the directory? (y/N)"
            )
            choice = input("> ").strip().lower()

            if choice in ("y", "yes"):
                return await handle_erasure_code_directory(
                    client,
                    file_path,
                    k,
                    m,
                    chunk_size,
                    miner_ids,
                    encrypt,
                    publish,
                    verbose,
                )
        else:
            print(f"   No files found in directory {file_path}")

        return 1

    # Check if zfec is installed
    try:
        import zfec
    except ImportError:
        print(
            "Error: zfec is required for erasure coding. Install it with: pip install zfec"
        )
        print("Then update your environment: poetry add zfec")
        return 1

    # Parse miner IDs if provided
    miner_id_list = None
    if miner_ids:
        miner_id_list = [m.strip() for m in miner_ids.split(",") if m.strip()]
        if verbose:
            print(f"Targeting {len(miner_id_list)} miners: {', '.join(miner_id_list)}")

    # Get the file size and adjust parameters if needed
    file_size = os.path.getsize(file_path)
    file_size_mb = file_size / (1024 * 1024)

    print(f"Processing {file_path} ({file_size_mb:.2f} MB) with erasure coding...")

    # Calculate how many chunks we would get with current settings
    potential_chunks = max(1, file_size // chunk_size)

    # If we can't get at least k chunks, adjust the chunk size
    if potential_chunks < k:
        # Calculate a new chunk size that would give us exactly k chunks
        new_chunk_size = max(1024, file_size // k)  # Ensure at least 1KB chunks

        print("Warning: File is too small for the requested parameters.")
        print(
            f"Original parameters: k={k}, m={m}, chunk size={chunk_size/1024/1024:.2f} MB"
        )
        print(f"Would create only {potential_chunks} chunks, which is less than k={k}")
        print(
            f"Automatically adjusting chunk size to {new_chunk_size/1024/1024:.6f} MB to create at least {k} chunks"
        )

        chunk_size = new_chunk_size

    print(f"Final parameters: k={k}, m={m} (need {k} of {m} chunks to reconstruct)")
    print(f"Chunk size: {chunk_size/1024/1024:.6f} MB")

    if encrypt:
        print("Encryption: Enabled")

    start_time = time.time()

    try:
        # Use the store_erasure_coded_file method directly from HippiusClient
        result = await client.store_erasure_coded_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            miner_ids=miner_id_list,
            max_retries=3,
            verbose=verbose,
        )

        # Store the original result before potentially overwriting it with publish result
        storage_result = result.copy()
        metadata_cid = storage_result.get("metadata_cid", "unknown")

        # If publish flag is set, publish to the global IPFS network
        if publish:
            if metadata_cid != "unknown":
                print("\nPublishing to global IPFS network...")
                try:
                    # Publish the metadata to the global IPFS network
                    publish_result = await client.ipfs_client.publish_global(
                        metadata_cid
                    )
                    if publish_result.get("published", False):
                        print("Successfully published to global IPFS network")
                        print(f"Access URL: https://ipfs.io/ipfs/{metadata_cid}")
                    else:
                        print(
                            f"Warning: {publish_result.get('message', 'Failed to publish to global network')}"
                        )
                except Exception as e:
                    print(f"Warning: Failed to publish to global IPFS network: {e}")

        elapsed_time = time.time() - start_time

        print(f"\nErasure coding and storage completed in {elapsed_time:.2f} seconds!")

        # Display metadata
        metadata = storage_result.get("metadata", {})
        total_files_stored = storage_result.get("total_files_stored", 0)

        original_file = metadata.get("original_file", {})
        erasure_coding = metadata.get("erasure_coding", {})

        # If metadata_cid is known but metadata is empty, try to get file info from result directly
        if metadata_cid != "unknown" and not original_file:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

            # Use direct values from input parameters when metadata is not available
            print("\nErasure Coding Summary:")
            print(f"  Original file: {file_name} ({file_size/1024/1024:.2f} MB)")
            print(f"  Parameters: k={k}, m={m}")
            print(f"  Total files stored in marketplace: {total_files_stored}")
            print(f"  Metadata CID: {metadata_cid}")

            # Add publish status if applicable
            if publish:
                print(f"  Published to global IPFS: Yes")
                print(f"  Global access URL: https://ipfs.io/ipfs/{metadata_cid}")
        else:
            print("\nErasure Coding Summary:")
            print(
                f"  Original file: {original_file.get('name')} ({original_file.get('size', 0)/1024/1024:.2f} MB)"
            )
            print(f"  File ID: {erasure_coding.get('file_id')}")
            print(
                f"  Parameters: k={erasure_coding.get('k')}, m={erasure_coding.get('m')}"
            )
            print(f"  Total chunks: {len(metadata.get('chunks', []))}")
            print(f"  Total files stored in marketplace: {total_files_stored}")
            print(f"  Metadata CID: {metadata_cid}")

            # Add publish status if applicable
            if publish:
                print(f"  Published to global IPFS: Yes")
                print(f"  Global access URL: https://ipfs.io/ipfs/{metadata_cid}")

        # If we stored in the marketplace
        if "transaction_hash" in result:
            print(
                f"\nStored in marketplace. Transaction hash: {result['transaction_hash']}"
            )

        # Instructions for reconstruction
        print("\nTo reconstruct this file, you will need:")
        print(f"  1. The metadata CID: {metadata_cid}")
        print("  2. Access to at least k chunks for each original chunk")
        print("\nReconstruction command:")

        # Get file name, either from metadata or directly from file path
        output_filename = original_file.get("name")
        if not output_filename:
            output_filename = os.path.basename(file_path)

        print(f"  hippius reconstruct {metadata_cid} reconstructed_{output_filename}")

        return 0

    except Exception as e:
        print(f"Error during erasure coding: {e}")

        # Provide helpful advice based on the error
        if "Wrong length" in str(e) and "input blocks" in str(e):
            print("\nThis error typically occurs with very small files.")
            print("Suggestions:")
            print("  1. Try using a smaller chunk size: --chunk-size 4096")
            print("  2. Try using a smaller k value: --k 2")
            print(
                "  3. For very small files, consider using regular storage instead of erasure coding."
            )

        return 1


async def handle_erasure_code_directory(
    client,
    dir_path,
    k,
    m,
    chunk_size,
    miner_ids,
    encrypt=None,
    publish=False,
    verbose=True,
):
    """Apply erasure coding to each file in a directory individually"""
    if not os.path.isdir(dir_path):
        print(f"Error: {dir_path} is not a directory")
        return 1

    # Check if zfec is installed
    try:
        import zfec
    except ImportError:
        print(
            "Error: zfec is required for erasure coding. Install it with: pip install zfec"
        )
        print("Then update your environment: poetry add zfec")
        return 1

    print(f"Applying erasure coding to all files in {dir_path}")
    print(f"Parameters: k={k}, m={m}, chunk_size={chunk_size/1024/1024:.2f} MB")
    if encrypt:
        print("Encryption: Enabled")

    # Parse miner IDs if provided
    miner_id_list = None
    if miner_ids:
        miner_id_list = [m.strip() for m in miner_ids.split(",") if m.strip()]
        if verbose:
            print(f"Targeting {len(miner_id_list)} miners: {', '.join(miner_id_list)}")

    # Find all files
    total_files = 0
    successful = 0
    failed = 0
    skipped = 0

    # Collect files first
    all_files = []
    for root, _, files in os.walk(dir_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            all_files.append(file_path)

    total_files = len(all_files)
    print(f"Found {total_files} files to process")

    if total_files == 0:
        print("No files to process.")
        return 0

    # Process each file
    results = []

    for i, file_path in enumerate(all_files, 1):
        print(f"\n[{i}/{total_files}] Processing: {file_path}")

        # Skip directories (shouldn't happen but just in case)
        if os.path.isdir(file_path):
            print(f"Skipping directory: {file_path}")
            skipped += 1
            continue

        # Get file size for information purposes
        file_size = os.path.getsize(file_path)
        file_size_mb = file_size / (1024 * 1024)
        print(f"File size: {file_size_mb:.4f} MB ({file_size} bytes)")

        # Calculate adjusted chunk size for this file if needed
        current_chunk_size = chunk_size
        potential_chunks = max(1, file_size // current_chunk_size)

        if potential_chunks < k:
            # Calculate a new chunk size that would give us exactly k chunks
            # For very small files, use a minimal chunk size to ensure proper erasure coding
            min_chunk_size = max(1, file_size // k)  # Ensure at least 1 byte per chunk
            print(f"Adjusting chunk size to {min_chunk_size} bytes for this file")
            current_chunk_size = min_chunk_size

        try:
            # Use the store_erasure_coded_file method directly from HippiusClient
            result = await client.store_erasure_coded_file(
                file_path=file_path,
                k=k,
                m=m,
                chunk_size=current_chunk_size,
                encrypt=encrypt,
                miner_ids=miner_id_list,
                max_retries=3,
                verbose=False,  # Less verbose for batch processing
            )

            metadata_cid = result.get("metadata_cid", "unknown")
            publishing_status = "Not published"

            # If publish flag is set, publish to the global IPFS network
            if publish and metadata_cid != "unknown":
                try:
                    # Publish the metadata to the global IPFS network
                    publish_result = await client.ipfs_client.publish_global(
                        metadata_cid
                    )
                    if publish_result.get("published", False):
                        publishing_status = "Published to global IPFS"
                    else:
                        publishing_status = f"Failed to publish: {publish_result.get('message', 'Unknown error')}"
                except Exception as e:
                    publishing_status = f"Failed to publish: {str(e)}"

            # Store basic result info with additional publish info
            results.append(
                {
                    "file_path": file_path,
                    "metadata_cid": metadata_cid,
                    "success": True,
                    "published": publish
                    and publishing_status == "Published to global IPFS",
                }
            )

            status_msg = f"Success! Metadata CID: {metadata_cid}"
            if publish:
                status_msg += f" ({publishing_status})"
            print(status_msg)
            successful += 1

        except Exception as e:
            print(f"Error coding file: {e}")

            # Provide specific guidance for very small files that fail
            if file_size < 1024 and "Wrong length" in str(e):
                print(
                    "This file may be too small for erasure coding with the current parameters."
                )
                print(
                    "Consider using smaller k and m values for very small files, e.g., --k 2 --m 3"
                )

            results.append(
                {
                    "file_path": file_path,
                    "error": str(e),
                    "success": False,
                }
            )
            failed += 1

    # Print summary
    print(f"\n=== Erasure Coding Directory Summary ===")
    print(f"Total files processed: {total_files}")
    print(f"Successfully coded: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")

    if successful > 0:
        print("\nSuccessfully coded files:")
        for result in results:
            if result.get("success"):
                print(f"  {result['file_path']} -> {result['metadata_cid']}")

    if failed > 0:
        print("\nFailed files:")
        for result in results:
            if not result.get("success"):
                print(
                    f"  {result['file_path']}: {result.get('error', 'Unknown error')}"
                )

    return 0 if failed == 0 else 1


async def handle_reconstruct(client, metadata_cid, output_file, verbose=True):
    """Handle the reconstruct command for erasure-coded files"""
    # Check if zfec is installed
    try:
        import zfec
    except ImportError:
        print(
            "Error: zfec is required for erasure coding. Install it with: pip install zfec"
        )
        print("Then update your environment: poetry add zfec")
        return 1

    print(f"Reconstructing file from metadata CID: {metadata_cid}")
    print(f"Output file: {output_file}")

    start_time = time.time()

    try:
        # Use the reconstruct_from_erasure_code method
        await client.reconstruct_from_erasure_code(
            metadata_cid=metadata_cid, output_file=output_file, verbose=verbose
        )

        elapsed_time = time.time() - start_time
        print(f"\nFile reconstruction completed in {elapsed_time:.2f} seconds!")

        return 0

    except Exception as e:
        print(f"Error during file reconstruction: {e}")
        return 1


def handle_config_get(section, key):
    """Handle getting a configuration value"""
    value = get_config_value(section, key)
    print(f"Configuration value for {section}.{key}: {value}")
    return 0


def handle_config_set(section, key, value):
    """Handle setting a configuration value"""
    # Try to parse JSON value for objects, arrays, and literals
    try:
        parsed_value = json.loads(value)
        value = parsed_value
    except (json.JSONDecodeError, TypeError):
        # If not valid JSON, keep the raw string
        pass

    result = set_config_value(section, key, value)
    if result:
        print(f"Successfully set {section}.{key} to {value}")
    else:
        print(f"Failed to set {section}.{key}")
        return 1
    return 0


def handle_config_list():
    """Handle listing all configuration values"""
    config = get_all_config()
    print("Current Hippius SDK Configuration:")
    print(json.dumps(config, indent=2))
    print(f"\nConfiguration file: {os.path.expanduser('~/.hippius/config.json')}")
    return 0


def handle_config_reset():
    """Handle resetting configuration to default values"""
    if reset_config():
        print("Successfully reset configuration to default values")
    else:
        print("Failed to reset configuration")
        return 1
    return 0


def handle_seed_phrase_set(seed_phrase, encode=False, account_name=None):
    """Handle setting the seed phrase"""
    if encode:
        try:
            password = getpass.getpass("Enter password to encrypt seed phrase: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                print("Error: Passwords do not match")
                return 1

            result = set_seed_phrase(
                seed_phrase, encode=True, password=password, account_name=account_name
            )
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return 1
    else:
        result = set_seed_phrase(seed_phrase, encode=False, account_name=account_name)

    if result:
        account_msg = f" for account '{account_name}'" if account_name else ""

        if encode:
            print(
                f"Successfully set and encrypted the seed phrase{account_msg} with password protection"
            )
        else:
            print(
                f"Successfully set the seed phrase{account_msg} (WARNING: stored in plain text)"
            )

        if account_name:
            address = get_account_address(account_name)
            if address:
                print(f"SS58 Address: {address}")

        return 0
    else:
        print(f"Failed to set the seed phrase")
        return 1


def handle_seed_phrase_encode(account_name=None):
    """Handle encoding the existing seed phrase"""
    # Get the current seed phrase
    seed_phrase = get_seed_phrase(account_name=account_name)
    if not seed_phrase:
        if account_name:
            print(f"Error: No seed phrase available for account '{account_name}'")
        else:
            print("Error: No seed phrase available to encode")
        return 1

    # Check if it's already encoded
    config = load_config()
    is_encoded = False

    if account_name:
        account_data = config["substrate"].get("accounts", {}).get(account_name, {})
        is_encoded = account_data.get("seed_phrase_encoded", False)
    else:
        is_encoded = config["substrate"].get("seed_phrase_encoded", False)

    if is_encoded:
        if account_name:
            print(f"Seed phrase for account '{account_name}' is already encoded")
        else:
            print("Seed phrase is already encoded")
        return 0

    # Get a password
    try:
        password = getpass.getpass("Enter password to encrypt seed phrase: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("Error: Passwords do not match")
            return 1

        # Encode the seed phrase
        result = encrypt_seed_phrase(seed_phrase, password, account_name)
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        return 1

    if result:
        account_msg = f" for account '{account_name}'" if account_name else ""
        print(
            f"Successfully encoded the seed phrase{account_msg} with password protection"
        )
        return 0
    else:
        print("Failed to encode the seed phrase")
        return 1


def handle_seed_phrase_decode(account_name=None):
    """Handle checking or decoding the seed phrase"""
    # Check if the seed phrase is encoded
    config = load_config()
    is_encoded = False

    if account_name:
        account_data = config["substrate"].get("accounts", {}).get(account_name, {})
        is_encoded = account_data.get("seed_phrase_encoded", False)
    else:
        is_encoded = config["substrate"].get("seed_phrase_encoded", False)

    if not is_encoded:
        if account_name:
            print(
                f"Seed phrase for account '{account_name}' is not encoded - nothing to decode"
            )
        else:
            print("Seed phrase is not encoded - nothing to decode")
        return 0

    # Get the decrypted seed phrase
    try:
        password = getpass.getpass("Enter password to decrypt seed phrase: ")
        seed_phrase = decrypt_seed_phrase(password, account_name)

        if seed_phrase:
            account_msg = f" for account '{account_name}'" if account_name else ""
            print(f"Decrypted seed phrase{account_msg}: {seed_phrase}")

            # Ask if the user wants to save it as plain text
            response = input(
                "Do you want to save the seed phrase as plain text? (y/N): "
            )
            if response.lower() in ("y", "yes"):
                result = set_seed_phrase(
                    seed_phrase, encode=False, account_name=account_name
                )
                if result:
                    print("Seed phrase saved as plain text")
                else:
                    print("Failed to save the seed phrase as plain text")

            return 0
        else:
            print("Failed to decode the seed phrase. Incorrect password?")
            return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        return 1


def handle_seed_phrase_status(account_name=None):
    """Handle showing the status of the seed phrase"""
    # Check if we have a seed phrase
    config = load_config()

    if account_name:
        if account_name not in config["substrate"].get("accounts", {}):
            print(f"Error: Account '{account_name}' not found")
            return 1

        account_data = config["substrate"].get("accounts", {}).get(account_name, {})
        seed_phrase_exists = account_data.get("seed_phrase") is not None
        is_encoded = account_data.get("seed_phrase_encoded", False)
        ss58_address = account_data.get("ss58_address")
    else:
        seed_phrase_exists = config["substrate"].get("seed_phrase") is not None
        is_encoded = config["substrate"].get("seed_phrase_encoded", False)
        ss58_address = config["substrate"].get("ss58_address")

    if not seed_phrase_exists:
        if account_name:
            print(f"No seed phrase is configured for account '{account_name}'")
        else:
            print("No seed phrase is configured")
        return 0

    account_msg = f" for account '{account_name}'" if account_name else ""

    if is_encoded:
        print(f"Seed phrase{account_msg} is stored with password-based encryption")

        # Offer to verify the password works
        print("You can verify your password by decoding the seed phrase")
        try:
            verify = input("Would you like to verify your password works? (y/N): ")
            if verify.lower() in ("y", "yes"):
                password = getpass.getpass("Enter password to decrypt seed phrase: ")
                seed_phrase = decrypt_seed_phrase(password, account_name)
                if seed_phrase:
                    print("Password verification successful!")
                else:
                    print("Password verification failed")
        except KeyboardInterrupt:
            print("\nOperation cancelled")
    else:
        print(f"Seed phrase{account_msg} is stored in plain text (not encrypted)")

        # Get the value
        seed_phrase = get_seed_phrase(account_name=account_name)
        if seed_phrase:
            # Show only the first and last few words for security
            words = seed_phrase.split()
            if len(words) >= 6:
                masked = " ".join(words[:2] + ["..."] + words[-2:])
                print(f"Seed phrase (masked): {masked}")
            else:
                print("Seed phrase is available")

    if ss58_address:
        print(f"SS58 Address: {ss58_address}")

    return 0


def handle_account_create(client, name, encrypt=False):
    """Handle creating a new account with a generated seed phrase"""
    print(f"Creating new account '{name}'...")

    # Get password if encryption is requested
    password = None
    if encrypt:
        try:
            password = getpass.getpass("Enter password to encrypt seed phrase: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                print("Error: Passwords do not match")
                return 1
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return 1

    try:
        # Create the account
        result = client.substrate_client.create_account(
            name, encode=encrypt, password=password
        )

        print(f"Account created successfully!")
        print(f"Name: {result['name']}")
        print(f"Address: {result['address']}")
        print(f"Seed phrase: {result['mnemonic']}")
        print()
        print(
            "IMPORTANT: Please write down your seed phrase and store it in a safe place."
        )
        print(
            "It is the only way to recover your account if you lose access to this configuration."
        )

        return 0
    except Exception as e:
        print(f"Error creating account: {e}")
        return 1


def handle_account_export(client, name=None, file_path=None):
    """Handle exporting an account to a file"""
    try:
        # Export the account
        exported_file = client.substrate_client.export_account(
            account_name=name, file_path=file_path
        )

        print(f"Account exported successfully to: {exported_file}")
        print("The exported file contains your seed phrase in plain text.")
        print("Please keep this file secure and do not share it with anyone.")

        return 0
    except Exception as e:
        print(f"Error exporting account: {e}")
        return 1


def handle_account_import(client, file_path, encrypt=False):
    """Handle importing an account from a file"""
    # Get password if encryption is requested
    password = None
    if encrypt:
        try:
            password = getpass.getpass("Enter password to encrypt seed phrase: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                print("Error: Passwords do not match")
                return 1
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return 1

    try:
        # Import the account
        result = client.substrate_client.import_account(
            file_path, password=password if encrypt else None
        )

        print(f"Account imported successfully!")
        print(f"Name: {result['name']}")
        print(f"Address: {result['address']}")

        if (
            result.get("original_name")
            and result.get("original_name") != result["name"]
        ):
            print(
                f"Note: Original name '{result['original_name']}' was already in use, renamed to '{result['name']}'"
            )

        return 0
    except Exception as e:
        print(f"Error importing account: {e}")
        return 1


async def handle_account_info(client, account_name=None, include_history=False):
    """Handle showing account information"""
    try:
        # Get account info - properly await the async method
        info = await client.substrate_client.get_account_info(
            account_name, include_history=include_history
        )

        active_marker = " (active)" if info.get("is_active", False) else ""
        encoded_status = (
            "encrypted" if info.get("seed_phrase_encrypted", False) else "plain text"
        )

        print(f"Account: {info['name']}{active_marker}")
        print(f"Address: {info['address']}")
        print(f"Seed phrase: {encoded_status}")

        # Show storage statistics if available
        if "storage_stats" in info:
            stats = info["storage_stats"]
            if "error" in stats:
                print(f"Storage stats: Error - {stats['error']}")
            else:
                print(f"Files stored: {stats['files']}")
                print(f"Total storage: {stats['size_formatted']}")

        # Show balance if available
        if "balance" in info:
            balance = info["balance"]
            print("\nAccount Balance:")
            print(f"  Free:     {balance['free']:.6f}")
            print(f"  Reserved: {balance['reserved']:.6f}")
            print(f"  Total:    {balance['total']:.6f}")

        # Show free credits if available
        if "free_credits" in info:
            print(f"Free credits: {info['free_credits']:.6f}")

        # Show file list if requested and available
        if include_history and "files" in info and info["files"]:
            print(f"\nStored Files ({len(info['files'])}):")
            for i, file in enumerate(info["files"], 1):
                print(f"  {i}. {file.get('file_name', 'Unnamed')}")
                print(f"     CID: {file.get('file_hash', 'Unknown')}")
                print(f"     Size: {file.get('size_formatted', 'Unknown')}")

        return 0
    except Exception as e:
        print(f"Error retrieving account info: {e}")
        return 1


async def handle_account_balance(client, account_name=None, watch=False, interval=5):
    """Handle checking or watching account balance"""
    try:
        # Get the account address
        if account_name:
            address = get_account_address(account_name)
            if not address:
                print(f"Error: Could not find address for account '{account_name}'")
                return 1
        else:
            if client.substrate_client._account_address:
                address = client.substrate_client._account_address
            else:
                print("Error: No account address available")
                return 1

        if watch:
            # Watch mode - continuous updates
            # Note: watch_account_balance may need to be modified to be async-compatible
            await client.substrate_client.watch_account_balance(address, interval)
        else:
            # One-time check
            balance = await client.substrate_client.get_account_balance(address)

            print(f"Account Balance for: {address}")
            print(f"Free:     {balance['free']:.6f}")
            print(f"Reserved: {balance['reserved']:.6f}")
            print(f"Frozen:   {balance['frozen']:.6f}")
            print(f"Total:    {balance['total']:.6f}")

            # Show raw values
            print("\nRaw Values:")
            print(f"Free:     {balance['raw']['free']:,}")
            print(f"Reserved: {balance['raw']['reserved']:,}")
            print(f"Frozen:   {balance['raw']['frozen']:,}")

        return 0
    except Exception as e:
        print(f"Error checking account balance: {e}")
        return 1


def handle_account_list():
    """Handle listing all accounts"""
    accounts = list_accounts()

    if not accounts:
        print("No accounts configured")
        return 0

    print(f"Found {len(accounts)} accounts:")

    for name, data in accounts.items():
        active_marker = " (active)" if data.get("is_active", False) else ""
        encoded_status = (
            "encrypted" if data.get("seed_phrase_encoded", False) else "plain text"
        )
        address = data.get("ss58_address", "unknown")

        print(f"  {name}{active_marker}:")
        print(f"    SS58 Address: {address}")
        print(f"    Seed phrase: {encoded_status}")
        print()

    return 0


def handle_account_switch(account_name):
    """Handle switching the active account"""
    if set_active_account(account_name):
        print(f"Switched to account '{account_name}'")

        # Show address
        address = get_account_address(account_name)
        if address:
            print(f"SS58 Address: {address}")

        return 0
    else:
        return 1


def handle_account_delete(account_name):
    """Handle deleting an account"""
    # Ask for confirmation
    confirm = input(
        f"Are you sure you want to delete account '{account_name}'? This cannot be undone. (y/N): "
    )
    if confirm.lower() not in ("y", "yes"):
        print("Operation cancelled")
        return 0

    if delete_account(account_name):
        print(f"Account '{account_name}' deleted")

        # Show the new active account if any
        active_account = get_active_account()
        if active_account:
            print(f"Active account is now '{active_account}'")
        else:
            print("No accounts remaining")

        return 0
    else:
        return 1


def handle_default_address_set(address):
    """Handle setting the default address for read-only operations"""
    # Validate SS58 address format (basic check)
    if not address.startswith("5"):
        print(
            f"Warning: '{address}' doesn't look like a valid SS58 address. SS58 addresses typically start with '5'."
        )
        confirm = input("Do you want to continue anyway? (y/N): ")
        if confirm.lower() not in ("y", "yes"):
            print("Operation cancelled")
            return 1

    config = load_config()
    config["substrate"]["default_address"] = address
    save_config(config)

    print(f"Default address for read-only operations set to: {address}")
    print(
        "This address will be used for commands like 'files' and 'ec-files' when no address is explicitly provided."
    )
    return 0


def handle_default_address_get():
    """Handle getting the current default address for read-only operations"""
    config = load_config()
    address = config["substrate"].get("default_address")

    if address:
        print(f"Current default address for read-only operations: {address}")
    else:
        print("No default address set for read-only operations")
        print("You can set one with: hippius address set-default <ss58_address>")

    return 0


def handle_default_address_clear():
    """Handle clearing the default address for read-only operations"""
    config = load_config()
    if "default_address" in config["substrate"]:
        del config["substrate"]["default_address"]
        save_config(config)
        print("Default address for read-only operations has been cleared")
    else:
        print("No default address was set")

    return 0


async def handle_pinning_status(
    client, account_address, verbose=False, show_contents=True
):
    """Handle the pinning-status command"""
    print("Checking file pinning status...")
    try:
        # Get the account address we're querying
        if account_address is None:
            # If no address provided, first try to get from keypair (if available)
            if (
                hasattr(client.substrate_client, "_keypair")
                and client.substrate_client._keypair is not None
            ):
                account_address = client.substrate_client._keypair.ss58_address
            else:
                # Try to get the default address
                default_address = get_default_address()
                if default_address:
                    account_address = default_address
                else:
                    has_default = get_default_address() is not None
                    print(
                        "Error: No account address provided, and client has no keypair."
                    )
                    if has_default:
                        print(
                            "Please provide an account address with '--account_address' or the default address may be invalid."
                        )
                    else:
                        print(
                            "Please provide an account address with '--account_address' or set a default with:"
                        )
                        print("  hippius address set-default <your_account_address>")
                    return 1

        storage_requests = client.substrate_client.get_pinning_status(account_address)

        # Check if any storage requests were found
        if not storage_requests:
            print(f"No pinning requests found for account: {account_address}")
            return 0

        print(
            f"\nFound {len(storage_requests)} pinning requests for account: {account_address}"
        )
        print("-" * 80)

        # Format and display each storage request
        for i, request in enumerate(storage_requests, 1):
            try:
                print(f"Request {i}:")

                # Display CID if available
                cid = None
                if "cid" in request:
                    cid = request.get("cid", "Unknown")
                    print(f"  CID: {cid}")

                # Display file name if available
                if "file_name" in request:
                    file_name = request.get("file_name", "Unknown")
                    print(f"  File name: {file_name}")
                elif "raw_value" in request and "file_name" in request["raw_value"]:
                    # Try to extract from raw value if it's available
                    try:
                        raw_value = request["raw_value"]
                        if isinstance(raw_value, str) and "{" in raw_value:
                            # It's a string representation of a dict, try to extract the file_name
                            if "'file_name': " in raw_value:
                                start_idx = raw_value.find("'file_name': '") + len(
                                    "'file_name': '"
                                )
                                end_idx = raw_value.find("'", start_idx)
                                if start_idx > 0 and end_idx > start_idx:
                                    file_name = raw_value[start_idx:end_idx]
                                    print(f"  File name: {file_name}")
                    except Exception:
                        pass

                # Display total replicas if available
                if "total_replicas" in request:
                    total_replicas = request.get("total_replicas", 0)
                    print(f"  Total replicas: {total_replicas}")

                # Display owner if available
                if "owner" in request:
                    owner = request.get("owner", "Unknown")
                    print(f"  Owner: {owner}")

                # Display timestamps if available
                if "created_at" in request:
                    created_at = request.get("created_at", 0)
                    if created_at > 0:
                        print(f"  Created at block: {created_at}")

                if "last_charged_at" in request:
                    last_charged_at = request.get("last_charged_at", 0)
                    if last_charged_at > 0:
                        print(f"  Last charged at block: {last_charged_at}")

                # Display assignment status and progress info
                status_text = "Awaiting validator"
                if "is_assigned" in request:
                    is_assigned = request.get("is_assigned", False)
                    if is_assigned:
                        status_text = "Assigned to miners"

                # Enhanced status info
                if "miner_ids" in request and "total_replicas" in request:
                    miner_ids = request.get("miner_ids", [])
                    total_replicas = request.get("total_replicas", 0)

                    if len(miner_ids) > 0:
                        if len(miner_ids) == total_replicas:
                            status_text = "Fully pinned"
                        else:
                            status_text = "Partially pinned"

                print(f"  Status: {status_text}")

                # Display validator if available
                if "selected_validator" in request:
                    validator = request.get("selected_validator", "")
                    if validator:
                        print(f"  Selected validator: {validator}")

                # Display miners if available
                if "miner_ids" in request:
                    miner_ids = request.get("miner_ids", [])
                    if miner_ids:
                        print(f"  Assigned miners: {len(miner_ids)}")
                        for miner in miner_ids[:3]:  # Show first 3 miners
                            print(f"    - {miner}")
                        if len(miner_ids) > 3:
                            print(f"    ... and {len(miner_ids) - 3} more")
                    else:
                        print(f"  Assigned miners: None")

                    # Calculate pinning percentage if we have total_replicas
                    if "total_replicas" in request and request["total_replicas"] > 0:
                        total_replicas = request["total_replicas"]
                        pinning_pct = (len(miner_ids) / total_replicas) * 100
                        print(
                            f"  Pinning progress: {pinning_pct:.1f}% ({len(miner_ids)}/{total_replicas} miners)"
                        )

                # Display raw data for debugging
                if verbose:
                    print("  Raw data:")
                    if "raw_key" in request:
                        print(f"    Key: {request['raw_key']}")
                    if "raw_value" in request:
                        print(f"    Value: {request['raw_value']}")

                # Try to fetch the content and determine if it's a file list by inspecting its contents
                if show_contents and cid:
                    try:
                        print("\n  Fetching contents from IPFS...")
                        # Fetch the contents from IPFS
                        file_data = await client.ipfs_client.cat(cid)

                        if file_data and file_data.get("is_text", False):
                            try:
                                # Try to parse as JSON
                                content_json = json.loads(
                                    file_data.get("content", "{}")
                                )

                                # Detect if this is a file list by checking if it's a list of file objects
                                is_file_list = False
                                if (
                                    isinstance(content_json, list)
                                    and len(content_json) > 0
                                ):
                                    # Check if it looks like a file list
                                    sample_item = content_json[0]
                                    if isinstance(sample_item, dict) and (
                                        "cid" in sample_item
                                        or "fileHash" in sample_item
                                        or "filename" in sample_item
                                        or "fileName" in sample_item
                                    ):
                                        is_file_list = True

                                if is_file_list:
                                    # It's a file list - display the files
                                    print(
                                        f"  Content is a file list with {len(content_json)} files:"
                                    )
                                    print("  " + "-" * 40)
                                    for j, file_info in enumerate(content_json, 1):
                                        filename = file_info.get(
                                            "filename"
                                        ) or file_info.get("fileName", "Unknown")
                                        file_cid = file_info.get(
                                            "cid"
                                        ) or file_info.get("fileHash", "Unknown")
                                        print(f"    File {j}: {filename}")
                                        print(f"    CID: {file_cid}")

                                        # Show size if available
                                        if "size" in file_info:
                                            size = file_info["size"]
                                            size_formatted = (
                                                client.format_size(size)
                                                if hasattr(client, "format_size")
                                                else f"{size} bytes"
                                            )
                                            print(f"    Size: {size_formatted}")

                                        print("  " + "-" * 40)
                                else:
                                    # Not a file list, show a compact summary
                                    content_type = type(content_json).__name__
                                    preview = str(content_json)
                                    if len(preview) > 100:
                                        preview = preview[:100] + "..."
                                    print(f"  Content type: JSON {content_type}")
                                    print(f"  Content preview: {preview}")
                            except json.JSONDecodeError:
                                # Not JSON, just show text preview
                                content = file_data.get("content", "")
                                preview = (
                                    content[:100] + "..."
                                    if len(content) > 100
                                    else content
                                )
                                print(f"  Content type: Text")
                                print(f"  Content preview: {preview}")
                        else:
                            # Binary data
                            content_size = len(file_data.get("content", b""))
                            size_formatted = (
                                client.format_size(content_size)
                                if hasattr(client, "format_size")
                                else f"{content_size} bytes"
                            )
                            print(f"  Content type: Binary data")
                            print(f"  Content size: {size_formatted}")
                    except Exception as e:
                        print(f"  Error fetching file list contents: {e}")

                print("-" * 80)
            except Exception as e:
                print(f"  Error displaying request {i}: {e}")
                print("-" * 80)
                continue

    except Exception as e:
        print(f"Error retrieving pinning status: {e}")
        return 1

    return 0


def main():
    """Main CLI entry point for hippius command."""
    # Set up the argument parser
    parser = argparse.ArgumentParser(
        description="Hippius SDK Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Store a file
  hippius store example.txt
  
  # Store a directory
  hippius store-dir ./my_directory
  
  # Download a file
  hippius download QmHash output.txt
  
  # Check if a CID exists
  hippius exists QmHash
  
  # View the content of a CID
  hippius cat QmHash
  
  # View your available credits
  hippius credits
  
  # View your stored files
  hippius files
  
  # View all miners for stored files
  hippius files --all-miners
  
  # Check file pinning status
  hippius pinning-status
  
  # Erasure code a file (Reed-Solomon)
  hippius erasure-code large_file.mp4 --k 3 --m 5
  
  # Erasure code and publish to global IPFS network
  hippius erasure-code large_file.avi --publish
  
  # Reconstruct an erasure-coded file
  hippius reconstruct QmMetadataHash reconstructed_file.mp4
""",
    )

    # Optional arguments for all commands
    parser.add_argument(
        "--gateway",
        default=get_config_value("ipfs", "gateway", "https://ipfs.io"),
        help="IPFS gateway URL for downloads (default: from config or https://ipfs.io)",
    )
    parser.add_argument(
        "--api-url",
        default=get_config_value("ipfs", "api_url", "https://store.hippius.network"),
        help="IPFS API URL for uploads (default: from config or https://store.hippius.network)",
    )
    parser.add_argument(
        "--local-ipfs",
        action="store_true",
        default=get_config_value("ipfs", "local_ipfs", False),
        help="Use local IPFS node (http://localhost:5001) instead of remote API",
    )
    parser.add_argument(
        "--substrate-url",
        default=get_config_value("substrate", "url", "wss://rpc.hippius.network"),
        help="Substrate node WebSocket URL (default: from config or wss://rpc.hippius.network)",
    )
    parser.add_argument(
        "--miner-ids",
        help="Comma-separated list of miner IDs for storage (default: from config)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=get_config_value("cli", "verbose", False),
        help="Enable verbose debug output",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt files when uploading (overrides default)",
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Do not encrypt files when uploading (overrides default)",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt files when downloading (overrides default)",
    )
    parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Do not decrypt files when downloading (overrides default)",
    )
    parser.add_argument(
        "--encryption-key",
        help="Base64-encoded encryption key (overrides HIPPIUS_ENCRYPTION_KEY in .env)",
    )
    parser.add_argument(
        "--password",
        help="Password to decrypt the seed phrase if needed (will prompt if required and not provided)",
    )
    parser.add_argument(
        "--account",
        help="Account name to use (uses active account if not specified)",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Download command
    download_parser = subparsers.add_parser(
        "download", help="Download a file from IPFS"
    )
    download_parser.add_argument("cid", help="CID of file to download")
    download_parser.add_argument("output_path", help="Path to save downloaded file")

    # Exists command
    exists_parser = subparsers.add_parser(
        "exists", help="Check if a CID exists on IPFS"
    )
    exists_parser.add_argument("cid", help="CID to check")

    # Cat command
    cat_parser = subparsers.add_parser(
        "cat", help="Display content of a file from IPFS"
    )
    cat_parser.add_argument("cid", help="CID of file to display")
    cat_parser.add_argument(
        "--max-size",
        type=int,
        default=1024,
        help="Maximum number of bytes to display (default: 1024)",
    )

    # Store command (upload to IPFS then store on Substrate)
    store_parser = subparsers.add_parser(
        "store", help="Upload a file to IPFS and store it on Substrate"
    )
    store_parser.add_argument("file_path", help="Path to file to upload")

    # Store directory command
    store_dir_parser = subparsers.add_parser(
        "store-dir", help="Upload a directory to IPFS and store all files on Substrate"
    )
    store_dir_parser.add_argument("dir_path", help="Path to directory to upload")

    # Credits command
    credits_parser = subparsers.add_parser(
        "credits", help="Check free credits for an account in the marketplace"
    )
    credits_parser.add_argument(
        "account_address",
        nargs="?",
        default=None,
        help="Substrate account address (uses keypair address if not specified)",
    )

    # Files command
    files_parser = subparsers.add_parser(
        "files", help="View files stored by you or another account"
    )
    files_parser.add_argument(
        "--account_address",
        help="Substrate account to view files for (defaults to your keyfile account)",
    )
    files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each file",
    )
    files_parser.set_defaults(
        func=lambda args, client: handle_files(
            client,
            args.account_address,
            show_all_miners=args.all_miners if hasattr(args, "all_miners") else False,
        )
    )

    # Pinning status command
    pinning_status_parser = subparsers.add_parser(
        "pinning-status", help="Check the status of file pinning requests"
    )
    pinning_status_parser.add_argument(
        "--account_address",
        help="Substrate account to check pinning status for (defaults to your keyfile account)",
    )
    pinning_status_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed debug information",
    )
    pinning_status_parser.add_argument(
        "--show-contents",
        action="store_true",
        default=True,
        help="Show the contents of file lists (defaults to true)",
    )
    pinning_status_parser.add_argument(
        "--no-contents",
        action="store_true",
        help="Don't show the contents of file lists",
    )

    # Erasure Coded Files command
    ec_files_parser = subparsers.add_parser(
        "ec-files", help="View erasure-coded files stored by you or another account"
    )
    ec_files_parser.add_argument(
        "--account_address",
        help="Substrate account to view erasure-coded files for (defaults to your keyfile account)",
    )
    ec_files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each file",
    )
    ec_files_parser.add_argument(
        "--show-chunks",
        action="store_true",
        help="Show chunk details for each erasure-coded file",
    )
    ec_files_parser.set_defaults(
        func=lambda args, client: handle_ec_files(
            client,
            args.account_address,
            show_all_miners=args.all_miners if hasattr(args, "all_miners") else False,
            show_chunks=args.show_chunks if hasattr(args, "show_chunks") else False,
        )
    )

    # Key generation command
    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate an encryption key for secure file storage"
    )
    keygen_parser.add_argument(
        "--copy", action="store_true", help="Copy the generated key to the clipboard"
    )
    keygen_parser.add_argument(
        "--save", action="store_true", help="Save the key to the Hippius configuration"
    )

    # Erasure code command
    erasure_code_parser = subparsers.add_parser(
        "erasure-code", help="Erasure code a file"
    )
    erasure_code_parser.add_argument("file_path", help="Path to file to erasure code")
    erasure_code_parser.add_argument(
        "--k",
        type=int,
        default=3,
        help="Number of data chunks needed to reconstruct (default: 3)",
    )
    erasure_code_parser.add_argument(
        "--m", type=int, default=5, help="Total number of chunks to create (default: 5)"
    )
    erasure_code_parser.add_argument(
        "--chunk-size",
        type=int,
        default=1048576,
        help="Chunk size in bytes (default: 1MB)",
    )
    erasure_code_parser.add_argument(
        "--miner-ids", help="Comma-separated list of miner IDs"
    )
    erasure_code_parser.add_argument(
        "--encrypt", action="store_true", help="Encrypt the file"
    )
    erasure_code_parser.add_argument(
        "--no-encrypt", action="store_true", help="Do not encrypt the file"
    )
    erasure_code_parser.add_argument(
        "--publish",
        action="store_true",
        help="Upload and publish the erasure-coded file to the global IPFS network",
    )
    erasure_code_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output", default=True
    )

    # Reconstruct command
    reconstruct_parser = subparsers.add_parser(
        "reconstruct", help="Reconstruct an erasure-coded file"
    )
    reconstruct_parser.add_argument(
        "metadata_cid", help="Metadata CID of the erasure-coded file"
    )
    reconstruct_parser.add_argument(
        "output_file", help="Path to save reconstructed file"
    )
    reconstruct_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output", default=True
    )

    # Configuration subcommand
    config_parser = subparsers.add_parser(
        "config", help="Manage Hippius SDK configuration"
    )
    config_subparsers = config_parser.add_subparsers(
        dest="config_action", help="Configuration action"
    )

    # Get configuration value
    get_parser = config_subparsers.add_parser("get", help="Get a configuration value")
    get_parser.add_argument(
        "section",
        help="Configuration section (ipfs, substrate, encryption, erasure_coding, cli)",
    )
    get_parser.add_argument("key", help="Configuration key")

    # Set configuration value
    set_parser = config_subparsers.add_parser("set", help="Set a configuration value")
    set_parser.add_argument(
        "section",
        help="Configuration section (ipfs, substrate, encryption, erasure_coding, cli)",
    )
    set_parser.add_argument("key", help="Configuration key")
    set_parser.add_argument("value", help="Value to set (use JSON for complex values)")

    # List all configuration values
    config_subparsers.add_parser("list", help="List all configuration values")

    # Reset configuration to defaults
    config_subparsers.add_parser("reset", help="Reset configuration to default values")

    # Import config from .env
    config_subparsers.add_parser(
        "import-env", help="Import configuration from .env file"
    )

    # Seed Phrase subcommand
    seed_parser = subparsers.add_parser("seed", help="Manage substrate seed phrase")
    seed_subparsers = seed_parser.add_subparsers(
        dest="seed_action", help="Seed phrase action"
    )

    # Set seed phrase
    set_seed_parser = seed_subparsers.add_parser(
        "set", help="Set the substrate seed phrase"
    )
    set_seed_parser.add_argument(
        "seed_phrase", help="The mnemonic seed phrase (e.g., 'word1 word2 word3...')"
    )
    set_seed_parser.add_argument(
        "--encode", action="store_true", help="Encrypt the seed phrase with a password"
    )
    set_seed_parser.add_argument(
        "--account", help="Account name to associate with this seed phrase"
    )

    # Encode existing seed phrase
    encode_seed_parser = seed_subparsers.add_parser(
        "encode", help="Encrypt the existing seed phrase"
    )
    encode_seed_parser.add_argument(
        "--account", help="Account name to encode the seed phrase for"
    )

    # Decode seed phrase
    decode_seed_parser = seed_subparsers.add_parser(
        "decode", help="Temporarily decrypt and display the seed phrase"
    )
    decode_seed_parser.add_argument(
        "--account", help="Account name to decode the seed phrase for"
    )

    # Check seed phrase status
    status_seed_parser = seed_subparsers.add_parser(
        "status", help="Check the status of the configured seed phrase"
    )
    status_seed_parser.add_argument(
        "--account", help="Account name to check the status for"
    )

    # Account subcommand
    account_parser = subparsers.add_parser("account", help="Manage substrate accounts")
    account_subparsers = account_parser.add_subparsers(
        dest="account_action", help="Account action"
    )

    # List accounts
    account_subparsers.add_parser("list", help="List all accounts")

    # Create account
    create_account_parser = account_subparsers.add_parser(
        "create", help="Create a new account with a generated seed phrase"
    )
    create_account_parser.add_argument(
        "--name", required=True, help="Name for the new account"
    )
    create_account_parser.add_argument(
        "--encrypt", action="store_true", help="Encrypt the seed phrase with a password"
    )

    # Export account
    export_account_parser = account_subparsers.add_parser(
        "export", help="Export an account to a file"
    )
    export_account_parser.add_argument(
        "--name",
        help="Name of the account to export (uses active account if not specified)",
    )
    export_account_parser.add_argument(
        "--file",
        help="Path to save the exported account file (auto-generated if not specified)",
    )

    # Import account
    import_account_parser = account_subparsers.add_parser(
        "import", help="Import an account from a file"
    )
    import_account_parser.add_argument(
        "--file", required=True, help="Path to the account file to import"
    )
    import_account_parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the imported seed phrase with a password",
    )

    # Account info
    info_account_parser = account_subparsers.add_parser(
        "info", help="Display detailed information about an account"
    )
    info_account_parser.add_argument(
        "account_name",
        nargs="?",
        help="Name of the account to show (uses active account if not specified)",
    )
    info_account_parser.add_argument(
        "--history", action="store_true", help="Include usage history in the output"
    )

    # Account balance
    balance_account_parser = account_subparsers.add_parser(
        "balance", help="Check account balance"
    )
    balance_account_parser.add_argument(
        "account_name",
        nargs="?",
        help="Name of the account to check (uses active account if not specified)",
    )
    balance_account_parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch account balance in real-time until Ctrl+C is pressed",
    )
    balance_account_parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Update interval in seconds for watch mode (default: 5)",
    )

    # Switch active account
    switch_account_parser = account_subparsers.add_parser(
        "switch", help="Switch to a different account"
    )
    switch_account_parser.add_argument(
        "account_name", help="Name of the account to switch to"
    )

    # Delete account
    delete_account_parser = account_subparsers.add_parser(
        "delete", help="Delete an account"
    )
    delete_account_parser.add_argument(
        "account_name", help="Name of the account to delete"
    )

    # Address subcommand for read-only operations
    address_parser = subparsers.add_parser(
        "address", help="Manage default address for read-only operations"
    )
    address_subparsers = address_parser.add_subparsers(
        dest="address_action", help="Address action"
    )

    # Set default address
    set_default_parser = address_subparsers.add_parser(
        "set-default", help="Set the default address for read-only operations"
    )
    set_default_parser.add_argument(
        "address", help="The SS58 address to use as default"
    )

    # Get current default address
    address_subparsers.add_parser(
        "get-default", help="Show the current default address for read-only operations"
    )

    # Clear default address
    address_subparsers.add_parser(
        "clear-default", help="Clear the default address for read-only operations"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        # Parse miner IDs if provided
        miner_ids = None
        if args.miner_ids:
            miner_ids = [miner.strip() for miner in args.miner_ids.split(",")]
        elif os.getenv("SUBSTRATE_DEFAULT_MINERS"):
            miner_ids = [
                miner.strip()
                for miner in os.getenv("SUBSTRATE_DEFAULT_MINERS").split(",")
            ]

        # Process encryption flags
        encrypt = None
        if hasattr(args, "encrypt") and args.encrypt:
            encrypt = True
        elif hasattr(args, "no_encrypt") and args.no_encrypt:
            encrypt = False

        decrypt = None
        if hasattr(args, "decrypt") and args.decrypt:
            decrypt = True
        elif hasattr(args, "no_decrypt") and args.no_decrypt:
            decrypt = False

        # Process encryption key if provided
        encryption_key = None
        if hasattr(args, "encryption_key") and args.encryption_key:
            try:
                encryption_key = base64.b64decode(args.encryption_key)
                if args.verbose:
                    print(f"Using provided encryption key")
            except Exception as e:
                print(f"Warning: Could not decode encryption key: {e}")
                print(f"Using default encryption key from configuration if available")

        # Get API URL based on local_ipfs flag
        api_url = "http://localhost:5001" if args.local_ipfs else args.api_url

        # Create client - using the updated client parameters
        client = HippiusClient(
            ipfs_gateway=args.gateway,
            ipfs_api_url=api_url,
            substrate_url=args.substrate_url,
            substrate_seed_phrase=None,  # Let it use config
            seed_phrase_password=args.password if hasattr(args, "password") else None,
            account_name=args.account if hasattr(args, "account") else None,
            encrypt_by_default=encrypt,
            encryption_key=encryption_key,
        )

        # Handle commands - separate async and sync handlers
        # Create a helper function to handle async handlers
        def run_async_handler(handler_func, *args, **kwargs):
            # Check if the handler is async
            if inspect.iscoroutinefunction(handler_func):
                # Run the async handler in the event loop
                return asyncio.run(handler_func(*args, **kwargs))
            else:
                # Run the handler directly
                return handler_func(*args, **kwargs)

        # Handle commands with the helper function
        if args.command == "download":
            return run_async_handler(
                handle_download, client, args.cid, args.output_path, decrypt=decrypt
            )

        elif args.command == "exists":
            return run_async_handler(handle_exists, client, args.cid)

        elif args.command == "cat":
            return run_async_handler(
                handle_cat, client, args.cid, args.max_size, decrypt=decrypt
            )

        elif args.command == "store":
            return run_async_handler(
                handle_store, client, args.file_path, miner_ids, encrypt=encrypt
            )

        elif args.command == "store-dir":
            return run_async_handler(
                handle_store_dir, client, args.dir_path, miner_ids, encrypt=encrypt
            )

        elif args.command == "credits":
            return run_async_handler(handle_credits, client, args.account_address)

        elif args.command == "files":
            return run_async_handler(
                handle_files,
                client,
                args.account_address,
                show_all_miners=(
                    args.all_miners if hasattr(args, "all_miners") else False
                ),
            )

        elif args.command == "pinning-status":
            show_contents = (
                not args.no_contents if hasattr(args, "no_contents") else True
            )
            return run_async_handler(
                handle_pinning_status,
                client,
                args.account_address,
                verbose=args.verbose,
                show_contents=show_contents,
            )

        elif args.command == "ec-files":
            return run_async_handler(
                handle_ec_files,
                client,
                args.account_address,
                show_all_miners=(
                    args.all_miners if hasattr(args, "all_miners") else False
                ),
                show_chunks=args.show_chunks if hasattr(args, "show_chunks") else False,
            )

        elif args.command == "erasure-code":
            return run_async_handler(
                handle_erasure_code,
                client,
                args.file_path,
                args.k,
                args.m,
                args.chunk_size,
                miner_ids,
                encrypt=args.encrypt,
                publish=args.publish,
                verbose=args.verbose,
            )

        elif args.command == "reconstruct":
            return run_async_handler(
                handle_reconstruct,
                client,
                args.metadata_cid,
                args.output_file,
                verbose=args.verbose,
            )

        elif args.command == "keygen":
            # Generate and save an encryption key
            client = HippiusClient()
            encryption_key = client.generate_encryption_key()
            print(f"Generated encryption key: {encryption_key}")

            # Save to config if requested
            if hasattr(args, "save") and args.save:
                print("Saving encryption key to configuration...")
                handle_config_set("encryption", "encryption_key", encryption_key)
                print(
                    "Encryption key saved. Files will not be automatically encrypted unless you set encryption.encrypt_by_default to true"
                )
            return 0

        elif args.command == "config":
            if args.config_action == "get":
                return handle_config_get(args.section, args.key)
            elif args.config_action == "set":
                return handle_config_set(args.section, args.key, args.value)
            elif args.config_action == "list":
                return handle_config_list()
            elif args.config_action == "reset":
                return handle_config_reset()
            elif args.config_action == "import-env":
                initialize_from_env()
                print("Successfully imported configuration from environment variables")
                return 0
            else:
                config_parser.print_help()
                return 1

        elif args.command == "seed":
            if args.seed_action == "set":
                return handle_seed_phrase_set(
                    args.seed_phrase, args.encode, args.account
                )
            elif args.seed_action == "encode":
                return handle_seed_phrase_encode(args.account)
            elif args.seed_action == "decode":
                return handle_seed_phrase_decode(args.account)
            elif args.seed_action == "status":
                return handle_seed_phrase_status(args.account)
            else:
                seed_parser.print_help()
                return 1

        # Handle the account commands
        elif args.command == "account":
            if args.account_action == "list":
                return handle_account_list()
            elif args.account_action == "create":
                return handle_account_create(client, args.name, args.encrypt)
            elif args.account_action == "export":
                return handle_account_export(client, args.name, args.file)
            elif args.account_action == "import":
                return handle_account_import(client, args.file, args.encrypt)
            elif args.account_action == "info":
                return run_async_handler(
                    handle_account_info, client, args.account_name, args.history
                )
            elif args.account_action == "balance":
                return run_async_handler(
                    handle_account_balance,
                    client,
                    args.account_name,
                    args.watch,
                    args.interval,
                )
            elif args.account_action == "switch":
                return handle_account_switch(args.account_name)
            elif args.account_action == "delete":
                return handle_account_delete(args.account_name)
            else:
                account_parser.print_help()
                return 1

        # Handle the address commands
        elif args.command == "address":
            if args.address_action == "set-default":
                return handle_default_address_set(args.address)
            elif args.address_action == "get-default":
                return handle_default_address_get()
            elif args.address_action == "clear-default":
                return handle_default_address_clear()
            else:
                address_parser.print_help()
                return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
