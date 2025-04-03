#!/usr/bin/env python3
"""
Command Line Interface tools for Hippius SDK.

This module provides CLI tools for working with the Hippius SDK, including
utilities for encryption key generation, file operations, and marketplace interactions.
"""

import base64
import argparse
import os
import sys
import time
import json
from typing import Optional, List
import getpass

# Import SDK components
from hippius_sdk import HippiusClient
from hippius_sdk.substrate import FileInput
from hippius_sdk import (
    get_config_value,
    set_config_value,
    get_encryption_key,
    set_encryption_key,
    load_config,
    save_config,
    get_all_config,
    reset_config,
    initialize_from_env,
    get_seed_phrase,
    set_seed_phrase,
    encrypt_seed_phrase,
    decrypt_seed_phrase,
    get_active_account,
    set_active_account,
    list_accounts,
    delete_account,
    get_account_address,
)
from dotenv import load_dotenv

try:
    import nacl.utils
    import nacl.secret
except ImportError:
    ENCRYPTION_AVAILABLE = False
else:
    ENCRYPTION_AVAILABLE = True

# Load environment variables
load_dotenv()

# Initialize configuration from environment variables
initialize_from_env()


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
            if args.verbose:
                print(f"Using provided encryption key")
        except Exception as e:
            print(f"Warning: Could not decode encryption key: {e}")
            print(f"Using default encryption key from configuration if available")

    # Get API URL based on local_ipfs flag
    api_url = "http://localhost:5001" if args.local_ipfs else args.api_url

    # Initialize client with provided parameters
    client = HippiusClient(
        ipfs_gateway=args.gateway,
        ipfs_api_url=api_url,
        substrate_url=args.substrate_url,
        encrypt_by_default=encrypt,
        encryption_key=encryption_key,
    )

    return client, encrypt, decrypt


def handle_download(client, cid, output_path, decrypt=None):
    """Handle the download command"""
    print(f"Downloading {cid} to {output_path}...")

    # Use the enhanced download method which returns formatted information
    result = client.download_file(cid, output_path, decrypt=decrypt)

    print(f"Download successful in {result['elapsed_seconds']} seconds!")
    print(f"Saved to: {result['output_path']}")
    print(f"Size: {result['size_bytes']:,} bytes ({result['size_formatted']})")

    if result.get("decrypted"):
        print("File was decrypted during download")

    return 0


def handle_exists(client, cid):
    """Handle the exists command"""
    print(f"Checking if CID {cid} exists on IPFS...")
    result = client.exists(cid)

    # Use the formatted CID from the result
    formatted_cid = result["formatted_cid"]
    exists = result["exists"]

    print(f"CID {formatted_cid} exists: {exists}")

    if exists and result.get("gateway_url"):
        print(f"Gateway URL: {result['gateway_url']}")
        print("\nTo download this file, you can run:")
        print(f"  hippius download {formatted_cid} <output_path>")

    return 0


def handle_cat(client, cid, max_size, decrypt=None):
    """Handle the cat command"""
    print(f"Retrieving content of CID {cid}...")
    try:
        # Use the enhanced cat method with formatting
        result = client.cat(cid, max_display_bytes=max_size, decrypt=decrypt)

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


def handle_store(client, file_path, miner_ids, encrypt=None):
    """Handle the store command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return 1

    print(f"Uploading {file_path} to IPFS...")
    start_time = time.time()

    # Use the enhanced upload_file method that returns formatted information
    result = client.upload_file(file_path, encrypt=encrypt)

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
        # Create a file input object for the marketplace
        file_input = {"fileHash": result["cid"], "fileName": result["filename"]}

        # Store on Substrate
        client.substrate_client.storage_request([file_input], miner_ids)

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


def handle_store_dir(client, dir_path, miner_ids, encrypt=None):
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
            file_result = client.upload_file(file_path, encrypt=encrypt)
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
    result = client.upload_directory(dir_path, encrypt=encrypt)

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
        client.substrate_client.storage_request(file_inputs, miner_ids)

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


def handle_credits(client, account_address):
    """Handle the credits command"""
    print("Checking free credits for the account...")
    try:
        credits = client.substrate_client.get_free_credits(account_address)
        print(f"\nFree credits: {credits:.6f}")
        raw_value = int(
            credits * 1_000_000_000_000_000_000
        )  # Convert back to raw for display
        print(f"Raw value: {raw_value:,}")
        print(
            f"Account address: {account_address or client.substrate_client._keypair.ss58_address}"
        )
    except Exception as e:
        print(f"Error checking credits: {e}")
        return 1

    return 0


def handle_files(client, account_address, debug=False, show_all_miners=False):
    """Handle the files command"""
    print("Retrieving file information...")
    try:
        if debug:
            print("DEBUG MODE: Will show details about CID decoding")

        # Use the enhanced get_user_files method with our preferences
        max_miners = 0 if show_all_miners else 3  # 0 means show all miners
        files = client.substrate_client.get_user_files(
            account_address,
            truncate_miners=True,  # Always truncate long miner IDs
            max_miners=max_miners,  # Use 0 for all or 3 for limited
        )

        if files:
            print(
                f"\nFound {len(files)} files for account: {account_address or client.substrate_client._keypair.ss58_address}"
            )
            print("\n" + "-" * 80)

            for i, file in enumerate(files, 1):
                print(f"File {i}:")

                # Format the CID using the SDK method
                file_hash = file.get("file_hash", "Unknown")
                formatted_cid = client.format_cid(file_hash)
                print(f"  File Hash (CID): {formatted_cid}")

                # Display file name
                print(f"  File Name: {file.get('file_name', 'Unnamed')}")

                # Display file size with SDK formatting method if needed
                file_size = file.get("file_size", 0)
                size_formatted = file.get("size_formatted")
                if not size_formatted and file_size > 0:
                    size_formatted = client.format_size(file_size)
                print(f"  File Size: {file_size:,} bytes ({size_formatted})")

                # Display miners
                miner_count = file.get("miner_count", 0)
                miners = file.get("miner_ids", [])

                if miner_count > 0:
                    print(f"  Pinned by {miner_count} miners:")

                    # Show message about truncated list if applicable
                    if miner_count > len(miners) and not show_all_miners:
                        print(
                            f"    (Showing {len(miners)} of {miner_count} miners - use --all-miners to see all)"
                        )
                    elif miner_count > 3 and show_all_miners:
                        print(f"    (Showing all {miner_count} miners)")

                    # Display the miners using their formatted IDs
                    for miner in miners:
                        if isinstance(miner, dict) and "formatted" in miner:
                            print(f"    - {miner['formatted']}")
                        else:
                            print(f"    - {miner}")
                else:
                    print("  Not pinned by any miners")

                print("-" * 80)
        else:
            print(
                f"No files found for account: {account_address or client.substrate_client._keypair.ss58_address}"
            )
    except Exception as e:
        print(f"Error retrieving file information: {e}")
        return 1

    return 0


def handle_ec_files(client, account_address, show_all_miners=False, show_chunks=False):
    """Handle the ec-files command to list only erasure-coded files"""
    print("Retrieving erasure-coded file information...")
    try:
        # Use the enhanced get_user_files method with our preferences
        max_miners = 0 if show_all_miners else 3  # 0 means show all miners
        files = client.substrate_client.get_user_files(
            account_address,
            truncate_miners=True,  # Always truncate long miner IDs
            max_miners=max_miners,  # Use 0 for all or 3 for limited
        )

        # Filter for erasure-coded metadata files
        ec_metadata_files = []
        ec_chunk_files = []

        for file in files:
            file_name = file.get("file_name", "")
            if file_name.endswith(".ec_metadata"):
                ec_metadata_files.append(file)
            elif "_chunk_" in file_name and file_name.endswith(".ec"):
                ec_chunk_files.append(file)

        # Group chunks by file ID
        chunk_groups = {}
        for chunk in ec_chunk_files:
            # Extract file_id from chunk name pattern: {file_id}_chunk_{original_idx}_{share_idx}.ec
            chunk_name = chunk.get("file_name", "")
            if "_chunk_" in chunk_name:
                file_id = chunk_name.split("_chunk_")[0]
                if file_id not in chunk_groups:
                    chunk_groups[file_id] = []
                chunk_groups[file_id].append(chunk)

        if not ec_metadata_files:
            print(
                f"No erasure-coded files found for account: {account_address or client.substrate_client._keypair.ss58_address}"
            )
            return 0

        print(
            f"\nFound {len(ec_metadata_files)} erasure-coded files for account: {account_address or client.substrate_client._keypair.ss58_address}"
        )
        print("\n" + "-" * 80)

        for i, file in enumerate(ec_metadata_files, 1):
            file_name = file.get("file_name", "Unnamed")
            original_file_name = file_name.replace(".ec_metadata", "")
            file_hash = file.get("file_hash", "Unknown")
            formatted_cid = client.format_cid(file_hash)

            # Try to extract file_id from the filename
            file_id = None
            if "_metadata.json.ec_metadata" in file_name:
                file_id = file_name.split("_metadata.json.ec_metadata")[0]

            print(f"Erasure-Coded File {i}:")
            print(f"  Original File: {original_file_name}")
            print(f"  Metadata CID: {formatted_cid}")

            # Display file size with SDK formatting method if needed
            file_size = file.get("file_size", 0)
            size_formatted = file.get("size_formatted")
            if not size_formatted and file_size > 0:
                size_formatted = client.format_size(file_size)
            print(f"  Metadata Size: {file_size:,} bytes ({size_formatted})")

            # Show associated chunks if requested and if we have a file_id
            if show_chunks and file_id and file_id in chunk_groups:
                chunks = chunk_groups[file_id]
                print(f"  Associated Chunks: {len(chunks)}")
                for j, chunk in enumerate(chunks, 1):
                    if j <= 3 or len(chunks) <= 5:  # Show all if few, otherwise first 3
                        chunk_name = chunk.get("file_name", "")
                        chunk_cid = client.format_cid(chunk.get("file_hash", "Unknown"))
                        print(f"    {j}. {chunk_name}: {chunk_cid}")
                if len(chunks) > 5 and not show_all_miners:
                    print(
                        f"    ... and {len(chunks) - 3} more chunks (use --show-all to see all)"
                    )

            # Display miners
            miner_count = file.get("miner_count", 0)
            miners = file.get("miner_ids", [])

            if miner_count > 0:
                print(f"  Pinned by {miner_count} miners:")

                # Show message about truncated list if applicable
                if miner_count > len(miners) and not show_all_miners:
                    print(
                        f"    (Showing {len(miners)} of {miner_count} miners - use --all-miners to see all)"
                    )
                elif miner_count > 3 and show_all_miners:
                    print(f"    (Showing all {miner_count} miners)")

                # Display the miners using their formatted IDs
                for miner in miners:
                    if isinstance(miner, dict) and "formatted" in miner:
                        print(f"    - {miner['formatted']}")
                    else:
                        print(f"    - {miner}")
            else:
                print("  Not pinned by any miners")

            # Reconstruction command hint
            print("\n  To reconstruct this file:")
            print(
                f"  hippius reconstruct {formatted_cid} reconstructed_{original_file_name}"
            )
            print("-" * 80)

    except Exception as e:
        print(f"Error retrieving erasure-coded file information: {e}")
        return 1

    return 0


def handle_erasure_code(
    client, file_path, k, m, chunk_size, miner_ids, encrypt=None, verbose=True
):
    """Handle the erasure-code command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
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

    # Check if the file is too small for the current chunk size and k value
    original_k = k
    original_m = m
    original_chunk_size = chunk_size

    # Calculate how many chunks we would get with current settings
    potential_chunks = max(1, file_size // chunk_size)

    # If we can't get at least k chunks, adjust the chunk size
    if potential_chunks < k:
        # Calculate a new chunk size that would give us exactly k chunks
        new_chunk_size = max(1024, file_size // k)  # Ensure at least 1KB chunks

        print(f"Warning: File is too small for the requested parameters.")
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
        result = client.store_erasure_coded_file(
            file_path=file_path,
            k=k,
            m=m,
            chunk_size=chunk_size,
            encrypt=encrypt,
            miner_ids=miner_id_list,
            max_retries=3,
            verbose=verbose,
        )

        elapsed_time = time.time() - start_time

        print(f"\nErasure coding and storage completed in {elapsed_time:.2f} seconds!")

        # Display metadata
        metadata = result.get("metadata", {})
        metadata_cid = result.get("metadata_cid", "unknown")
        total_files_stored = result.get("total_files_stored", 0)

        original_file = metadata.get("original_file", {})
        erasure_coding = metadata.get("erasure_coding", {})

        print("\nErasure Coding Summary:")
        print(
            f"  Original file: {original_file.get('name')} ({original_file.get('size', 0)/1024/1024:.2f} MB)"
        )
        print(f"  File ID: {erasure_coding.get('file_id')}")
        print(f"  Parameters: k={erasure_coding.get('k')}, m={erasure_coding.get('m')}")
        print(f"  Total chunks: {len(metadata.get('chunks', []))}")
        print(f"  Total files stored in marketplace: {total_files_stored}")
        print(f"  Metadata CID: {metadata_cid}")

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
        print(
            f"  hippius reconstruct {metadata_cid} reconstructed_{original_file.get('name')}"
        )

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


def handle_reconstruct(client, metadata_cid, output_file, verbose=True):
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
        result = client.reconstruct_from_erasure_code(
            metadata_cid=metadata_cid, output_file=output_file, verbose=verbose
        )

        elapsed_time = time.time() - start_time
        print(f"\nFile reconstruction completed in {elapsed_time:.2f} seconds!")
        print(f"Reconstructed file saved to: {result}")

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
  
  # Erasure code a file (Reed-Solomon)
  hippius erasure-code large_file.mp4 --k 3 --m 5
  
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
        default=get_config_value("ipfs", "api_url", "https://relay-fr.hippius.network"),
        help="IPFS API URL for uploads (default: from config or https://relay-fr.hippius.network)",
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
        "files", help="View detailed information about files stored by a user"
    )
    files_parser.add_argument(
        "account_address",
        nargs="?",
        default=None,
        help="Substrate account address (uses keypair address if not specified)",
    )
    files_parser.add_argument(
        "--debug", action="store_true", help="Show debug information about CID decoding"
    )
    files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each file instead of only the first 3",
    )

    # Erasure Coded Files command
    ec_files_parser = subparsers.add_parser(
        "ec-files", help="List only erasure-coded files stored by a user"
    )
    ec_files_parser.add_argument(
        "account_address",
        nargs="?",
        default=None,
        help="Substrate account address (uses keypair address if not specified)",
    )
    ec_files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each file instead of only the first 3",
    )
    ec_files_parser.add_argument(
        "--show-chunks",
        action="store_true",
        help="Show associated chunks for each erasure-coded file",
    )

    # Key generation command
    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate an encryption key for secure file storage"
    )
    keygen_parser.add_argument(
        "--copy", action="store_true", help="Copy the generated key to the clipboard"
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Special case for keygen which doesn't need client initialization
    if args.command == "keygen":
        # Handle key generation separately
        if args.copy:
            return key_generation_cli()
        else:
            # Create a new argparse namespace with just the copy flag for compatibility
            keygen_args = argparse.Namespace(copy=False)
            return key_generation_cli()

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

        # Create client
        client, encrypt, decrypt = create_client(args)

        # Handle commands
        if args.command == "download":
            return handle_download(client, args.cid, args.output_path, decrypt=decrypt)

        elif args.command == "exists":
            return handle_exists(client, args.cid)

        elif args.command == "cat":
            return handle_cat(client, args.cid, args.max_size, decrypt=decrypt)

        elif args.command == "store":
            return handle_store(client, args.file_path, miner_ids, encrypt=encrypt)

        elif args.command == "store-dir":
            return handle_store_dir(client, args.dir_path, miner_ids, encrypt=encrypt)

        elif args.command == "credits":
            return handle_credits(client, args.account_address)

        elif args.command == "files":
            return handle_files(
                client,
                args.account_address,
                debug=args.debug if hasattr(args, "debug") else False,
                show_all_miners=args.all_miners
                if hasattr(args, "all_miners")
                else False,
            )

        elif args.command == "ec-files":
            return handle_ec_files(
                client,
                args.account_address,
                show_all_miners=args.all_miners
                if hasattr(args, "all_miners")
                else False,
                show_chunks=args.show_chunks if hasattr(args, "show_chunks") else False,
            )

        elif args.command == "erasure-code":
            return handle_erasure_code(
                client,
                args.file_path,
                args.k,
                args.m,
                args.chunk_size,
                miner_ids,
                encrypt=args.encrypt,
                verbose=args.verbose,
            )

        elif args.command == "reconstruct":
            return handle_reconstruct(
                client, args.metadata_cid, args.output_file, verbose=args.verbose
            )

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
            elif args.account_action == "switch":
                return handle_account_switch(args.account_name)
            elif args.account_action == "delete":
                return handle_account_delete(args.account_name)
            else:
                account_parser.print_help()
                return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
