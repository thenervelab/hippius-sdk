#!/usr/bin/env python3
"""
Test script for Hippius SDK IPFS functionality

This script provides a command-line interface for testing the Hippius SDK's
IPFS operations including uploading, downloading, checking existence,
retrieving content, and storing files on the Hippius marketplace.

Usage:
    python test_hippius.py download <cid> <output_path>
    python test_hippius.py exists <cid>
    python test_hippius.py cat <cid>
    python test_hippius.py store <file_path>
    python test_hippius.py store-dir <directory_path>
    python test_hippius.py credits [<account_address>]
    python test_hippius.py files [<account_address>]
"""

import argparse
import os
import sys
import time
from hippius_sdk import HippiusClient
from hippius_sdk.substrate import FileInput
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        description="Test Hippius SDK IPFS functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_hippius.py download QmCID123 downloaded_file.txt
  python test_hippius.py exists QmCID123
  python test_hippius.py cat QmCID123
  python test_hippius.py store test_file.txt
  python test_hippius.py store-dir ./test_directory
  python test_hippius.py credits
  python test_hippius.py credits 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
  python test_hippius.py files
  python test_hippius.py files 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH
  python test_hippius.py files --all-miners
"""
    )
    
    # Optional arguments for all commands
    parser.add_argument(
        "--gateway", 
        default=os.getenv("IPFS_GATEWAY", "https://ipfs.io"),
        help="IPFS gateway URL for downloads (default: from env or https://ipfs.io)"
    )
    parser.add_argument(
        "--api-url", 
        default=os.getenv("IPFS_API_URL", "https://relay-fr.hippius.network"),
        help="IPFS API URL for uploads (default: from env or https://relay-fr.hippius.network)"
    )
    parser.add_argument(
        "--local-ipfs",
        action="store_true",
        help="Use local IPFS node (http://localhost:5001) instead of remote API"
    )
    parser.add_argument(
        "--substrate-url",
        default=os.getenv("SUBSTRATE_URL", "wss://rpc.hippius.network"),
        help="Substrate node WebSocket URL (default: from env or wss://rpc.hippius.network)"
    )
    parser.add_argument(
        "--miner-ids",
        help="Comma-separated list of miner IDs for storage (default: from env SUBSTRATE_DEFAULT_MINERS)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug output"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Download command
    download_parser = subparsers.add_parser("download", help="Download a file from IPFS")
    download_parser.add_argument("cid", help="CID of file to download")
    download_parser.add_argument("output_path", help="Path to save downloaded file")
    
    # Exists command
    exists_parser = subparsers.add_parser("exists", help="Check if a CID exists on IPFS")
    exists_parser.add_argument("cid", help="CID to check")
    
    # Cat command
    cat_parser = subparsers.add_parser("cat", help="Display content of a file from IPFS")
    cat_parser.add_argument("cid", help="CID of file to display")
    cat_parser.add_argument("--max-size", type=int, default=1024, 
                           help="Maximum number of bytes to display (default: 1024)")
    
    # Store command (upload to IPFS then store on Substrate)
    store_parser = subparsers.add_parser("store", help="Upload a file to IPFS and store it on Substrate")
    store_parser.add_argument("file_path", help="Path to file to upload")
    
    # Store directory command
    store_dir_parser = subparsers.add_parser("store-dir", help="Upload a directory to IPFS and store all files on Substrate")
    store_dir_parser.add_argument("dir_path", help="Path to directory to upload")
    
    # Credits command
    credits_parser = subparsers.add_parser("credits", help="Check free credits for an account in the marketplace")
    credits_parser.add_argument("account_address", nargs="?", default=None, 
                              help="Substrate account address (uses keypair address if not specified)")
    
    # Files command
    files_parser = subparsers.add_parser("files", help="View detailed information about files stored by a user")
    files_parser.add_argument("account_address", nargs="?", default=None, 
                            help="Substrate account address (uses keypair address if not specified)")
    files_parser.add_argument("--debug", action="store_true", 
                            help="Show debug information about CID decoding")
    files_parser.add_argument("--all-miners", action="store_true",
                            help="Show all miners for each file instead of only the first 3")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        # Initialize client with provided gateway and API URL
        client = HippiusClient(
            ipfs_gateway=args.gateway,
            ipfs_api_url="http://localhost:5001" if args.local_ipfs else args.api_url,
            substrate_url=args.substrate_url
        )
        
        # Parse miner IDs if provided
        miner_ids = None
        if args.miner_ids:
            miner_ids = [miner.strip() for miner in args.miner_ids.split(",")]
        elif os.getenv("SUBSTRATE_DEFAULT_MINERS"):
            miner_ids = [miner.strip() for miner in os.getenv("SUBSTRATE_DEFAULT_MINERS").split(",")]
        
        # Handle commands
        if args.command == "download":
            return handle_download(client, args.cid, args.output_path)
            
        elif args.command == "exists":
            return handle_exists(client, args.cid)
            
        elif args.command == "cat":
            return handle_cat(client, args.cid, args.max_size)
            
        elif args.command == "store":
            return handle_store(client, args.file_path, miner_ids)
            
        elif args.command == "store-dir":
            return handle_store_dir(client, args.dir_path, miner_ids)
            
        elif args.command == "credits":
            return handle_credits(client, args.account_address)
            
        elif args.command == "files":
            return handle_files(client, args.account_address, 
                              debug=args.debug if hasattr(args, 'debug') else False,
                              show_all_miners=args.all_miners if hasattr(args, 'all_miners') else False)
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
        
    return 0


def handle_download(client, cid, output_path):
    """Handle the download command"""
    print(f"Downloading {cid} to {output_path}...")
    start_time = time.time()
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # Download the file
    client.download_file(cid, output_path)
    
    elapsed_time = time.time() - start_time
    file_size_bytes = os.path.getsize(output_path)
    file_size_mb = file_size_bytes / (1024 * 1024)
    
    print(f"Download successful in {elapsed_time:.2f} seconds!")
    print(f"Saved to: {output_path}")
    print(f"Size: {file_size_bytes} bytes ({file_size_mb:.2f} MB)")
    
    return 0


def handle_exists(client, cid):
    """Handle the exists command"""
    print(f"Checking if CID {cid} exists on IPFS...")
    exists = client.exists(cid)
    print(f"CID {cid} exists: {exists}")
    
    if exists:
        print("\nTo download this file, you can run:")
        print(f"  python {sys.argv[0]} download {cid} <output_path>")
    
    return 0


def handle_cat(client, cid, max_size):
    """Handle the cat command"""
    print(f"Retrieving content of CID {cid}...")
    try:
        content = client.cat(cid)
        
        # Limit the output size
        if len(content) > max_size:
            display_content = content[:max_size]
            print(f"Content (showing first {max_size} bytes):")
        else:
            display_content = content
            print("Content:")
        
        # Try to decode as text, fallback to hex display for binary data
        try:
            print(display_content.decode('utf-8'))
        except UnicodeDecodeError:
            print(f"Binary content (hex): {display_content.hex()}")
            
        print(f"\nTotal size: {len(content)} bytes")
        
    except Exception as e:
        print(f"Error retrieving content: {e}")
        return 1
    
    return 0


def handle_store(client, file_path, miner_ids):
    """Handle the store command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return 1
        
    print(f"Uploading {file_path} to IPFS...")
    start_time = time.time()
    
    # Upload the file to IPFS first
    result = client.upload_file(file_path)
    
    ipfs_elapsed_time = time.time() - start_time
    file_size_mb = result["size_bytes"] / (1024 * 1024)
    
    print(f"IPFS upload successful in {ipfs_elapsed_time:.2f} seconds!")
    print(f"CID: {result['cid']}")
    print(f"Filename: {result['filename']}")
    print(f"Size: {result['size_bytes']} bytes ({file_size_mb:.2f} MB)")
    
    # Store the file on Substrate
    print("\nStoring the file on Substrate...")
    start_time = time.time()
    
    try:
        # Create a file input object for the marketplace
        file_input = {
            "fileHash": result["cid"],
            "fileName": result["filename"]
        }
        
        # Store on Substrate
        client.substrate_client.storage_request([file_input], miner_ids)
        
        substrate_elapsed_time = time.time() - start_time
        print(f"Substrate storage request completed in {substrate_elapsed_time:.2f} seconds!")
        
        # Suggestion to verify
        print("\nTo verify the IPFS upload, you can run:")
        print(f"  python {sys.argv[0]} exists {result['cid']}")
        print(f"  python {sys.argv[0]} cat {result['cid']}")
    
    except NotImplementedError as e:
        print(f"\nNote: {e}")
    except Exception as e:
        print(f"\nError storing file on Substrate: {e}")
        return 1
    
    return 0


def handle_store_dir(client, dir_path, miner_ids):
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
            file_result = client.upload_file(file_path)
            individual_cids.append({
                "path": rel_path,
                "cid": file_result["cid"],
                "filename": file_result["filename"],
                "size_bytes": file_result["size_bytes"]
            })
            print(f"    CID: {individual_cids[-1]['cid']}")
        except Exception as e:
            print(f"    Error uploading {rel_path}: {e}")
    
    # Now upload the entire directory
    result = client.upload_directory(dir_path)
    
    ipfs_elapsed_time = time.time() - start_time
    
    print(f"\nIPFS directory upload successful in {ipfs_elapsed_time:.2f} seconds!")
    print(f"Directory CID: {result['cid']}")
    print(f"Directory name: {result['dirname']}")
    
    # Print summary of all individual file CIDs
    print(f"\nAll individual file CIDs ({len(individual_cids)}):")
    for item in individual_cids:
        size_kb = item["size_bytes"] / 1024
        print(f"  {item['path']}: {item['cid']} ({size_kb:.2f} KB)")
    
    # Suggestion to verify
    print("\nTo verify the IPFS directory upload, you can run:")
    print(f"  python {sys.argv[0]} exists {result['cid']}")
    
    # Suggestion to pin files
    print("\nTo pin individual files, you can run:")
    for item in individual_cids:
        print(f"  python {sys.argv[0]} pin {item['cid']}  # {item['path']}")
    print(f"  python {sys.argv[0]} pin {result['cid']}  # directory")
    
    # Store all files on Substrate
    print("\nStoring all files on Substrate...")
    start_time = time.time()
    
    try:
        # Create file input objects for the marketplace
        file_inputs = []
        for item in individual_cids:
            file_inputs.append({
                "fileHash": item["cid"],
                "fileName": item["filename"]
            })
        
        # Store all files in a single batch request
        client.substrate_client.storage_request(file_inputs, miner_ids)
        
        substrate_elapsed_time = time.time() - start_time
        print(f"Substrate storage request completed in {substrate_elapsed_time:.2f} seconds!")
    
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
        raw_value = int(credits * 1_000_000_000_000_000_000)  # Convert back to raw for display
        print(f"Raw value: {raw_value:,}")
        print(f"Account address: {account_address or 'Using default keypair address'}")
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
            # Try to decode a sample hex-encoded CID to test the implementation
            sample_hex = "6261666b7265696134696b3262697767736675647237656e6a6d6170617174657733336e727467697032656c663472777134323537636f68666561"
            try:
                print("\nTesting CID decoding with sample hex:")
                hex_bytes = bytes.fromhex(sample_hex)
                ascii_str = hex_bytes.decode('ascii')
                print(f"  Hex: {sample_hex}")
                print(f"  Decoded as ASCII: {ascii_str}")
                print(f"  Starts with valid prefix: {ascii_str.startswith(('Qm', 'bafy', 'bafk', 'bafyb', 'bafzb', 'b'))}")
            except Exception as e:
                print(f"  Error decoding sample: {e}")
        
        files = client.substrate_client.get_user_files(account_address)
        
        if files:
            print(f"\nFound {len(files)} files for account: {account_address or client.substrate_client._keypair.ss58_address}")
            print("\n" + "-" * 80)
            
            for i, file in enumerate(files, 1):
                print(f"File {i}:")
                
                # Display file hash (CID) - already formatted in substrate.py
                file_hash = file.get('file_hash', 'Unknown')
                print(f"  File Hash (CID): {file_hash}")
                
                if debug and file_hash.startswith('0x'):
                    # If it's still hex, show debug info
                    hex_str = file_hash[2:]  # Remove 0x prefix
                    try:
                        print("  DEBUG - Trying to decode this CID:")
                        hex_bytes = bytes.fromhex(hex_str)
                        print(f"    Hex bytes length: {len(hex_bytes)}")
                        try:
                            ascii_str = hex_bytes.decode('ascii', errors='replace')
                            print(f"    As ASCII: {ascii_str}")
                        except Exception as e:
                            print(f"    ASCII decode error: {e}")
                    except Exception as e:
                        print(f"    Hex decode error: {e}")
                
                # Display file name
                print(f"  File Name: {file.get('file_name', 'Unnamed')}")
                
                # Display file size
                file_size = file.get('file_size', 0)
                size_kb = file_size / 1024
                size_mb = size_kb / 1024
                
                if size_mb >= 1:
                    print(f"  File Size: {file_size:,} bytes ({size_mb:.2f} MB)")
                else:
                    print(f"  File Size: {file_size:,} bytes ({size_kb:.2f} KB)")
                
                # Display miners - use the clean list from substrate.py
                miners = file.get('miner_ids', [])
                if miners:
                    print(f"  Pinned by {len(miners)} miners:")
                    # Only show first 3 miners if there are many (unless show_all_miners is True)
                    if len(miners) > 3 and not show_all_miners:
                        display_miners = miners[:3]
                        print(f"    (Showing first 3 of {len(miners)} miners - use --all-miners to see all)")
                    else:
                        display_miners = miners
                        if len(miners) > 3:
                            print(f"    (Showing all {len(miners)} miners)")
                    
                    for miner_id in display_miners:
                        # Format long IDs for readability
                        if isinstance(miner_id, str) and miner_id.startswith('1') and len(miner_id) > 40:
                            # Truncate long peer IDs
                            print(f"    - {miner_id[:12]}...{miner_id[-4:]}")
                        else:
                            print(f"    - {miner_id}")
                else:
                    print("  Not pinned by any miners")
                
                print("-" * 80)
        else:
            print(f"No files found for account: {account_address or 'Using default keypair address'}")
    except Exception as e:
        print(f"Error retrieving file information: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 