#!/usr/bin/env python3
"""
Test script for Hippius SDK IPFS functionality

This script provides a command-line interface for testing the Hippius SDK's
IPFS operations including uploading, downloading, checking existence,
retrieving content, and pinning files.

Usage:
    python test_hippius.py upload <file_path>
    python test_hippius.py upload-dir <directory_path>
    python test_hippius.py download <cid> <output_path>
    python test_hippius.py exists <cid>
    python test_hippius.py cat <cid>
    python test_hippius.py pin <cid>
"""

import argparse
import os
import sys
import time
from hippius_sdk import HippiusClient


def main():
    parser = argparse.ArgumentParser(
        description="Test Hippius SDK IPFS functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_hippius.py upload test_file.txt
  python test_hippius.py upload-dir ./test_directory
  python test_hippius.py download QmCID123 downloaded_file.txt
  python test_hippius.py exists QmCID123
  python test_hippius.py cat QmCID123
  python test_hippius.py pin QmCID123
"""
    )
    
    # Optional arguments for all commands
    parser.add_argument(
        "--gateway", 
        default="https://ipfs.io",
        help="IPFS gateway URL for downloads (default: https://ipfs.io)"
    )
    parser.add_argument(
        "--api-url", 
        default="https://relay-fr.hippius.network",
        help="IPFS API URL for uploads (default: https://relay-fr.hippius.network)"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a file to IPFS")
    upload_parser.add_argument("file_path", help="Path to file to upload")
    
    # Upload directory command
    upload_dir_parser = subparsers.add_parser("upload-dir", help="Upload a directory to IPFS")
    upload_dir_parser.add_argument("dir_path", help="Path to directory to upload")
    
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
    
    # Pin command
    pin_parser = subparsers.add_parser("pin", help="Pin a CID to IPFS")
    pin_parser.add_argument("cid", help="CID to pin")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        # Initialize client with provided gateway and API URL
        client = HippiusClient(
            ipfs_gateway=args.gateway,
            ipfs_api_url=args.api_url
        )
        
        # Handle commands
        if args.command == "upload":
            return handle_upload(client, args.file_path)
            
        elif args.command == "upload-dir":
            return handle_upload_dir(client, args.dir_path)
            
        elif args.command == "download":
            return handle_download(client, args.cid, args.output_path)
            
        elif args.command == "exists":
            return handle_exists(client, args.cid)
            
        elif args.command == "cat":
            return handle_cat(client, args.cid, args.max_size)
            
        elif args.command == "pin":
            return handle_pin(client, args.cid)
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
        
    return 0


def handle_upload(client, file_path):
    """Handle the upload command"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return 1
        
    print(f"Uploading {file_path}...")
    start_time = time.time()
    
    result = client.upload_file(file_path)
    
    elapsed_time = time.time() - start_time
    file_size_mb = result["size_bytes"] / (1024 * 1024)
    
    print(f"Upload successful in {elapsed_time:.2f} seconds!")
    print(f"CID: {result['cid']}")
    print(f"Filename: {result['filename']}")
    print(f"Size: {result['size_bytes']} bytes ({file_size_mb:.2f} MB)")
    
    # Suggestion to verify
    print("\nTo verify the upload, you can run:")
    print(f"  python {sys.argv[0]} exists {result['cid']}")
    print(f"  python {sys.argv[0]} cat {result['cid']}")
    
    return 0


def handle_upload_dir(client, dir_path):
    """Handle the upload-dir command"""
    if not os.path.isdir(dir_path):
        print(f"Error: Directory {dir_path} not found")
        return 1
        
    print(f"Uploading directory {dir_path}...")
    start_time = time.time()
    
    result = client.upload_directory(dir_path)
    
    elapsed_time = time.time() - start_time
    
    print(f"Directory upload successful in {elapsed_time:.2f} seconds!")
    print(f"CID: {result['cid']}")
    print(f"Directory name: {result['dirname']}")
    
    # Suggestion to verify
    print("\nTo verify the upload, you can run:")
    print(f"  python {sys.argv[0]} exists {result['cid']}")
    
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


def handle_pin(client, cid):
    """Handle the pin command"""
    print(f"Pinning CID {cid} to IPFS...")
    try:
        success = client.pin(cid)
        if success:
            print(f"Successfully pinned {cid}")
        else:
            print(f"Failed to pin {cid}")
            return 1
    except Exception as e:
        print(f"Error pinning CID: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 