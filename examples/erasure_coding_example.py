#!/usr/bin/env python3
"""
Erasure Coding Example for Hippius SDK.

This example demonstrates how to use the erasure coding functionality
in the Hippius SDK to split files, add redundancy, and reconstruct them.

Requirements:
    - hippius SDK (pip install hippius)
    - zfec (pip install zfec)
"""

import argparse
import os
import random
import sys
import time

from hippius_sdk import HippiusClient


def create_test_file(file_path, size_mb=10):
    """Create a test file of the specified size."""
    print(f"Creating test file of {size_mb} MB at {file_path}...")

    # Create a file with random content
    with open(file_path, "wb") as f:
        # Write random data in chunks
        chunk_size = 1024 * 1024  # 1MB
        remaining = size_mb * chunk_size

        while remaining > 0:
            # Determine size of this chunk
            this_chunk = min(chunk_size, remaining)

            # Generate random data
            data = os.urandom(this_chunk)

            # Write to file
            f.write(data)

            # Update remaining
            remaining -= this_chunk

            # Show progress
            progress = (
                ((size_mb * chunk_size) - remaining) / (size_mb * chunk_size) * 100
            )
            print(f"  Progress: {progress:.1f}%", end="\r")

    print(f"Created test file: {file_path} ({size_mb} MB)")
    return file_path


def erasure_code_example(file_path, k=3, m=5, chunk_size=1024 * 1024, encrypt=False):
    """Demonstrate erasure coding functionality."""
    print("\n=== Erasure Coding Example ===")
    print(f"File: {file_path}")
    print(f"Parameters: k={k}, m={m} (need {k} of {m} chunks to reconstruct)")
    print(f"Chunk size: {chunk_size/1024/1024:.2f} MB")
    if encrypt:
        print("Encryption: Enabled")

    # Create a client
    client = HippiusClient()

    print("\n1. Splitting and uploading file...")
    start_time = time.time()

    # Erasure code the file
    result = client.erasure_code_file(
        file_path=file_path,
        k=k,
        m=m,
        chunk_size=chunk_size,
        encrypt=encrypt,
        verbose=True,
    )

    elapsed_time = time.time() - start_time
    print(f"Erasure coding completed in {elapsed_time:.2f} seconds")

    # Extract metadata
    metadata = result
    metadata_cid = metadata.get("metadata_cid")

    print(f"\nMetadata CID: {metadata_cid}")

    # Simulate deletion of original file
    if os.path.exists(file_path):
        print(f"\n2. Simulating deletion of original file...")
        backup_path = f"{file_path}.backup"
        os.rename(file_path, backup_path)
        print(f"Original file moved to {backup_path}")

    # Now reconstruct
    print(f"\n3. Reconstructing file from chunks...")
    reconstructed_path = f"{file_path}.reconstructed"

    start_time = time.time()

    # Reconstruct the file
    client.reconstruct_from_erasure_code(
        metadata_cid=metadata_cid, output_file=reconstructed_path, verbose=True
    )

    elapsed_time = time.time() - start_time
    print(f"Reconstruction completed in {elapsed_time:.2f} seconds")

    # Verify
    if os.path.exists(backup_path):
        print(f"\n4. Verifying reconstruction...")

        # Get file sizes
        original_size = os.path.getsize(backup_path)
        reconstructed_size = os.path.getsize(reconstructed_path)

        # Compare file sizes
        print(f"Original size: {original_size/1024/1024:.2f} MB")
        print(f"Reconstructed size: {reconstructed_size/1024/1024:.2f} MB")

        if original_size == reconstructed_size:
            print("Size match: Yes")
        else:
            print(
                f"Size match: No (difference: {abs(original_size - reconstructed_size)} bytes)"
            )

        # Compare file content (first 1MB and random samples)
        with open(backup_path, "rb") as f1, open(reconstructed_path, "rb") as f2:
            # Check first 1MB
            data1 = f1.read(1024 * 1024)
            data2 = f2.read(1024 * 1024)

            if data1 == data2:
                print("First 1MB content match: Yes")
            else:
                print("First 1MB content match: No")

            # If files are large, check a few random sample points
            if original_size > 10 * 1024 * 1024:  # If larger than 10MB
                print("Checking random samples throughout the file...")

                matches = 0
                samples = 5

                for _ in range(samples):
                    # Generate a random position
                    pos = random.randint(0, original_size - 1024)

                    # Read 1KB at this position
                    f1.seek(pos)
                    f2.seek(pos)

                    sample1 = f1.read(1024)
                    sample2 = f2.read(1024)

                    if sample1 == sample2:
                        matches += 1

                print(f"Random sample matches: {matches}/{samples}")

        # Restore original file
        print(f"\nRestoring original file from backup...")
        os.rename(backup_path, file_path)
        print(f"Original file restored")

    print("\n=== Erasure Coding Example Complete ===")


def main():
    """Run the example with command line arguments."""
    parser = argparse.ArgumentParser(
        description="Erasure Coding Example for Hippius SDK"
    )
    parser.add_argument("--file", help="File to use (will be created if doesn't exist)")
    parser.add_argument("--size", type=int, default=10, help="Size of test file in MB")
    parser.add_argument(
        "--k", type=int, default=3, help="Number of data chunks needed to reconstruct"
    )
    parser.add_argument("--m", type=int, default=5, help="Total number of chunks")
    parser.add_argument(
        "--chunk-size", type=int, default=1048576, help="Chunk size in bytes"
    )
    parser.add_argument("--encrypt", action="store_true", help="Enable encryption")

    args = parser.parse_args()

    # Determine file to use
    file_path = args.file

    if not file_path:
        file_path = "test_file.bin"

    # Create file if needed
    if not os.path.exists(file_path):
        create_test_file(file_path, args.size)

    # Run the example
    erasure_code_example(
        file_path=file_path,
        k=args.k,
        m=args.m,
        chunk_size=args.chunk_size,
        encrypt=args.encrypt,
    )


if __name__ == "__main__":
    main()
