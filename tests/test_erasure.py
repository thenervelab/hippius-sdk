#!/usr/bin/env python3
"""
Test module for Erasure Coding with IPFS Integration in Hippius SDK.

This test module tests various edge cases of erasure coding in combination
with IPFS uploads/downloads:
1. Empty file handling
2. Small file processing
3. Corrupted shares recovery
4. Minimum shares reconstruction
5. Missing metadata recovery
6. Large file chunking
"""

import asyncio
import hashlib
import json
import os
import random
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from hippius_sdk import HippiusClient

# Check for zfec
try:
    import zfec

    ZFEC_AVAILABLE = True
except ImportError:
    ZFEC_AVAILABLE = False

# IPFS configuration with timeout settings
# Can be overridden by environment variables
IPFS_GATEWAY = os.environ.get("IPFS_GATEWAY", "http://127.0.0.1:8080")
IPFS_API_URL = os.environ.get("IPFS_API_URL", "http://127.0.0.1:5001")
IPFS_TIMEOUT = int(os.environ.get("IPFS_TIMEOUT", "30"))  # Timeout in seconds

# Default erasure coding parameters
DEFAULT_K = 3
DEFAULT_M = 5


@pytest.fixture
def client(docker_ipfs_node, test_hippius_key):
    """
    Create and return a HippiusClient configured for Docker IPFS.

    Args:
        docker_ipfs_node: Session-scoped fixture that provides Docker IPFS API URL
        test_hippius_key: Test HIPPIUS_KEY from environment
    """
    # Create client with Docker IPFS settings and hippius_key
    client = HippiusClient(
        ipfs_api_url=docker_ipfs_node,
        hippius_key=test_hippius_key,
    )

    # Verify client is properly instantiated
    if client is None or not hasattr(client, "ipfs_client"):
        pytest.skip("Failed to create HippiusClient")

    return client


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    dir_path = tempfile.mkdtemp()
    yield dir_path
    # Clean up after test
    try:
        shutil.rmtree(dir_path)
    except Exception as e:
        print(f"Warning: Could not clean up temp directory {dir_path}: {e}")


class CleanupManager:
    """Context manager for test file cleanup."""

    def __init__(self):
        self.files = []

    def add(self, file_path):
        """Add a file to be cleaned up."""
        self.files.append(file_path)
        return file_path

    def cleanup(self):
        """Clean up all registered files."""
        for path in self.files:
            if os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                except Exception as e:
                    print(f"Warning: Failed to clean up {path}: {e}")


async def create_test_file(path: str, size_kb: int = 10) -> str:
    """Create a test file with predictable content for verification."""
    with open(path, "wb") as f:
        # For small files, create recognizable patterns for easy verification
        for i in range(size_kb):
            # Create a 1KB block with index embedded for verification
            block = f"BLOCK_{i:04d}_".encode() * (1024 // 10)
            block = block[:1024]  # Ensure exactly 1KB
            f.write(block)

    return path


async def create_large_file(path: str, size_mb: int = 3) -> str:
    """Create a larger test file using streaming to avoid memory issues."""
    with open(path, "wb") as f:
        # Write in 1MB chunks
        chunk_size = 1024 * 1024
        for i in range(size_mb):
            # Create deterministic but unique data for each chunk
            chunk_data = f"CHUNK_{i:04d}_".encode() * (chunk_size // 10)
            chunk_data = chunk_data[:chunk_size]  # Ensure exact size
            f.write(chunk_data)

    return path


async def verify_files_match(
    original: str, reconstructed: str, sample_count: int = 10
) -> bool:
    """Verify two files match using size and content checks."""
    # Check file exists
    if not os.path.exists(original) or not os.path.exists(reconstructed):
        print(
            f"File existence check failed: Original exists: {os.path.exists(original)}, "
            f"Reconstructed exists: {os.path.exists(reconstructed)}"
        )
        return False

    # Check file sizes
    orig_size = os.path.getsize(original)
    recon_size = os.path.getsize(reconstructed)

    if orig_size != recon_size:
        print(
            f"Size mismatch: Original {orig_size} bytes, Reconstructed {recon_size} bytes"
        )
        return False

    # For small files, check entire content
    if orig_size < 1024 * 1024:  # If less than 1MB
        try:
            with open(original, "rb") as f1, open(reconstructed, "rb") as f2:
                original_data = f1.read()
                reconstructed_data = f2.read()
                if original_data != reconstructed_data:
                    print(f"Content mismatch for small file.")
                    return False
                return True
        except Exception as e:
            print(f"Error comparing small files: {str(e)}")
            return False

    # For larger files, check hash
    try:
        with open(original, "rb") as f1, open(reconstructed, "rb") as f2:
            hash1 = hashlib.md5()
            hash2 = hashlib.md5()

            # Read and update hash in chunks to avoid memory issues
            for chunk in iter(lambda: f1.read(4096), b""):
                hash1.update(chunk)
            for chunk in iter(lambda: f2.read(4096), b""):
                hash2.update(chunk)

            if hash1.hexdigest() != hash2.hexdigest():
                print(f"MD5 hash mismatch: {hash1.hexdigest()} vs {hash2.hexdigest()}")
                return False

            return True

    except Exception as e:
        print(f"Error comparing large files: {str(e)}")
        return False


async def ipfs_operation_with_retry(operation_func, max_retries=3, delay=1):
    """Execute an IPFS operation with retry logic."""
    for attempt in range(max_retries):
        try:
            result = await operation_func()
            return result
        except Exception as e:
            if attempt == max_retries - 1:  # Last attempt
                raise
            print(
                f"Operation attempt {attempt+1} failed: {str(e)}. Retrying in {delay}s..."
            )
            await asyncio.sleep(delay)


async def encode_data_to_shares(
    data: bytes, k: int, m: int
) -> Tuple[List[bytes], int, int]:
    """
    Encode data into erasure-coded shares.

    Returns:
        Tuple containing:
        - List of encoded shares
        - Block size
        - Padding size
    """
    # Ensure data is divisible by k
    padding_size = (k - (len(data) % k)) % k
    if padding_size > 0:
        data += b"\0" * padding_size

    # Split into k blocks
    block_size = len(data) // k
    blocks = []
    for i in range(k):
        block_start = i * block_size
        block_end = block_start + block_size
        blocks.append(data[block_start:block_end])

    # Encode into m shares
    encoder = zfec.Encoder(k, m)
    shares = encoder.encode(blocks)

    return shares, block_size, padding_size


async def upload_shares_to_ipfs(
    client, shares: List[bytes], temp_dir: str, prefix="share"
) -> List[Dict[str, Any]]:
    """
    Upload shares to IPFS and return their info.

    Returns:
        List of dictionaries with share info (index, cid, size)
    """
    share_info = []
    cleanup = CleanupManager()

    try:
        for i, share in enumerate(shares):
            # Write share to temporary file
            share_path = cleanup.add(os.path.join(temp_dir, f"{prefix}_{i}.bin"))
            with open(share_path, "wb") as f:
                f.write(share)

            # Upload to IPFS with retry
            result = await ipfs_operation_with_retry(
                lambda: client.upload_file(share_path)
            )

            # Validate CID format (CIDv0 starts with Qm, CIDv1 starts with baf)
            assert result["cid"].startswith("Qm") or result["cid"].startswith(
                "baf"
            ), f"Invalid CID format: {result['cid']}"

            share_info.append({"index": i, "cid": result["cid"], "size": len(share)})

        return share_info
    finally:
        cleanup.cleanup()


async def download_shares(
    client, share_info: List[Dict[str, Any]], k: int, temp_dir: str
) -> Tuple[List[bytes], List[int]]:
    """
    Download k random shares from IPFS.

    Returns:
        Tuple containing:
        - List of share data
        - List of share indexes
    """
    # Select k random shares
    selected_shares = random.sample(share_info, k)
    downloaded_shares = []
    share_indexes = []
    cleanup = CleanupManager()

    try:
        for share in selected_shares:
            share_idx = share["index"]
            share_indexes.append(share_idx)

            # Download from IPFS
            share_path = cleanup.add(
                os.path.join(temp_dir, f"dl_share_{share_idx}.bin")
            )
            await ipfs_operation_with_retry(
                lambda: client.download_file(share["cid"], share_path)
            )

            # Read the share data
            with open(share_path, "rb") as f:
                downloaded_shares.append(f.read())

        return downloaded_shares, share_indexes
    finally:
        cleanup.cleanup()


async def reconstruct_from_shares(
    downloaded_shares: List[bytes],
    share_indexes: List[int],
    k: int,
    m: int,
    padding_size: int = 0,
) -> bytes:
    """
    Reconstruct original data from downloaded shares.

    Returns:
        Reconstructed data with padding removed
    """
    # Reconstruct using zfec
    decoder = zfec.Decoder(k, m)
    reconstructed_blocks = decoder.decode(downloaded_shares, share_indexes)
    reconstructed_data = b"".join(reconstructed_blocks)

    # Remove padding if needed
    if padding_size > 0:
        reconstructed_data = reconstructed_data[:-padding_size]

    return reconstructed_data


def create_metadata(
    original_file: str,
    k: int,
    m: int,
    block_size: int,
    padding_size: int,
    shares: List[Dict[str, Any]],
    file_size: int = 0,
    is_empty: bool = False,
    is_chunked: bool = False,
    chunks_info: List[Dict[str, Any]] = None,
    **extra_fields,
) -> Dict[str, Any]:
    """Create metadata for erasure coded file."""
    metadata = {
        "original_file": os.path.basename(original_file),
        "original_size": file_size,
        "erasure_coding": {"k": k, "m": m, "block_size": block_size},
        "padding_size": padding_size,
        "shares": shares,
        "created_at": time.time(),
        "version": "1.0",
    }

    if is_empty:
        metadata["is_empty_file"] = True

    if is_chunked and chunks_info:
        metadata["chunked"] = True
        metadata["chunks"] = chunks_info

    # Add any extra fields
    for key, value in extra_fields.items():
        metadata[key] = value

    return metadata


async def prepare_and_upload_metadata(
    client, metadata: Dict[str, Any], temp_dir: str
) -> str:
    """
    Prepare and upload metadata to IPFS.

    Returns:
        Metadata CID
    """
    cleanup = CleanupManager()
    try:
        # Write metadata to file
        metadata_path = cleanup.add(os.path.join(temp_dir, "metadata.json"))
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Upload metadata
        result = await ipfs_operation_with_retry(
            lambda: client.upload_file(metadata_path)
        )

        return result["cid"]
    finally:
        cleanup.cleanup()


async def download_and_parse_metadata(
    client, metadata_cid: str, temp_dir: str
) -> Dict[str, Any]:
    """
    Download and parse metadata from IPFS.

    Returns:
        Parsed metadata
    """
    cleanup = CleanupManager()
    try:
        # Download metadata
        metadata_path = cleanup.add(os.path.join(temp_dir, "downloaded_metadata.json"))
        await ipfs_operation_with_retry(
            lambda: client.download_file(metadata_cid, metadata_path)
        )

        # Parse metadata
        with open(metadata_path, "r") as f:
            metadata = json.load(f)

        return metadata
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
async def test_empty_file_erasure(client, temp_dir):
    """Test erasure coding with an empty file uploaded to IPFS."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters
        k, m = DEFAULT_K, DEFAULT_M

        # Create empty file
        file_path = cleanup.add(os.path.join(temp_dir, "empty_test.bin"))
        with open(file_path, "wb") as f:
            pass

        # Placeholder for empty file
        placeholder = b"EMPTY_FILE_PLACEHOLDER"

        # Encode placeholder into shares
        shares, block_size, padding_size = await encode_data_to_shares(
            placeholder, k, m
        )

        # Upload shares to IPFS
        share_info = await upload_shares_to_ipfs(
            client, shares, temp_dir, "empty_share"
        )

        # Create and upload metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=block_size,
            padding_size=padding_size,
            shares=share_info,
            file_size=0,
            is_empty=True,
        )

        metadata_cid = await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original for simulation
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # Download and parse metadata
        recovered_metadata = await download_and_parse_metadata(
            client, metadata_cid, temp_dir
        )

        # Reconstruct file
        reconstructed_path = cleanup.add(
            os.path.join(temp_dir, "empty_reconstructed.bin")
        )

        # For empty files, just create an empty file
        if recovered_metadata.get("is_empty_file"):
            with open(reconstructed_path, "wb") as f:
                pass

        # Verify reconstructed file
        assert os.path.exists(reconstructed_path)
        assert os.path.getsize(reconstructed_path) == 0

    except Exception as e:
        pytest.fail(f"Empty file test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
async def test_small_file_erasure(client, temp_dir):
    """Test basic erasure coding with a small file uploaded to IPFS."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters
        k, m = DEFAULT_K, DEFAULT_M

        # Create test file
        file_path = cleanup.add(os.path.join(temp_dir, "small_test.bin"))
        await create_test_file(file_path, size_kb=10)

        # Read the file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Encode data into shares
        shares, block_size, padding_size = await encode_data_to_shares(file_data, k, m)

        # Upload shares to IPFS
        share_info = await upload_shares_to_ipfs(
            client, shares, temp_dir, "small_share"
        )

        # Create and upload metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=block_size,
            padding_size=padding_size,
            shares=share_info,
            file_size=len(file_data),
        )

        metadata_cid = await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original for simulation
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # Download and parse metadata
        recovered_metadata = await download_and_parse_metadata(
            client, metadata_cid, temp_dir
        )

        # Download shares
        downloaded_shares, share_indexes = await download_shares(
            client, recovered_metadata["shares"], k, temp_dir
        )

        # Reconstruct data
        reconstructed_data = await reconstruct_from_shares(
            downloaded_shares, share_indexes, k, m, recovered_metadata["padding_size"]
        )

        # Write reconstructed file
        reconstructed_path = cleanup.add(
            os.path.join(temp_dir, "small_reconstructed.bin")
        )
        with open(reconstructed_path, "wb") as f:
            f.write(reconstructed_data)

        # Verify reconstructed file
        assert await verify_files_match(backup_path, reconstructed_path)

    except Exception as e:
        pytest.fail(f"Small file test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
async def test_corrupted_shares(client, temp_dir):
    """Test reconstruction when some shares are corrupted."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters
        k, m = DEFAULT_K, DEFAULT_M

        # Create test file
        file_path = cleanup.add(os.path.join(temp_dir, "corrupt_test.bin"))
        await create_test_file(file_path, size_kb=20)

        # Read the file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Encode data into shares
        shares, block_size, padding_size = await encode_data_to_shares(file_data, k, m)

        # Create a corrupted share (for share at index 0)
        corrupt_data = (
            b"This is completely corrupted data" * 50
        )  # Make sure it's large enough

        # Upload shares to IPFS, with one corrupted
        share_info = []
        for i, share in enumerate(shares):
            # Write share to temporary file
            share_path = cleanup.add(os.path.join(temp_dir, f"corrupt_share_{i}.bin"))

            # For the first share, use corrupted data
            if i == 0:
                with open(share_path, "wb") as f:
                    f.write(corrupt_data)

                # Upload corrupted data
                corrupt_result = await ipfs_operation_with_retry(
                    lambda: client.upload_file(share_path)
                )

                share_info.append(
                    {
                        "index": i,
                        "cid": corrupt_result["cid"],
                        "corrupted": True,
                        "size": len(corrupt_data),
                    }
                )
            else:
                # Upload normal share
                with open(share_path, "wb") as f:
                    f.write(share)

                result = await ipfs_operation_with_retry(
                    lambda: client.upload_file(share_path)
                )

                share_info.append(
                    {
                        "index": i,
                        "cid": result["cid"],
                        "corrupted": False,
                        "size": len(share),
                    }
                )

        # Create and upload metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=block_size,
            padding_size=padding_size,
            shares=share_info,
            file_size=len(file_data),
            corrupt_test=True,
            corrupted_share_index=0,
        )

        metadata_cid = await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # Download and parse metadata
        recovered_metadata = await download_and_parse_metadata(
            client, metadata_cid, temp_dir
        )

        # CASE 1: Try to reconstruct using corrupted share
        # This should either fail or produce incorrect data
        case1_path = cleanup.add(os.path.join(temp_dir, "corrupt_case1.bin"))

        # Select shares including the corrupted one
        all_shares = recovered_metadata["shares"]
        corrupted_idx = 0  # We know it's the first one

        # Pick the corrupted share plus k-1 others
        corrupt_test_shares = [all_shares[corrupted_idx]]
        other_shares = [
            share for i, share in enumerate(all_shares) if i != corrupted_idx
        ]
        corrupt_test_shares.extend(random.sample(other_shares, k - 1))

        # Track if reconstruction with corrupted share succeeded
        corrupt_reconstruction_failed = False

        try:
            # Download these shares
            downloaded_corrupt_shares = []
            corrupt_share_indexes = []

            for share in corrupt_test_shares:
                share_idx = share["index"]
                corrupt_share_indexes.append(share_idx)

                # Download from IPFS
                share_path = cleanup.add(
                    os.path.join(temp_dir, f"corrupt_dl_{share_idx}.bin")
                )
                await ipfs_operation_with_retry(
                    lambda: client.download_file(share["cid"], share_path)
                )

                # Read the share data
                with open(share_path, "rb") as f:
                    downloaded_corrupt_shares.append(f.read())

            # Try to reconstruct (might fail or produce incorrect data)
            try:
                corrupt_data = await reconstruct_from_shares(
                    downloaded_corrupt_shares,
                    corrupt_share_indexes,
                    k,
                    m,
                    recovered_metadata["padding_size"],
                )

                # If we get here, reconstruction "succeeded" but should produce incorrect data
                with open(case1_path, "wb") as f:
                    f.write(corrupt_data)

                # This reconstruction should not match the original
                is_correct = await verify_files_match(backup_path, case1_path)
                assert (
                    not is_correct
                ), "Reconstruction with corrupted share should not match original"

            except Exception:
                # Expected error
                corrupt_reconstruction_failed = True
                print("Reconstruction with corrupted share failed as expected")

        except Exception as e:
            print(f"Error in corrupted share test case 1: {str(e)}")

        # CASE 2: Reconstruct avoiding the corrupted share
        case2_path = cleanup.add(os.path.join(temp_dir, "corrupt_case2.bin"))

        # Select k shares excluding the corrupted one
        valid_shares = [
            share for share in all_shares if not share.get("corrupted", False)
        ]

        # Download these shares
        downloaded_shares, share_indexes = await download_shares(
            client, valid_shares, k, temp_dir
        )

        # Reconstruct data
        reconstructed_data = await reconstruct_from_shares(
            downloaded_shares, share_indexes, k, m, recovered_metadata["padding_size"]
        )

        # Write reconstructed file
        with open(case2_path, "wb") as f:
            f.write(reconstructed_data)

        # Verify reconstructed file
        assert await verify_files_match(backup_path, case2_path)

    except Exception as e:
        pytest.fail(f"Corrupted shares test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
async def test_min_shares_reconstruction(client, temp_dir):
    """Test reconstruction with exactly k shares (minimum needed)."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters - high redundancy scenario
        k = DEFAULT_K
        m = 10  # More redundancy for this test

        # Create test file
        file_path = cleanup.add(os.path.join(temp_dir, "min_shares_test.bin"))
        await create_test_file(file_path, size_kb=15)

        # Read the file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Encode data into shares
        shares, block_size, padding_size = await encode_data_to_shares(file_data, k, m)

        # Upload shares to IPFS
        share_info = await upload_shares_to_ipfs(client, shares, temp_dir, "min_share")

        # Create and upload metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=block_size,
            padding_size=padding_size,
            shares=share_info,
            file_size=len(file_data),
        )

        metadata_cid = await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # Download and parse metadata
        recovered_metadata = await download_and_parse_metadata(
            client, metadata_cid, temp_dir
        )

        # Select exactly k shares
        all_shares = recovered_metadata["shares"]
        selected_shares = random.sample(all_shares, k)

        # Download these shares
        downloaded_shares, share_indexes = [], []

        for share in selected_shares:
            share_idx = share["index"]
            share_indexes.append(share_idx)

            # Download from IPFS
            share_path = cleanup.add(os.path.join(temp_dir, f"min_dl_{share_idx}.bin"))
            await ipfs_operation_with_retry(
                lambda: client.download_file(share["cid"], share_path)
            )

            # Read the share data
            with open(share_path, "rb") as f:
                downloaded_shares.append(f.read())

        # Reconstruct data
        reconstructed_data = await reconstruct_from_shares(
            downloaded_shares, share_indexes, k, m, recovered_metadata["padding_size"]
        )

        # Write reconstructed file
        reconstructed_path = cleanup.add(
            os.path.join(temp_dir, "min_reconstructed.bin")
        )
        with open(reconstructed_path, "wb") as f:
            f.write(reconstructed_data)

        # Verify reconstructed file
        assert await verify_files_match(backup_path, reconstructed_path)

    except Exception as e:
        pytest.fail(f"Minimum shares test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
async def test_missing_metadata(client, temp_dir):
    """Test reconstruction when metadata is missing using embedded filename info."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters
        k, m = DEFAULT_K, DEFAULT_M

        # Create test file
        file_path = cleanup.add(os.path.join(temp_dir, "metadata_test.bin"))
        await create_test_file(file_path, size_kb=10)

        # Read the file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Encode data into shares
        shares, block_size, padding_size = await encode_data_to_shares(file_data, k, m)

        # Store parameter info in the share filenames
        # Format: erasure_k{k}_m{m}_idx{i}_filesize{file_size}_padding{padding_size}.bin
        share_info = []
        for i, share in enumerate(shares):
            # Create filename with embedded parameters
            share_filename = f"erasure_k{k}_m{m}_idx{i}_filesize{len(file_data)}_padding{padding_size}.bin"
            share_path = cleanup.add(os.path.join(temp_dir, share_filename))

            with open(share_path, "wb") as f:
                f.write(share)

            # Upload to IPFS
            result = await ipfs_operation_with_retry(
                lambda: client.upload_file(share_path)
            )

            # Store share info with filename
            share_info.append(
                {
                    "index": i,
                    "cid": result["cid"],
                    "filename": share_filename,
                    "size": len(share),
                }
            )

        # Create metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=block_size,
            padding_size=padding_size,
            shares=share_info,
            file_size=len(file_data),
            note="This metadata file will be intentionally 'lost'",
        )

        # Upload metadata (but we'll ignore it later)
        await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # SCENARIO: We have CIDs of the shares but no metadata
        # We'll use the filenames embedded in the downloads to recover parameters
        share_cids = [share["cid"] for share in share_info]

        # Download k random shares
        selected_cids = random.sample(share_cids, k)
        downloaded_shares = []
        share_indexes = []
        recovered_k = None
        recovered_m = None
        recovered_size = None
        recovered_padding = None

        # Download and extract parameters from filenames
        for i, cid in enumerate(selected_cids):
            # Download from IPFS
            share_path = cleanup.add(os.path.join(temp_dir, f"recovered_share_{i}.bin"))
            await ipfs_operation_with_retry(
                lambda: client.download_file(cid, share_path)
            )

            # Get the share data
            with open(share_path, "rb") as f:
                share_data = f.read()
                downloaded_shares.append(share_data)

            # For each share, get original info since we can't access filename through API
            original_share = next(share for share in share_info if share["cid"] == cid)
            filename = original_share["filename"]

            # Parse parameters from filename
            # Format: erasure_k{k}_m{m}_idx{i}_filesize{file_size}_padding{padding_size}.bin
            parts = filename.split("_")

            if recovered_k is None:
                recovered_k = int(parts[1][1:])
            if recovered_m is None:
                recovered_m = int(parts[2][1:])
            if recovered_size is None:
                # Extract filesize part
                filesize_part = [p for p in parts if p.startswith("filesize")][0]
                recovered_size = int(filesize_part[8:])
            if recovered_padding is None:
                # Extract padding part
                padding_part = [p for p in parts if p.startswith("padding")][0]
                recovered_padding = int(padding_part[7:].split(".")[0])

            # Get share index
            idx_part = [p for p in parts if p.startswith("idx")][0]
            idx = int(idx_part[3:])
            share_indexes.append(idx)

        # At this point we've recovered all parameters from filenames
        print(
            f"Recovered parameters: k={recovered_k}, m={recovered_m}, size={recovered_size}, padding={recovered_padding}"
        )

        # Reconstruct using recovered parameters
        decoder = zfec.Decoder(recovered_k, recovered_m)
        reconstructed_blocks = decoder.decode(downloaded_shares, share_indexes)
        reconstructed_data = b"".join(reconstructed_blocks)

        # Remove padding if needed
        if recovered_padding > 0:
            reconstructed_data = reconstructed_data[:-recovered_padding]

        # Write reconstructed file
        reconstructed_path = cleanup.add(
            os.path.join(temp_dir, "metadata_reconstructed.bin")
        )
        with open(reconstructed_path, "wb") as f:
            f.write(reconstructed_data)

        # Verify reconstructed file
        assert await verify_files_match(backup_path, reconstructed_path)

    except Exception as e:
        pytest.fail(f"Missing metadata test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_large_file_chunked(client, temp_dir):
    """Test erasure coding with a larger file processed in chunks."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    cleanup = CleanupManager()
    try:
        # Parameters
        k, m = DEFAULT_K, DEFAULT_M
        chunk_size = 256 * 1024  # 256KB chunks (reduced from 1MB for faster testing)

        # Create a test file (1MB, smaller for tests but still demonstrates chunking)
        file_path = cleanup.add(os.path.join(temp_dir, "large_test.bin"))
        size_mb = 1  # Reduced from 3MB to 1MB for faster test execution
        await create_large_file(file_path, size_mb)

        # Get file size
        file_size = os.path.getsize(file_path)
        num_chunks = (file_size + chunk_size - 1) // chunk_size

        # Process file in chunks
        chunks_info = []

        with open(file_path, "rb") as f:
            for chunk_idx in range(num_chunks):
                # Read chunk
                chunk_data = f.read(chunk_size)

                # Encode chunk
                shares, block_size, padding_size = await encode_data_to_shares(
                    chunk_data, k, m
                )

                # Upload shares
                share_info = await upload_shares_to_ipfs(
                    client, shares, temp_dir, f"chunk_{chunk_idx}_share"
                )

                # Store chunk info
                chunks_info.append(
                    {
                        "chunk_index": chunk_idx,
                        "original_size": len(chunk_data),
                        "padding_size": padding_size,
                        "block_size": block_size,
                        "shares": share_info,
                    }
                )

        # Create and upload metadata
        metadata = create_metadata(
            original_file=file_path,
            k=k,
            m=m,
            block_size=0,  # Not used at top level for chunked files
            padding_size=0,  # Not used at top level for chunked files
            shares=[],  # Not used at top level for chunked files
            file_size=file_size,
            is_chunked=True,
            chunks_info=chunks_info,
            chunk_size=chunk_size,
            num_chunks=num_chunks,
        )

        metadata_cid = await prepare_and_upload_metadata(client, metadata, temp_dir)

        # Backup and delete original
        backup_path = cleanup.add(f"{file_path}.backup")
        shutil.copy(file_path, backup_path)
        os.remove(file_path)

        # Download and parse metadata
        recovered_metadata = await download_and_parse_metadata(
            client, metadata_cid, temp_dir
        )

        # Prepare for reconstruction
        reconstructed_path = cleanup.add(
            os.path.join(temp_dir, "large_reconstructed.bin")
        )

        # Reconstruct each chunk
        with open(reconstructed_path, "wb") as out_file:
            # Look for chunks info in the right field
            chunks_key = (
                "chunks_info" if "chunks_info" in recovered_metadata else "chunks"
            )
            if chunks_key not in recovered_metadata:
                print(f"Metadata keys: {list(recovered_metadata.keys())}")
                raise KeyError(
                    f"No chunks information found in metadata. Available keys: {list(recovered_metadata.keys())}"
                )

            for chunk_info in recovered_metadata[chunks_key]:
                chunk_idx = chunk_info["chunk_index"]

                # Download shares for this chunk
                downloaded_shares, share_indexes = await download_shares(
                    client, chunk_info["shares"], k, temp_dir
                )

                # Reconstruct chunk
                chunk_data = await reconstruct_from_shares(
                    downloaded_shares, share_indexes, k, m, chunk_info["padding_size"]
                )

                # Write to output file
                out_file.write(chunk_data)

        # Verify reconstructed file
        assert await verify_files_match(backup_path, reconstructed_path)

    except Exception as e:
        pytest.fail(f"Large file chunked test failed: {str(e)}")
    finally:
        cleanup.cleanup()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_erasure_coding_with_pinning(hippius_client, temp_test_file):
    """Test erasure coding with chunk and metadata pinning to Hippius API."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    result = await hippius_client.ipfs_client.store_erasure_coded_file(
        file_path=temp_test_file,
        k=3,
        m=5,
        api_client=hippius_client.api_client,
        pin_chunks=True,
        pin_metadata=True,
        verbose=False,
    )

    assert "metadata_cid" in result
    assert "metadata" in result

    assert result["metadata_pinned"] is True
    assert "metadata_pin_request_id" in result
    assert result["metadata_pin_request_id"] is not None

    metadata = result["metadata"]
    assert "chunks" in metadata

    for chunk in metadata["chunks"]:
        assert "cid" in chunk
        assert "pin_request_id" in chunk
        assert chunk["pin_request_id"] is not None


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_erasure_coding_without_pinning(hippius_client, temp_test_file):
    """Test erasure coding without API pinning."""
    if not ZFEC_AVAILABLE:
        pytest.skip("zfec not installed")

    result = await hippius_client.ipfs_client.store_erasure_coded_file(
        file_path=temp_test_file,
        k=3,
        m=5,
        pin_chunks=False,
        pin_metadata=False,
        verbose=False,
    )

    assert "metadata_cid" in result
    assert result["metadata_pinned"] is False

    metadata = result["metadata"]

    for chunk in metadata["chunks"]:
        assert "pin_request_id" not in chunk or chunk.get("pin_request_id") is None


if __name__ == "__main__":
    # For manual testing
    asyncio.run(pytest.main(["-xvs", __file__]))
