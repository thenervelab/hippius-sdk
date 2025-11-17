"""
Erasure Coding module for Hippius SDK.

Provides Reed-Solomon erasure coding functionality for file splitting and reconstruction.
This allows files to be split into m chunks where any k chunks can reconstruct the original.
"""

import hashlib
import json
import os
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

# Try to import zfec for erasure coding
try:
    from zfec import easyfec

    ERASURE_CODING_AVAILABLE = True
except ImportError:
    ERASURE_CODING_AVAILABLE = False


def is_erasure_coding_available() -> bool:
    """Check if erasure coding is available (zfec installed)."""
    return ERASURE_CODING_AVAILABLE


async def erasure_encode_file(
    file_path: str,
    k: int = 3,
    m: int = 5,
    chunk_size: int = 1024 * 1024,
    encrypt_data_fn: Optional[Callable[[bytes], bytes]] = None,
    verbose: bool = True,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Tuple[List[bytes], Dict[str, Any]]:
    """
    Split a file using Reed-Solomon erasure coding.

    Args:
        file_path: Path to the file to encode
        k: Number of data chunks (minimum required to reconstruct)
        m: Total number of chunks (k + redundancy)
        chunk_size: Size of each chunk in bytes before encoding
        encrypt_data_fn: Optional function to encrypt data before encoding
        verbose: Whether to print progress information
        progress_callback: Optional callback for progress updates (stage_name, current, total)

    Returns:
        Tuple of (encoded_chunks, metadata_dict)
        - encoded_chunks: List of m encoded chunk bytes
        - metadata_dict: Metadata needed for reconstruction

    Raises:
        ValueError: If erasure coding is not available or parameters are invalid
        FileNotFoundError: If file doesn't exist
    """
    if not ERASURE_CODING_AVAILABLE:
        raise ValueError(
            "Erasure coding is not available. Install zfec: pip install zfec"
        )

    if k >= m:
        raise ValueError(
            f"Invalid erasure coding parameters: k ({k}) must be less than m ({m})"
        )

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Get file info
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    if verbose:
        print(f"Processing file: {file_name} ({file_size / 1024 / 1024:.2f} MB)")
        print(
            f"Erasure coding parameters: k={k}, m={m} (need {k}/{m} chunks to reconstruct)"
        )

    # Read file
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Calculate original hash
    original_file_hash = hashlib.sha256(file_data).hexdigest()

    # Encrypt if function provided
    if encrypt_data_fn:
        if verbose:
            print("Encrypting file data...")
        file_data = encrypt_data_fn(file_data)

    # Split into chunks
    chunk_size = max(1, int(chunk_size))
    chunks = []
    chunk_positions = []

    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i : i + chunk_size]
        chunks.append(chunk)
        chunk_positions.append(i)

    # Pad last chunk if necessary
    if chunks and len(chunks[-1]) < chunk_size:
        pad_size = int(chunk_size - len(chunks[-1]))
        chunks[-1] = chunks[-1] + b"\x00" * pad_size

    if verbose:
        print(f"Split file into {len(chunks)} chunks of {chunk_size} bytes each")

    # Apply erasure coding to each chunk
    encoder = easyfec.Encoder(k, m)
    all_encoded_chunks = []

    for idx, chunk in enumerate(chunks):
        if progress_callback:
            progress_callback("Encoding chunks", idx + 1, len(chunks))

        encoded = encoder.encode(chunk)
        all_encoded_chunks.append(encoded)

        if verbose and (idx + 1) % 10 == 0:
            print(f"Encoded {idx + 1}/{len(chunks)} chunks...")

    # Restructure: create m output files, each containing one piece from each chunk
    final_chunks = []
    for piece_idx in range(m):
        piece_data = b""
        for chunk_encoded in all_encoded_chunks:
            piece_data += chunk_encoded[piece_idx]
        final_chunks.append(piece_data)

    # Create metadata
    metadata = {
        "file_id": str(uuid.uuid4()),
        "file_name": file_name,
        "file_size": file_size,
        "original_file_hash": original_file_hash,
        "k": k,
        "m": m,
        "chunk_size": chunk_size,
        "num_chunks": len(chunks),
        "encrypted": encrypt_data_fn is not None,
    }

    if verbose:
        print(f"Erasure coding complete: {m} pieces created")

    return final_chunks, metadata


async def erasure_decode_chunks(
    chunks: List[bytes],
    chunk_indices: List[int],
    metadata: Dict[str, Any],
    decrypt_data_fn: Optional[Callable[[bytes], bytes]] = None,
    verbose: bool = True,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> bytes:
    """
    Reconstruct a file from erasure-coded chunks.

    Args:
        chunks: List of at least k chunk bytes
        chunk_indices: List of indices indicating which chunks these are (0 to m-1)
        metadata: Metadata dict from encoding (contains k, m, chunk_size, etc.)
        decrypt_data_fn: Optional function to decrypt data after decoding
        verbose: Whether to print progress
        progress_callback: Optional callback for progress updates

    Returns:
        bytes: The reconstructed file data

    Raises:
        ValueError: If not enough chunks or invalid parameters
    """
    if not ERASURE_CODING_AVAILABLE:
        raise ValueError(
            "Erasure coding is not available. Install zfec: pip install zfec"
        )

    k = metadata["k"]
    m = metadata["m"]
    chunk_size = metadata["chunk_size"]
    num_chunks = metadata["num_chunks"]

    if len(chunks) < k:
        raise ValueError(
            f"Not enough chunks to reconstruct: have {len(chunks)}, need {k}"
        )

    if verbose:
        print(f"Reconstructing from {len(chunks)} of {m} chunks (need {k} minimum)")

    # Take only first k chunks
    chunks_to_use = chunks[:k]
    indices_to_use = chunk_indices[:k]

    # Calculate piece size (each chunk contains one piece from each original chunk)
    piece_size = len(chunks_to_use[0]) // num_chunks

    # Decode each original chunk
    decoder = easyfec.Decoder(k, m)
    decoded_chunks = []

    for chunk_idx in range(num_chunks):
        if progress_callback:
            progress_callback("Decoding chunks", chunk_idx + 1, num_chunks)

        # Extract the piece for this chunk from each file
        pieces = []
        for file_data in chunks_to_use:
            start = chunk_idx * piece_size
            end = start + piece_size
            pieces.append(file_data[start:end])

        # Decode this chunk
        decoded = decoder.decode(pieces, indices_to_use)
        decoded_chunks.append(decoded)

        if verbose and (chunk_idx + 1) % 10 == 0:
            print(f"Decoded {chunk_idx + 1}/{num_chunks} chunks...")

    # Combine all decoded chunks
    reconstructed_data = b"".join(decoded_chunks)

    # Trim to original file size (remove padding)
    if metadata.get("encrypted"):
        # If encrypted, we need to decrypt first, then it will be the right size
        if decrypt_data_fn:
            if verbose:
                print("Decrypting file data...")
            reconstructed_data = decrypt_data_fn(reconstructed_data)
    else:
        # If not encrypted, trim padding from last chunk
        original_size = metadata["file_size"]
        reconstructed_data = reconstructed_data[:original_size]

    if verbose:
        print("Reconstruction complete!")

    return reconstructed_data


def create_metadata_json(metadata: Dict[str, Any], chunk_cids: List[str]) -> str:
    """
    Create metadata JSON string for an erasure-coded file.

    Args:
        metadata: Metadata dict from encoding
        chunk_cids: List of m CIDs for the uploaded chunks

    Returns:
        JSON string of complete metadata
    """
    full_metadata = {
        **metadata,
        "chunk_cids": chunk_cids,
        "version": "1.0",
    }
    return json.dumps(full_metadata, indent=2)


def parse_metadata_json(metadata_json: str) -> Dict[str, Any]:
    """
    Parse metadata JSON string.

    Args:
        metadata_json: JSON string of metadata

    Returns:
        Metadata dictionary
    """
    return json.loads(metadata_json)
