"""
Unit tests for CLI erasure-code and reconstruct handlers.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.cli_handlers import handle_erasure_code, handle_reconstruct


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.store_erasure_coded_file = AsyncMock()
    client.reconstruct_from_erasure_code = AsyncMock()
    client.ipfs_client = MagicMock()
    client.ipfs_client.publish_global = AsyncMock()
    client.ipfs_client.api_url = "http://localhost:5001"
    return client


# ---- handle_erasure_code ----


@pytest.mark.asyncio
async def test_erasure_code_file_not_found(mock_client):
    """Returns 1 for nonexistent file."""
    result = await handle_erasure_code(
        mock_client, "/nonexistent/file.txt", k=3, m=5, chunk_size=1
    )
    assert result == 1


@pytest.mark.asyncio
async def test_erasure_code_success(mock_client, tmp_path):
    """Returns 0 with valid result."""
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(b"x" * 10240)

    mock_client.store_erasure_coded_file.return_value = {
        "metadata_cid": "QmMetaCid",
        "total_files_stored": 5,
        "metadata": {
            "original_file": {"name": "data.bin", "size": 10240},
            "erasure_coding": {"file_id": "abc123", "k": 3, "m": 5},
            "chunks": [{"cid": f"QmChunk{i}"} for i in range(5)],
        },
    }
    mock_client.ipfs_client.publish_global.return_value = {"published": True}

    result = await handle_erasure_code(
        mock_client,
        str(test_file),
        k=3,
        m=5,
        chunk_size=1,
        publish=True,
    )
    assert result == 0
    mock_client.store_erasure_coded_file.assert_awaited_once()


# ---- handle_reconstruct ----


@pytest.mark.asyncio
async def test_reconstruct_success(mock_client):
    """Returns 0 with valid result."""
    mock_client.reconstruct_from_erasure_code.return_value = {
        "output_path": "/tmp/reconstructed.bin",
        "size_bytes": 10240,
        "decrypted": False,
    }

    result = await handle_reconstruct(
        mock_client, "QmMetaCid", "/tmp/reconstructed.bin"
    )
    assert result == 0
    mock_client.reconstruct_from_erasure_code.assert_awaited_once_with(
        metadata_cid="QmMetaCid",
        output_file="/tmp/reconstructed.bin",
        verbose=False,
    )


@pytest.mark.asyncio
async def test_reconstruct_failure(mock_client):
    """Returns 1 on exception."""
    mock_client.reconstruct_from_erasure_code.side_effect = Exception(
        "No metadata found for CID"
    )

    result = await handle_reconstruct(mock_client, "QmBadMeta", "/tmp/output.bin")
    assert result == 1
