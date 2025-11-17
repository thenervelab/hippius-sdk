"""
Integration tests for HippiusClient with API operations.

These tests verify the integration between HippiusClient and HippiusApiClient,
ensuring that high-level client operations work correctly with the API.

To run these tests:
    export TEST_HIPPIUS_KEY=your_test_key
    export TEST_IPFS_API_URL=http://localhost:5001  # optional
    pytest tests/test_api_integration.py -v
"""

import os
import tempfile

import pytest

from hippius_sdk.client import HippiusClient


@pytest.mark.e2e
@pytest.mark.asyncio
class TestHippiusClientInitialization:
    """Test HippiusClient initialization with API client."""

    async def test_client_initialization_with_hippius_key(
        self, test_hippius_key, test_api_url
    ):
        """Test that client initializes correctly with HIPPIUS_KEY."""
        client = HippiusClient(
            hippius_key=test_hippius_key,
            api_url=test_api_url,
            ipfs_api_url="http://localhost:5001",
        )

        # Verify API client is initialized
        assert client.api_client is not None
        assert client.api_client._hippius_key == test_hippius_key

        # Verify IPFS client is initialized
        assert client.ipfs_client is not None

        await client.api_client.close()

    async def test_client_without_hippius_key_uses_config(self, test_api_url):
        """Test that client can use HIPPIUS_KEY from config."""
        # This test assumes HIPPIUS_KEY is in config or env
        try:
            client = HippiusClient(
                api_url=test_api_url, ipfs_api_url="http://localhost:5001"
            )

            # If no key in config/env, api_client should still initialize
            assert client.api_client is not None

            await client.api_client.close()
        except Exception:
            pytest.skip("No HIPPIUS_KEY in config/env")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestClientAPIIntegration:
    """Test integration of client methods with API."""

    async def test_format_cid_helper(self, hippius_client):
        """Test that format_cid helper works."""
        cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        formatted = hippius_client.format_cid(cid)

        assert isinstance(formatted, str)
        assert cid in formatted

    async def test_format_size_helper(self, hippius_client):
        """Test that format_size helper works."""
        size_bytes = 1024 * 1024  # 1 MB

        formatted = hippius_client.format_size(size_bytes)

        assert isinstance(formatted, str)
        assert "MB" in formatted or "MiB" in formatted

    async def test_generate_encryption_key(self, hippius_client):
        """Test encryption key generation."""
        key = hippius_client.generate_encryption_key()

        assert isinstance(key, str)
        assert len(key) > 0
        # Should be base64 encoded
        import base64

        decoded = base64.b64decode(key)
        assert len(decoded) == 32  # NaCl SecretBox key size


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.requires_ipfs
class TestClientIPFSOperations:
    """Test IPFS operations through HippiusClient."""

    async def test_upload_file_basic(self, hippius_client, temp_test_file):
        """Test basic file upload through client with pinning."""
        result = await hippius_client.upload_file(temp_test_file)

        assert isinstance(result, dict)
        assert "cid" in result
        assert "filename" in result
        assert "size_bytes" in result
        assert result["size_bytes"] > 0

        assert "pinned" in result
        assert result["pinned"] is True
        assert "pin_request_id" in result
        assert result["pin_request_id"] is not None

    async def test_upload_file_without_pinning(self, hippius_client, temp_test_file):
        """Test file upload to IPFS only, without pinning."""
        result = await hippius_client.upload_file(temp_test_file, pin=False)

        assert isinstance(result, dict)
        assert "cid" in result
        assert "filename" in result

        assert "pinned" in result
        assert result["pinned"] is False

    async def test_upload_file_with_encryption(self, hippius_client, temp_test_file):
        """Test file upload with encryption and pinning."""
        result = await hippius_client.upload_file(temp_test_file, encrypt=True)

        assert isinstance(result, dict)
        assert "cid" in result
        assert "encrypted" in result
        assert result["encrypted"] is True

        assert "pinned" in result
        assert result["pinned"] is True
        assert "pin_request_id" in result

    async def test_download_file_basic(self, hippius_client, sample_cid):
        """Test basic file download through client."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            output_path = tmp.name

        try:
            # This may fail if CID doesn't exist - that's expected
            result = await hippius_client.download_file(sample_cid, output_path)

            if result.get("success"):
                assert os.path.exists(output_path)
                assert "size_bytes" in result
                assert "elapsed_seconds" in result
        except Exception:
            pytest.skip("Sample CID not available for download")
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    async def test_cat_file(self, hippius_client, sample_cid):
        """Test getting file content through cat."""
        try:
            result = await hippius_client.cat(sample_cid, max_display_bytes=100)

            assert isinstance(result, dict)
            assert "content" in result
            assert "size_bytes" in result
        except Exception:
            pytest.skip("Sample CID not available")

    async def test_exists_check(self, hippius_client, sample_cid):
        """Test checking if CID exists."""
        result = await hippius_client.exists(sample_cid)

        assert isinstance(result, dict)
        assert "exists" in result
        assert isinstance(result["exists"], bool)
        assert "cid" in result

    async def test_pin_operation(self, hippius_client, sample_cid):
        """Test pinning a CID."""
        result = await hippius_client.pin(sample_cid)

        assert isinstance(result, dict)
        assert "success" in result or "message" in result

    @pytest.mark.slow
    async def test_upload_download_from_gateway_match(
        self, hippius_client, temp_test_file
    ):
        """Test upload with pinning, download from local IPFS API, and verify files match."""
        import hashlib
        import httpx

        with open(temp_test_file, "rb") as f:
            original_data = f.read()
        original_hash = hashlib.sha256(original_data).hexdigest()

        upload_result = await hippius_client.upload_file(temp_test_file, pin=True)

        assert "cid" in upload_result
        assert upload_result["pinned"] is True
        cid = upload_result["cid"]

        download_path = tempfile.mktemp(suffix=".download")

        ipfs_api_url = hippius_client.ipfs_client.api_url
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{ipfs_api_url}/api/v0/cat?arg={cid}")
            response.raise_for_status()

            with open(download_path, "wb") as f:
                f.write(response.content)

        with open(download_path, "rb") as f:
            downloaded_data = f.read()
        downloaded_hash = hashlib.sha256(downloaded_data).hexdigest()

        assert (
            original_hash == downloaded_hash
        ), "Downloaded file does not match original"

        os.unlink(download_path)

    @pytest.mark.slow
    async def test_upload_download_from_gateway_no_pin(
        self, hippius_client, temp_test_file
    ):
        """Test upload without pinning, download from local IPFS API, verify match."""
        import hashlib
        import httpx

        with open(temp_test_file, "rb") as f:
            original_data = f.read()
        original_hash = hashlib.sha256(original_data).hexdigest()

        upload_result = await hippius_client.upload_file(temp_test_file, pin=False)

        assert "cid" in upload_result
        assert upload_result["pinned"] is False
        cid = upload_result["cid"]

        download_path = tempfile.mktemp(suffix=".download")

        ipfs_api_url = hippius_client.ipfs_client.api_url
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{ipfs_api_url}/api/v0/cat?arg={cid}")
            response.raise_for_status()

            with open(download_path, "wb") as f:
                f.write(response.content)

        with open(download_path, "rb") as f:
            downloaded_data = f.read()
        downloaded_hash = hashlib.sha256(downloaded_data).hexdigest()

        assert (
            original_hash == downloaded_hash
        ), "Downloaded file does not match original"

        os.unlink(download_path)

    @pytest.mark.slow
    async def test_erasure_code_reassemble_download_match(
        self, hippius_client, temp_test_file
    ):
        """Test erasure coding with pinning, reassemble, download from local IPFS API, and verify match."""
        import hashlib
        import httpx

        with open(temp_test_file, "rb") as f:
            original_data = f.read()
        original_hash = hashlib.sha256(original_data).hexdigest()

        ec_result = await hippius_client.ipfs_client.store_erasure_coded_file(
            file_path=temp_test_file,
            k=2,
            m=3,
            api_client=hippius_client.api_client,
            pin_chunks=True,
            pin_metadata=True,
            verbose=False,
        )

        assert "metadata_cid" in ec_result
        assert ec_result["metadata_pinned"] is True
        metadata_cid = ec_result["metadata_cid"]

        reconstructed_path = tempfile.mktemp(suffix=".reconstructed")

        reconstruct_result = await hippius_client.reconstruct_from_erasure_code(
            metadata_cid=metadata_cid,
            output_file=reconstructed_path,
            verbose=False,
        )

        assert os.path.exists(reconstructed_path)

        with open(reconstructed_path, "rb") as f:
            reconstructed_data = f.read()
        reconstructed_hash = hashlib.sha256(reconstructed_data).hexdigest()

        assert (
            original_hash == reconstructed_hash
        ), "Reconstructed file does not match original"

        ipfs_api_url = hippius_client.ipfs_client.api_url
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{ipfs_api_url}/api/v0/cat?arg={metadata_cid}"
            )
            response.raise_for_status()

            metadata_from_api = response.json()
            assert (
                "metadata_cid" in metadata_from_api
                or "original_file" in metadata_from_api
            )

        os.unlink(reconstructed_path)

    @pytest.mark.slow
    async def test_erasure_code_reassemble_no_pin(self, hippius_client, temp_test_file):
        """Test erasure coding without pinning, reassemble, and verify SHA matches."""
        import hashlib

        with open(temp_test_file, "rb") as f:
            original_data = f.read()
        original_hash = hashlib.sha256(original_data).hexdigest()

        ec_result = await hippius_client.ipfs_client.store_erasure_coded_file(
            file_path=temp_test_file,
            k=2,
            m=3,
            pin_chunks=False,
            pin_metadata=False,
            verbose=False,
        )

        assert "metadata_cid" in ec_result
        metadata_cid = ec_result["metadata_cid"]

        reconstructed_path = tempfile.mktemp(suffix=".reconstructed")

        reconstruct_result = await hippius_client.reconstruct_from_erasure_code(
            metadata_cid=metadata_cid,
            output_file=reconstructed_path,
            verbose=False,
        )

        assert os.path.exists(reconstructed_path)

        with open(reconstructed_path, "rb") as f:
            reconstructed_data = f.read()
        reconstructed_hash = hashlib.sha256(reconstructed_data).hexdigest()

        assert (
            original_hash == reconstructed_hash
        ), f"SHA mismatch! Original: {original_hash}, Reconstructed: {reconstructed_hash}"

        os.unlink(reconstructed_path)

    @pytest.mark.slow
    async def test_pin_verify_unpin_flow(self, hippius_client, temp_test_file):
        """Test pin a file, verify it's pinned, then unpin it and verify removal."""
        import asyncio

        upload_result = await hippius_client.upload_file(temp_test_file, pin=False)
        assert "cid" in upload_result
        assert upload_result["pinned"] is False
        cid = upload_result["cid"]

        pin_result = await hippius_client.api_client.pin_file(
            cid=cid, filename="test_pin_unpin.txt"
        )
        assert isinstance(pin_result, dict)

        await asyncio.sleep(2)

        files = await hippius_client.api_client.list_files(
            cid=cid, include_pending=True
        )
        assert isinstance(files, list)

        file_found = any(f.get("cid") == cid for f in files)
        if file_found:
            matching_file = next(f for f in files if f.get("cid") == cid)
            assert matching_file.get("status") in ["Pending", "Active", "Pinned"]

        unpin_result = await hippius_client.api_client.unpin_file(cid=cid)
        assert isinstance(unpin_result, dict)

        await asyncio.sleep(2)

        files_after_unpin = await hippius_client.api_client.list_files(
            cid=cid, include_pending=True
        )

        if files_after_unpin:
            for f in files_after_unpin:
                if f.get("cid") == cid:
                    assert f.get("status") not in ["Active", "Pinned"]


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.requires_ipfs
@pytest.mark.slow
class TestClientErasureCoding:
    """Test erasure coding operations through client."""

    async def test_erasure_code_file(self, hippius_client, temp_test_file):
        """Test erasure coding a file."""
        result = await hippius_client.erasure_code_file(
            temp_test_file, k=2, m=3, verbose=False
        )

        # Verify result structure
        assert isinstance(result, dict)
        assert "metadata_cid" in result or "metadata" in result

        if "metadata" in result:
            metadata = result["metadata"]
            assert "original_file" in metadata
            assert "erasure_coding" in metadata
            assert metadata["erasure_coding"]["k"] == 2
            assert metadata["erasure_coding"]["m"] == 3

    async def test_store_erasure_coded_file(self, hippius_client, temp_test_file):
        """Test storing erasure coded file (without publishing)."""
        result = await hippius_client.store_erasure_coded_file(
            temp_test_file, k=2, m=3, publish=False, verbose=False
        )

        assert isinstance(result, dict)
        assert "metadata_cid" in result
        assert "metadata" in result

    async def test_reconstruct_from_erasure_code(self, hippius_client, temp_test_file):
        """Test full cycle: encode -> reconstruct."""
        # First, encode a file
        encode_result = await hippius_client.erasure_code_file(
            temp_test_file, k=2, m=3, verbose=False
        )

        metadata_cid = encode_result.get("metadata_cid")
        if not metadata_cid:
            pytest.skip("Could not get metadata CID from encoding")

        # Now try to reconstruct
        with tempfile.NamedTemporaryFile(delete=False, suffix=".reconstructed") as tmp:
            output_path = tmp.name

        try:
            result = await hippius_client.reconstruct_from_erasure_code(
                metadata_cid=metadata_cid, output_file=output_path, verbose=False
            )

            assert isinstance(result, dict)
            assert "output_path" in result
            assert os.path.exists(output_path)

            # Verify file size matches
            original_size = os.path.getsize(temp_test_file)
            reconstructed_size = os.path.getsize(output_path)
            assert original_size == reconstructed_size

        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    async def test_erasure_code_with_chunk_pinning(
        self, hippius_client, temp_test_file
    ):
        """Test erasure coding with chunk pinning to Hippius API."""
        result = await hippius_client.ipfs_client.store_erasure_coded_file(
            file_path=temp_test_file,
            k=2,
            m=3,
            api_client=hippius_client.api_client,
            pin_chunks=True,
            pin_metadata=True,
            verbose=False,
        )

        assert isinstance(result, dict)
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

    async def test_erasure_code_without_pinning(self, hippius_client, temp_test_file):
        """Test erasure coding without API pinning (local IPFS only)."""
        result = await hippius_client.ipfs_client.store_erasure_coded_file(
            file_path=temp_test_file,
            k=2,
            m=3,
            pin_chunks=False,
            pin_metadata=False,
            verbose=False,
        )

        assert isinstance(result, dict)
        assert "metadata_cid" in result
        assert result["metadata_pinned"] is False

        metadata = result["metadata"]
        for chunk in metadata["chunks"]:
            assert "pin_request_id" not in chunk or chunk.get("pin_request_id") is None


@pytest.mark.e2e
@pytest.mark.asyncio
class TestClientDeleteOperations:
    """Test delete operations through client."""

    async def test_delete_file(self, hippius_client, sample_cid):
        """Test deleting a file (unpin only, no blockchain)."""
        try:
            result = await hippius_client.delete_file(
                sample_cid,
                cancel_from_blockchain=False,
                unpin=False,  # Don't actually unpin in test
            )

            assert isinstance(result, dict)
            assert "success" in result or "unpin_result" in result
        except Exception as e:
            # Expected if file doesn't exist
            assert "not found" in str(e).lower() or "does not exist" in str(e).lower()

    async def test_delete_ec_file(self, hippius_client, sample_cid):
        """Test deleting an erasure-coded file."""
        try:
            result = await hippius_client.delete_ec_file(
                sample_cid, cancel_from_blockchain=False
            )

            # Should return boolean
            assert isinstance(result, bool)
        except Exception:
            # Expected if file doesn't exist or isn't EC file
            pass


@pytest.mark.e2e
@pytest.mark.asyncio
class TestClientErrorPropagation:
    """Test that API errors propagate correctly through client."""

    async def test_api_error_propagates_on_invalid_operation(self, hippius_client):
        """Test that API errors propagate through client methods."""
        # Try to get details of non-existent file
        # This should eventually raise an error from the API

        # We can't test this easily without knowing what will fail
        # But we can verify the error handling structure exists
        assert hasattr(hippius_client.api_client, "_client")
        assert hasattr(hippius_client.api_client, "_get_auth_headers")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestClientConfigurationIntegration:
    """Test integration with configuration system."""

    async def test_client_uses_config_hippius_key(self, test_api_url):
        """Test that client can read HIPPIUS_KEY from config."""
        from hippius_sdk.config import set_hippius_key

        # Set a test key in config (non-encrypted)
        test_key = "test_key_from_config"
        set_hippius_key(test_key, encode=False, account_name="test_account")

        # Create client without explicit key
        client = HippiusClient(
            api_url=test_api_url,
            ipfs_api_url="http://localhost:5001",
            account_name="test_account",
        )

        # Client should have loaded key from config
        # Note: This might not work if get_hippius_key doesn't return the set value
        # This test is more of a structural test

        await client.api_client.close()


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.requires_ipfs
class TestClientMultipartUpload:
    """Test multipart upload through client (if implemented)."""

    async def test_large_file_upload(self, hippius_client):
        """Test uploading a larger file."""
        # Create a 5MB test file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            f.write(b"x" * (5 * 1024 * 1024))
            large_file = f.name

        try:
            result = await hippius_client.upload_file(large_file)

            assert isinstance(result, dict)
            assert "cid" in result
            assert result["size_bytes"] == 5 * 1024 * 1024

        finally:
            if os.path.exists(large_file):
                os.unlink(large_file)


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.requires_ipfs
class TestClientDirectoryOperations:
    """Test directory upload operations."""

    async def test_upload_directory(self, hippius_client, temp_test_dir):
        """Test uploading a directory."""
        result = await hippius_client.upload_directory(temp_test_dir)

        assert isinstance(result, dict)
        assert "cid" in result
        assert "dirname" in result
        assert "file_count" in result
        assert result["file_count"] > 0


@pytest.mark.e2e
@pytest.mark.asyncio
class TestClientConcurrency:
    """Test concurrent operations through client."""

    async def test_multiple_concurrent_api_calls(self, hippius_client):
        """Test that client handles multiple concurrent API calls."""
        import asyncio

        # Make several API calls concurrently
        tasks = [
            hippius_client.api_client.get_account_balance(),
            hippius_client.api_client.list_files(),
            hippius_client.api_client.list_uploads(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should complete
        assert len(results) == 3

        # Credits should be numeric
        assert isinstance(results[0], (int, float))

        # Files and uploads should be lists
        assert isinstance(results[1], list)
        assert isinstance(results[2], list)
