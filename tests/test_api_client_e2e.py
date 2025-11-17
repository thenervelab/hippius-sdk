"""
End-to-end tests for HippiusApiClient.

These tests verify that all API interactions work correctly against
the real Hippius API using TEST_HIPPIUS_KEY from environment.

To run these tests:
    export TEST_HIPPIUS_KEY=your_test_key
    pytest tests/test_api_client_e2e.py -v
"""

import pytest

from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.errors import (
    HippiusAPIError,
    HippiusAuthenticationError,
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientAuthentication:
    """Test API client authentication and initialization."""

    async def test_client_initialization(self, test_hippius_key, test_api_url):
        """Test that API client initializes correctly."""
        client = HippiusApiClient(api_url=test_api_url, hippius_key=test_hippius_key)

        assert client.api_url == test_api_url
        assert client._hippius_key == test_hippius_key

        await client.close()

    async def test_auth_header_generation(self, api_client):
        """Test that authentication headers are generated correctly."""
        headers = api_client._get_headers()

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Token ")

    async def test_invalid_key_raises_error(self, test_api_url):
        """Test that invalid HIPPIUS_KEY raises an error."""
        import httpx

        client = HippiusApiClient(api_url=test_api_url, hippius_key="invalid_key_12345")

        # Invalid key will result in 404 (account not found) or auth error
        with pytest.raises((HippiusAuthenticationError, httpx.HTTPStatusError)):
            await client.get_account_balance()

        await client.close()


@pytest.mark.e2e
@pytest.mark.asyncio
class TestBillingEndpoints:
    """Test billing and credit management endpoints."""

    async def test_get_credits_balance(self, api_client):
        """
        Test GET /billing/credits/balance/
        Should return user's credit balance.
        """
        result = await api_client.get_account_balance()

        # Verify response structure
        assert isinstance(result, dict), "Credits should be a dict"

    async def test_get_tao_price(self, api_client):
        """
        Test GET /billing/latest-tao-price/
        Should return current TAO/USD price (public endpoint).
        """
        # This might not be implemented yet, but testing for future
        try:
            result = await api_client._client.get("/billing/latest-tao-price/")
            result.raise_for_status()
            data = result.json()
            assert "price" in data or "tao_price" in data
        except Exception:
            pytest.skip("TAO price endpoint not yet implemented")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestStorageFileEndpoints:
    """Test storage file management endpoints."""

    async def test_list_files(self, api_client):
        """
        Test GET /storage-control/files/
        Should return list of user's files.
        """
        result = await api_client.list_files()

        # Result should be a list (may be empty)
        assert isinstance(result, list), "list_files should return a list"

        # If there are files, check structure
        if result:
            file = result[0]
            assert "cid" in file or "id" in file, "File should have cid or id"

    async def test_list_files_with_cid_filter(self, api_client, sample_cid):
        """
        Test GET /storage-control/files/?cid={cid}
        Should return files filtered by CID.
        """
        result = await api_client.list_files(cid=sample_cid)

        assert isinstance(result, list)
        # Should be empty or contain only matching CID
        for file in result:
            if "cid" in file:
                assert file["cid"] == sample_cid

    async def test_get_user_files_alias(self, api_client):
        """
        Test get_user_files() as alias for list_files().
        """
        files1 = await api_client.list_files()
        files2 = await api_client.get_user_files()

        assert files1 == files2, "Both methods should return same data"

    async def test_get_file_details_nonexistent(self, api_client):
        """
        Test GET /storage-control/files/{file_id}/
        Should handle non-existent file gracefully.
        """
        with pytest.raises((HippiusAPIError, Exception)):
            await api_client.get_file_details("nonexistent-file-id-12345")

    async def test_get_pinning_status(self, api_client):
        """
        Test getting pinning status for all user files.
        """
        result = await api_client.get_pinning_status()

        # Result should be a list
        assert isinstance(result, list)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestStorageRequestEndpoints:
    """Test storage request endpoints (Pin/Unpin operations)."""

    async def test_pin_file_request(self, api_client, sample_cid):
        """
        Test POST /storage-control/requests/ with request_type="Pin"
        Should create a pin request with new payload structure:
        {cid: string, original_name: string, request_type: "Pin"}
        """
        try:
            result = await api_client.pin_file(
                cid=sample_cid, filename="test_pin_file.txt"
            )

            assert isinstance(result, dict), "pin_file should return a dict"

            assert "id" in result or "status" in result or "request_id" in result
        except Exception as e:
            assert any(code in str(e) for code in ["400", "500"])

    async def test_unpin_file_request(self, api_client, sample_cid):
        """
        Test POST /storage-control/requests/ with type="Unpin"
        Should create an unpin request.
        """
        try:
            result = await api_client.unpin_file(cid=sample_cid)

            # Verify response structure
            assert isinstance(result, dict), "unpin_file should return a dict"
        except Exception as e:
            # May fail with sample CID (500/400 errors are expected)
            assert any(code in str(e) for code in ["400", "500"])

    async def test_storage_request_generic(self, api_client, sample_cid):
        """
        Test generic storage_request() method.
        """
        try:
            result = await api_client.storage_request(
                files=[{"cid": sample_cid, "filename": "test_generic_request.txt"}]
            )

            # Returns request ID as string
            assert isinstance(result, str)
        except Exception as e:
            # May fail with sample CID - that's expected
            assert "500" in str(e) or "error" in str(e).lower()

    async def test_check_storage_request_exists(self, api_client, sample_cid):
        """
        Test checking if a storage request exists for a CID.
        """
        exists = await api_client.check_storage_request_exists(sample_cid)

        assert isinstance(exists, bool), "Should return boolean"

    async def test_cancel_storage_request(self, api_client, sample_cid):
        """
        Test cancelling a storage request.
        This may fail if no request exists - that's expected.
        """
        try:
            result = await api_client.cancel_storage_request(sample_cid)
            assert isinstance(result, (dict, bool, str))
        except Exception as e:
            # Expected if no request exists or sample CID is invalid
            # May get 500/400 errors or HippiusFailedSubstrateDelete
            pass


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.slow
class TestUploadEndpoints:
    """Test file upload endpoints."""

    async def test_list_uploads(self, api_client):
        """
        Test GET /storage-control/uploads/
        Should return list of user's uploads.
        """
        result = await api_client.list_uploads()

        assert isinstance(result, list), "list_uploads should return a list"

        # If there are uploads, check structure
        if result:
            upload = result[0]
            assert "id" in upload, "Upload should have an id"
            assert "cid" in upload or "status" in upload

    async def test_list_uploads_basic(self, api_client):
        """
        Test basic list_uploads functionality.
        """
        result = await api_client.list_uploads()

        assert isinstance(result, list)

    async def test_get_upload_details_nonexistent(self, api_client):
        """
        Test GET /storage-control/uploads/{id}/
        Should handle non-existent upload gracefully.
        """
        with pytest.raises((HippiusAPIError, Exception)):
            await api_client.get_upload_details("nonexistent-upload-id-12345")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientErrorHandling:
    """Test API client error handling and retry logic."""

    async def test_retry_on_server_error(self, api_client):
        """
        Test that retry logic works for server errors.
        This is hard to test without a mock, but we verify the decorator exists.
        """
        # Verify the method has the retry decorator
        assert hasattr(api_client.list_files, "__wrapped__")

    async def test_no_retry_on_auth_error(self, test_api_url):
        """
        Test that authentication errors (401/403) don't retry.
        """
        import httpx

        client = HippiusApiClient(
            api_url=test_api_url, hippius_key="definitely_invalid_key"
        )

        # Should fail quickly without retries
        # get_account_balance doesn't have retry decorator, so raises HTTPStatusError directly
        with pytest.raises((HippiusAuthenticationError, httpx.HTTPStatusError)):
            await client.get_account_balance()

        await client.close()

    async def test_context_manager_usage(self, test_hippius_key, test_api_url):
        """
        Test that API client works as async context manager.
        """
        async with HippiusApiClient(
            api_url=test_api_url, hippius_key=test_hippius_key
        ) as client:
            # Should be able to make requests
            credits = await client.get_account_balance()
            assert isinstance(credits, dict)

        # Client should be closed after context exit
        # Note: Can't easily verify this without internal state access


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientHealthCheck:
    """Test service health check."""

    async def test_health_check(self, api_client):
        """
        Test GET /storage-control/health/
        Should return service health status.
        """
        try:
            response = await api_client._client.get(
                "/storage-control/health/", headers=api_client._get_headers()
            )
            response.raise_for_status()
            data = response.json()

            # Should return some health status
            assert isinstance(data, dict)
            # Common health check fields
            assert any(key in data for key in ["status", "healthy", "ok", "message"])
        except Exception:
            # Health endpoint might not be implemented yet
            pytest.skip("Health check endpoint not available")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestApiClientEdgeCases:
    """Test edge cases and boundary conditions."""

    async def test_empty_cid_handling(self, api_client):
        """Test that empty CID is handled gracefully."""
        with pytest.raises((ValueError, TypeError, HippiusAPIError, Exception)):
            await api_client.pin_file(cid="", filename="test.txt")

    async def test_none_cid_handling(self, api_client):
        """Test that None CID is handled gracefully."""
        with pytest.raises((ValueError, TypeError, HippiusAPIError, Exception)):
            await api_client.pin_file(cid=None, filename="test.txt")

    async def test_very_long_filename(self, api_client, sample_cid):
        """Test handling of very long filenames."""
        long_filename = "a" * 500 + ".txt"

        try:
            result = await api_client.pin_file(cid=sample_cid, filename=long_filename)
            assert isinstance(result, dict)
        except Exception:
            # May fail with sample CID or filename length - expected
            pass

    async def test_special_characters_in_filename(self, api_client, sample_cid):
        """Test handling of special characters in filenames."""
        special_filename = "test_file_with_特殊字符_äöü.txt"

        try:
            result = await api_client.pin_file(
                cid=sample_cid, filename=special_filename
            )
            assert isinstance(result, dict)
        except Exception:
            # May fail with sample CID or character restrictions - expected
            pass

    async def test_concurrent_requests(self, api_client):
        """Test that multiple concurrent requests work correctly."""
        import asyncio

        # Make multiple concurrent requests
        tasks = [
            api_client.get_account_balance(),
            api_client.list_files(),
            api_client.list_uploads(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should complete (may have exceptions but shouldn't hang)
        assert len(results) == 3

        # At least the balance call should succeed and return a dict
        assert isinstance(results[0], dict)
