"""
Unit tests for HippiusApiClient with mocked HTTP responses.

These tests verify API client logic without making actual network calls,
using mocked httpx responses.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from httpx import Response

from hippius_sdk.api_client import HippiusApiClient, retry_on_error
from hippius_sdk.errors import HippiusAuthenticationError


@pytest.mark.asyncio
class TestApiClientUnit:
    """Unit tests for API client methods."""

    async def test_get_auth_headers(self):
        """Test authentication header generation."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key_12345"
        )

        headers = client._get_headers()

        assert "Authorization" in headers
        assert headers["Authorization"] == "Token test_key_12345"

        await client.close()

    async def test_get_auth_headers_from_config(self):
        """Test authentication header from config."""
        with patch("hippius_sdk.api_client.get_hippius_key") as mock_get_key:
            mock_get_key.return_value = "key_from_config"

            client = HippiusApiClient(api_url="https://test.api.com")
            headers = client._get_headers()

            assert headers["Authorization"] == "Token key_from_config"

            await client.close()

    async def test_get_credits_mocked(self):
        """Test get_credits with mocked response."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        # Mock the httpx client
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"balance": 150.75}
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            credits = await client.get_account_balance()

            assert credits["balance"] == 150.75
            mock_get.assert_called_once()

        await client.close()

    async def test_list_files_mocked(self):
        """Test list_files with mocked response."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"id": "file1", "cid": "QmTest1", "name": "test1.txt"},
                {"id": "file2", "cid": "QmTest2", "name": "test2.txt"},
            ]
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            files = await client.list_files()

            assert isinstance(files, list)
            assert len(files) == 2
            assert files[0]["cid"] == "QmTest1"

        await client.close()

    async def test_pin_file_mocked(self):
        """Test pin_file with mocked response."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "request123",
            "type": "Pin",
            "cid": "QmTest",
            "status": "pending",
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            result = await client.pin_file("QmTest", "test.txt")

            assert result["id"] == "request123"
            assert result["type"] == "Pin"
            mock_post.assert_called_once()

        await client.close()

    async def test_unpin_file_mocked(self):
        """Test unpin_file with mocked response."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "request456",
            "request_type": "Unpin",
            "cid": "QmTest",
            "status": "pending",
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            result = await client.unpin_file("QmTest")

            assert result["request_type"] == "Unpin"
            mock_post.assert_called_once()

            call_args = mock_post.call_args
            assert "json" in call_args.kwargs
            payload = call_args.kwargs["json"]
            assert payload["cid"] == "QmTest"
            assert payload["request_type"] == "Unpin"

        await client.close()


@pytest.mark.asyncio
class TestRetryDecorator:
    """Test the retry_on_error decorator."""

    async def test_retry_on_server_error(self):
        """Test that decorator retries on 5xx errors."""
        call_count = 0

        @retry_on_error(retries=2, backoff=0.1)
        async def failing_function():
            nonlocal call_count
            call_count += 1

            if call_count < 3:
                # First two calls fail with 500
                from httpx import HTTPStatusError, Request, Response

                response = Response(500, request=Request("GET", "http://test.com"))
                raise HTTPStatusError(
                    "Server error", request=response.request, response=response
                )

            return "success"

        result = await failing_function()

        assert result == "success"
        assert call_count == 3  # Failed twice, succeeded on third

    async def test_no_retry_on_auth_error(self):
        """Test that decorator doesn't retry on 401 errors."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.1)
        async def auth_failing_function():
            nonlocal call_count
            call_count += 1

            from httpx import HTTPStatusError, Request, Response

            response = Response(401, request=Request("GET", "http://test.com"))
            raise HTTPStatusError(
                "Unauthorized", request=response.request, response=response
            )

        with pytest.raises(HippiusAuthenticationError):
            await auth_failing_function()

        # Should only be called once (no retries)
        assert call_count == 1

    async def test_retry_exhausted(self):
        """Test behavior when all retries are exhausted."""
        call_count = 0

        @retry_on_error(retries=2, backoff=0.1)
        async def always_failing_function():
            nonlocal call_count
            call_count += 1

            from httpx import HTTPStatusError, Request, Response

            response = Response(500, request=Request("GET", "http://test.com"))
            raise HTTPStatusError(
                "Server error", request=response.request, response=response
            )

        from httpx import HTTPStatusError

        with pytest.raises(HTTPStatusError):
            await always_failing_function()

        # Should be called 3 times (initial + 2 retries)
        assert call_count == 3


@pytest.mark.asyncio
class TestApiClientErrorHandling:
    """Test error handling in API client."""

    async def test_auth_error_on_401(self):
        """Test that 401 raises HippiusAuthenticationError."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="invalid_key"
        )

        from httpx import HTTPStatusError, Request, Response

        response = Response(401, request=Request("GET", "http://test.com"))

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = HTTPStatusError(
                "Unauthorized", request=response.request, response=response
            )

            with pytest.raises(HippiusAuthenticationError):
                await client.get_account_balance()

        await client.close()

    async def test_api_error_on_404(self):
        """Test that 404 raises appropriate error."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        from httpx import HTTPStatusError, Request, Response

        response = Response(404, request=Request("GET", "http://test.com"))

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = HTTPStatusError(
                "Not found", request=response.request, response=response
            )

            with pytest.raises(Exception):  # Will be caught by retry, then raised
                await client.get_file_details("nonexistent")

        await client.close()


@pytest.mark.asyncio
class TestApiClientContextManager:
    """Test context manager functionality."""

    async def test_context_manager_closes_client(self):
        """Test that context manager properly closes the client."""
        async with HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        ) as client:
            assert client._client is not None

        # After exit, client should be closed (but we can't easily verify)
        # The important part is that no exception is raised

    async def test_explicit_close(self):
        """Test explicit close method."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        await client.close()

        # Closing again should not raise an error
        await client.close()


@pytest.mark.asyncio
class TestApiClientParameterHandling:
    """Test parameter handling in API client methods."""

    async def test_list_files_with_cid_parameter(self):
        """Test that list_files passes CID parameter correctly."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            await client.list_files(cid="QmTest123")

            # Verify the CID was passed in params
            call_args = mock_get.call_args
            assert "params" in call_args.kwargs
            assert call_args.kwargs["params"]["cid"] == "QmTest123"

        await client.close()

    async def test_list_files_with_include_pending_parameter(self):
        """Test that list_files passes include_pending parameter correctly."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"cid": "QmTest1", "status": "Pending"},
                {"cid": "QmTest2", "status": "Active"},
            ]
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            files = await client.list_files(include_pending=True)

            call_args = mock_get.call_args
            assert "params" in call_args.kwargs
            assert call_args.kwargs["params"]["include_pending"] == "true"
            assert len(files) == 2

        await client.close()

    async def test_pin_file_with_hippius_key_override(self):
        """Test that pin_file can override HIPPIUS_KEY."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="default_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "request123"}
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            await client.pin_file("QmTest", "test.txt", hippius_key="override_key")

            # Verify override key was used
            call_args = mock_post.call_args
            assert call_args.kwargs["headers"]["Authorization"] == "Token override_key"

        await client.close()


@pytest.mark.asyncio
class TestApiClientResponseParsing:
    """Test response parsing in API client."""

    async def test_get_credits_handles_different_response_formats(self):
        """Test that get_credits handles various response formats."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        # Test actual API format: {"balance": "1.000000000000000000", "last_updated": "..."}
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "balance": "100.500000000000000000",
            "last_updated": "2025-11-17T11:55:07.705142Z",
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await client.get_account_balance()

            assert isinstance(result, dict)
            assert "balance" in result
            assert result["balance"] == "100.500000000000000000"
            assert "last_updated" in result

        await client.close()

    async def test_list_files_handles_pagination_response(self):
        """Test that list_files handles paginated responses."""
        client = HippiusApiClient(
            api_url="https://test.api.com", hippius_key="test_key"
        )

        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"id": "1"}, {"id": "2"}],
            "count": 2,
            "next": None,
            "previous": None,
        }
        mock_response.raise_for_status = Mock()

        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            files = await client.list_files()

            # Should extract results array
            assert isinstance(files, list)
            assert len(files) == 2

        await client.close()
