"""
Unit tests for ArionClient with mocked httpx transport.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from hippius_sdk.arion import ArionClient, CanUploadResponse
from hippius_sdk.errors import HippiusArionError, HippiusAuthenticationError


@pytest.fixture
def arion():
    return ArionClient(
        base_url="https://arion.test",
        api_token="test-token",
        account_address="5TestAddr",
    )


class TestUploadFile:
    @pytest.mark.asyncio
    @patch("hippius_sdk.arion.ArionClient.can_upload")
    async def test_upload_success(self, mock_can_upload, arion, tmp_path):
        """Upload returns dict with file_id and size_formatted."""
        mock_can_upload.return_value = CanUploadResponse(result=True)

        test_file = tmp_path / "hello.txt"
        test_file.write_text("hello world")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "file_id": "abc123",
            "upload_id": "up-001",
            "timestamp": 1700000000,
            "size_bytes": 0,
        }
        mock_response.raise_for_status = MagicMock()
        arion._client.post = AsyncMock(return_value=mock_response)

        result = await arion.upload_file(str(test_file))

        assert result["file_id"] == "abc123"
        assert result["size_formatted"] == "11 bytes"
        assert result["filename"] == "hello.txt"
        assert "upload_id" in result

    @pytest.mark.asyncio
    async def test_upload_file_not_found(self, arion):
        """FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            await arion.upload_file("/nonexistent/path.txt")

    @pytest.mark.asyncio
    @patch("hippius_sdk.arion.ArionClient.can_upload")
    async def test_upload_denied(self, mock_can_upload, arion, tmp_path):
        """HippiusArionError when can_upload returns false."""
        mock_can_upload.return_value = CanUploadResponse(
            result=False, error="quota exceeded"
        )
        test_file = tmp_path / "big.bin"
        test_file.write_bytes(b"\x00" * 100)

        with pytest.raises(HippiusArionError, match="quota exceeded"):
            await arion.upload_file(str(test_file))


class TestDeleteFile:
    @pytest.mark.asyncio
    async def test_delete_success(self, arion):
        """Delete returns dict with status and file_id."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Success": {
                "status": "deleted",
                "file_id": "abc123",
                "user_id": "5TestAddr",
            }
        }
        mock_response.raise_for_status = MagicMock()
        arion._client.delete = AsyncMock(return_value=mock_response)

        result = await arion.delete_file("abc123")
        assert result == {"status": "deleted", "file_id": "abc123"}


class TestCanUpload:
    @pytest.mark.asyncio
    async def test_can_upload_allowed(self, arion):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": True, "error": None}
        mock_response.raise_for_status = MagicMock()
        arion._client.post = AsyncMock(return_value=mock_response)

        result = await arion.can_upload(1024)
        assert result.result is True

    @pytest.mark.asyncio
    async def test_can_upload_denied(self, arion):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": False, "error": "no credits"}
        mock_response.raise_for_status = MagicMock()
        arion._client.post = AsyncMock(return_value=mock_response)

        result = await arion.can_upload(999999999)
        assert result.result is False
        assert result.error == "no credits"


class TestAuthErrors:
    @pytest.mark.asyncio
    async def test_401_raises_auth_error(self, arion):
        """401 response is converted to HippiusAuthenticationError."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        arion._client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "401", request=MagicMock(), response=mock_response
            )
        )

        with pytest.raises(HippiusAuthenticationError):
            await arion.can_upload(1024)
