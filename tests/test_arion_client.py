"""
Unit tests for ArionClient with mocked httpx transport.
"""

import json
import os
import tempfile
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
    async def test_upload_success(self, arion, tmp_path):
        """Upload returns dict with file_id and size_formatted via HCFS."""
        test_file = tmp_path / "hello.txt"
        test_file.write_text("hello world")

        mock_manager = MagicMock()
        mock_manager.is_initialized.return_value = True
        mock_manager.upload = AsyncMock(
            return_value={
                "file_id": "abc123",
                "size_bytes": 11,
            }
        )
        arion._hcfs_manager = mock_manager
        arion._hcfs_password = "testpass"

        result = await arion.upload_file(str(test_file))

        assert result["file_id"] == "abc123"
        assert result["size_formatted"] == "11 bytes"
        assert result["filename"] == "hello.txt"
        assert result["encrypted"] is True

    @pytest.mark.asyncio
    async def test_upload_file_not_found(self, arion):
        """FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            await arion.upload_file("/nonexistent/path.txt")

    @pytest.mark.asyncio
    async def test_upload_requires_encryption(self, arion, tmp_path):
        """HippiusArionError when encryption is not enabled."""
        test_file = tmp_path / "big.bin"
        test_file.write_bytes(b"\x00" * 100)

        with pytest.raises(HippiusArionError, match="HCFS encryption not enabled"):
            await arion.upload_file(str(test_file))


class TestDeleteFile:
    @pytest.mark.asyncio
    async def test_delete_success(self, arion):
        """Delete returns dict with status and file_id via HCFS."""
        mock_manager = MagicMock()
        mock_manager.is_initialized.return_value = True
        mock_manager.delete = AsyncMock()
        arion._hcfs_manager = mock_manager
        arion._hcfs_password = "testpass"

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


class TestDownloadBytesCleanup:
    @pytest.mark.asyncio
    async def test_temp_file_cleaned_on_success(self, arion):
        """Temp file is removed after successful download_bytes."""
        mock_manager = MagicMock()
        mock_manager.is_initialized.return_value = True

        created_paths = []

        async def mock_download(user_id, file_id, output_path, password):
            created_paths.append(output_path)
            with open(output_path, "wb") as f:
                f.write(b"content")

        mock_manager.download = AsyncMock(side_effect=mock_download)
        arion._hcfs_manager = mock_manager
        arion._hcfs_password = "testpass"

        data = await arion.download_bytes("file123")

        assert data == b"content"
        assert len(created_paths) == 1
        assert not os.path.exists(created_paths[0])

    @pytest.mark.asyncio
    async def test_temp_file_cleaned_on_failure(self, arion):
        """Temp file is removed even when download raises."""
        mock_manager = MagicMock()
        mock_manager.is_initialized.return_value = True
        mock_manager.download = AsyncMock(side_effect=RuntimeError("network error"))
        arion._hcfs_manager = mock_manager
        arion._hcfs_password = "testpass"

        with pytest.raises(RuntimeError, match="network error"):
            await arion.download_bytes("file123")

        # Verify no leftover temp files with our prefix
        tmp_dir = tempfile.gettempdir()
        leftover = [f for f in os.listdir(tmp_dir) if f.startswith("hippius_dl_")]
        assert len(leftover) == 0
