"""
Arion API Client for interacting with the Hippius Arion storage service.

This module provides an HTTP-based client for file operations via the
Arion service at https://arion.hippius.com/.

All file operations (upload, download, delete) are routed through HCFS
for client-side encryption. Call enable_encryption() before using file operations.
"""

import logging
import os
import tempfile
from typing import Any, Dict, Optional

from pydantic import BaseModel

from hippius_sdk.config import get_config_value
from hippius_sdk.errors import HippiusArionError
from hippius_sdk.http_utils import create_http_client, retry_on_error
from hippius_sdk.utils import format_size

logger = logging.getLogger(__name__)


# --- Pydantic models ---


class UploadResponse(BaseModel):
    upload_id: str
    timestamp: int
    size_bytes: int = 0
    file_id: str

    @property
    def cid(self) -> str:
        return self.file_id

    @property
    def status(self) -> str:
        return "uploaded"


class DeleteResult(BaseModel):
    status: str
    file_id: str
    user_id: str


class DeleteSuccessResponse(BaseModel):
    Success: DeleteResult


class CanUploadRequest(BaseModel):
    user_id: str
    size_bytes: int


class CanUploadResponse(BaseModel):
    result: bool
    error: str | None = None


# --- ArionClient ---


class ArionClient:
    """
    HTTP API client for Hippius Arion storage service.

    All file operations require HCFS encryption to be enabled via enable_encryption().
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        account_address: str | None = None,
        password: str | None = None,
    ) -> None:
        """
        Initialize the Arion API client.

        Args:
            base_url: Arion base URL (default: https://arion.hippius.com)
            api_token: API token for Bearer authentication
            account_address: SS58 account address for file operations
            password: Encryption password for HCFS operations
        """
        self.base_url = base_url or "https://arion.hippius.com"
        self._api_token = api_token
        self._account_address = account_address
        self._password = password
        self._client = create_http_client(self.base_url)
        self._hcfs_manager = None

    async def __aenter__(self) -> "ArionClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    def enable_encryption(self, password: str, config_dir: Optional[str] = None):
        """
        Enable client-side encryption via HCFS.

        Encryption must be initialized first via HcfsManager.init() or the CLI.

        Args:
            password: Password to unlock the encrypted mnemonic
            config_dir: Path to HCFS drive directory (default: ~/.hippius/drive)
        """
        from hippius_sdk.hcfs import HcfsManager, DEFAULT_DRIVE_DIR

        config_dir = config_dir or DEFAULT_DRIVE_DIR
        hcfs_api_key = get_config_value("arion", "hcfs_api_key", "SERVER")
        self._hcfs_manager = HcfsManager(
            drive_dir=config_dir,
            base_url=self.base_url,
            api_key=hcfs_api_key,
            bearer_token=self._api_token or "",
            account_ss58=self._account_address or "",
        )
        self._password = password

    @property
    def encryption_enabled(self) -> bool:
        """Whether client-side encryption is active."""
        return self._hcfs_manager is not None and self._hcfs_manager.is_initialized()

    def _require_encryption(self):
        """Raise if HCFS encryption is not enabled."""
        if self._hcfs_manager is None:
            raise HippiusArionError(
                "HCFS encryption not enabled. Call enable_encryption() first, "
                "or run: hippius account login"
            )
        if not self._hcfs_manager.is_initialized():
            raise HippiusArionError(
                "HCFS encryption not initialized. Run: hippius account login"
            )

    def _get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers with Bearer token authentication.

        Returns:
            Dict[str, str]: Headers with authentication token
        """
        return {
            "Authorization": f"Bearer {self._api_token}",
        }

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusArionError)
    async def upload_file(
        self,
        file_path: str,
        file_name: str | None = None,
    ) -> Dict[str, Any]:
        """
        Upload a file to Arion storage via HCFS (encrypted).

        Maps to: copy to drive dir → sync

        Args:
            file_path: Path to the file to upload
            file_name: Optional filename override (defaults to basename of file_path)

        Returns:
            dict: Upload result with file_id, size_bytes, size_formatted, etc.

        Raises:
            HippiusArionError: If encryption is not enabled or the upload fails
            FileNotFoundError: If the file doesn't exist
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        self._require_encryption()

        result = await self._hcfs_manager.upload(file_path, self._password)
        return {
            "file_id": result["file_id"],
            "size_bytes": result["size_bytes"],
            "size_formatted": format_size(result["size_bytes"]),
            "filename": file_name or os.path.basename(file_path),
            "encrypted": True,
        }

    async def download_file(
        self,
        file_id: str,
        output_path: str,
        chunk_size: int = 65536,
    ) -> dict:
        """
        Download a file from Arion storage (decrypted via HCFS).

        Maps to: HcfsClient.download()

        Args:
            file_id: File identifier
            output_path: Local path to save the downloaded file
            chunk_size: Unused (kept for API compatibility)

        Returns:
            dict: Download result with output_path and size_bytes
        """
        self._require_encryption()

        await self._hcfs_manager.download(
            self._account_address, file_id, output_path, self._password
        )
        size_bytes = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        return {
            "output_path": output_path,
            "size_bytes": size_bytes,
            "size_formatted": format_size(size_bytes),
            "file_id": file_id,
            "encrypted": True,
        }

    async def download_bytes(
        self,
        file_id: str,
        chunk_size: int = 65536,
    ) -> bytes:
        """
        Download a file from Arion storage to memory (decrypted via HCFS).

        Downloads to a temp file, reads bytes, and cleans up.

        Args:
            file_id: File identifier
            chunk_size: Unused (kept for API compatibility)

        Returns:
            bytes: Decrypted file content
        """
        self._require_encryption()

        tmp_fd, tmp_path = tempfile.mkstemp(prefix="hippius_dl_")
        os.close(tmp_fd)
        try:
            await self._hcfs_manager.download(
                self._account_address, file_id, tmp_path, self._password
            )
            with open(tmp_path, "rb") as f:
                data = f.read()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return data

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusArionError)
    async def delete_file(
        self,
        file_id: str,
    ) -> Dict[str, str]:
        """
        Delete a file from Arion storage via HCFS.

        Removes the file from the drive directory and syncs.

        Args:
            file_id: File identifier

        Returns:
            dict: Deletion result with status and file_id
        """
        self._require_encryption()

        await self._hcfs_manager.delete(self._account_address, file_id, self._password)
        return {
            "status": "deleted",
            "file_id": file_id,
        }

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusArionError)
    async def can_upload(
        self,
        size_bytes: int,
    ) -> CanUploadResponse:
        """
        Check whether the account is allowed to upload a file of the given size.

        Maps to: POST /can_upload

        Args:
            size_bytes: Size of the intended upload in bytes

        Returns:
            CanUploadResponse: Whether the upload is permitted
        """
        headers = self._get_headers()
        payload = CanUploadRequest(user_id=self._account_address, size_bytes=size_bytes)
        response = await self._client.post(
            "/can_upload",
            json=payload.model_dump(),
            headers=headers,
        )
        response.raise_for_status()
        return CanUploadResponse.model_validate(response.json())

    async def list_files(self) -> list:
        """
        List files for the account.

        Not yet available on Arion.

        Raises:
            NotImplementedError: List not yet available on Arion
        """
        raise NotImplementedError("List not yet available on Arion")
