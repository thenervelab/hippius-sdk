"""
Arion API Client for interacting with the Hippius Arion storage service.

This module provides an HTTP-based client for file operations via the
Arion service at https://arion.hippius.com/.
"""

import logging
import os
from typing import Any, Dict

from pydantic import BaseModel

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
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        account_address: str | None = None,
    ) -> None:
        """
        Initialize the Arion API client.

        Args:
            base_url: Arion base URL (default: https://arion.hippius.com)
            api_token: API token for Bearer authentication
            account_address: SS58 account address for file operations
        """
        self.base_url = base_url or "https://arion.hippius.com"
        self._api_token = api_token
        self._account_address = account_address
        self._client = create_http_client(self.base_url)

    async def __aenter__(self) -> "ArionClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

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
        Upload a file to Arion storage.

        Checks can_upload first, then uploads via multipart form.

        Maps to: POST /upload

        Args:
            file_path: Path to the file to upload
            file_name: Optional filename override (defaults to basename of file_path)

        Returns:
            dict: Upload result with file_id, size_bytes, size_formatted, etc.

        Raises:
            HippiusArionError: If the upload fails
            FileNotFoundError: If the file doesn't exist
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_name = file_name or os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Check if upload is permitted
        can_upload_result = await self.can_upload(file_size)
        if not can_upload_result.result:
            error_msg = can_upload_result.error or "Upload not permitted"
            raise HippiusArionError(f"Cannot upload: {error_msg}")

        # Read file data
        with open(file_path, "rb") as f:
            file_data = f.read()

        files = {
            "file": (
                file_name,
                file_data,
                "application/octet-stream",
                {"Content-Length": str(len(file_data))},
            ),
        }
        data = {"account_ss58": self._account_address}

        headers = self._get_headers()
        response = await self._client.post(
            "/upload",
            files=files,
            data=data,
            headers=headers,
        )
        response.raise_for_status()
        response_json = response.json()

        upload_response = UploadResponse.model_validate(response_json)
        size_bytes = len(file_data)
        return {
            "file_id": upload_response.file_id,
            "size_bytes": size_bytes,
            "size_formatted": format_size(size_bytes),
            "filename": file_name,
            "upload_id": upload_response.upload_id,
            "timestamp": upload_response.timestamp,
        }

    async def download_file(
        self,
        file_id: str,
        output_path: str,
        chunk_size: int = 65536,
    ) -> dict:
        """
        Download a file from Arion storage to a local path.

        Maps to: GET /download/{account}/{file_id}

        Args:
            file_id: File identifier
            output_path: Local path to save the downloaded file
            chunk_size: Size of chunks for streaming download (default 64KB)

        Returns:
            dict: Download result with output_path and size_bytes
        """
        headers = self._get_headers()
        download_path = f"/download/{self._account_address}/{file_id}"

        total_bytes = 0
        async with self._client.stream(
            "GET",
            download_path,
            headers=headers,
        ) as response:
            response.raise_for_status()
            with open(output_path, "wb") as f:
                async for chunk in response.aiter_bytes(chunk_size):
                    f.write(chunk)
                    total_bytes += len(chunk)

        return {
            "output_path": output_path,
            "size_bytes": total_bytes,
            "size_formatted": format_size(total_bytes),
            "file_id": file_id,
        }

    async def download_bytes(
        self,
        file_id: str,
        chunk_size: int = 65536,
    ) -> bytes:
        """
        Download a file from Arion storage to memory.

        Maps to: GET /download/{account}/{file_id}

        Args:
            file_id: File identifier
            chunk_size: Size of chunks for streaming download (default 64KB)

        Returns:
            bytes: File content
        """
        headers = self._get_headers()
        download_path = f"/download/{self._account_address}/{file_id}"

        chunks = []
        async with self._client.stream(
            "GET",
            download_path,
            headers=headers,
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes(chunk_size):
                chunks.append(chunk)

        return b"".join(chunks)

    @retry_on_error(retries=3, backoff=5.0, base_error_class=HippiusArionError)
    async def delete_file(
        self,
        file_id: str,
    ) -> Dict[str, str]:
        """
        Delete a file from Arion storage.

        Maps to: DELETE /delete/{account}/{file_id}

        Args:
            file_id: File identifier

        Returns:
            dict: Deletion result with status and file_id
        """
        headers = self._get_headers()
        response = await self._client.delete(
            f"/delete/{self._account_address}/{file_id}",
            headers=headers,
        )
        response.raise_for_status()
        response_json = response.json()

        parsed = DeleteSuccessResponse.model_validate(response_json)
        return {
            "status": parsed.Success.status,
            "file_id": parsed.Success.file_id,
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
