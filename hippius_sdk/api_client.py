"""
Hippius API Client for interacting with the Hippius API.

This module provides an HTTP-based client that replaces direct blockchain
interactions with API calls authenticated via HIPPIUS_KEY.

API Documentation: https://api.hippius.com/?format=openapi
"""

import asyncio
import functools
import logging
from typing import Any, Dict, List, Optional

import httpx

from hippius_sdk.config import get_hippius_key
from hippius_sdk.errors import (
    HippiusAPIError,
    HippiusAuthenticationError,
    HippiusFailedSubstrateDelete,
)

logger = logging.getLogger(__name__)


def retry_on_error(retries: int = 3, backoff: float = 5.0):
    """
    Decorator to retry HTTP requests on 4xx/5xx errors.

    Args:
        retries: Number of retry attempts (default: 3)
        backoff: Seconds to wait between retries (default: 5.0)
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(retries + 1):
                try:
                    return await func(*args, **kwargs)
                except (httpx.HTTPStatusError, HippiusAPIError) as e:
                    last_exception = e

                    # Don't retry on authentication errors (401, 403)
                    if hasattr(e, "response") and e.response.status_code in [401, 403]:
                        raise HippiusAuthenticationError(f"Authentication failed: {e}")

                    # Don't retry on 404 Not Found - resource doesn't exist
                    if hasattr(e, "response") and e.response.status_code == 404:
                        raise

                    # Don't retry if this was the last attempt
                    if attempt == retries:
                        break

                    # Log retry attempt
                    print(f"Request failed (attempt {attempt + 1}/{retries + 1}): {e}")
                    print(f"Retrying in {backoff} seconds...")
                    await asyncio.sleep(backoff)
                except Exception:
                    # Don't retry on unexpected errors
                    raise

            # If we get here, all retries failed
            raise last_exception

        return wrapper

    return decorator


class HippiusApiClient:
    """
    HTTP API client for Hippius platform.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        hippius_key: Optional[str] = None,
        hippius_key_password: Optional[str] = None,
        account_name: Optional[str] = None,
    ):
        """
        Initialize the Hippius API client.

        Args:
            api_url: Base URL for the Hippius API (default: https://api.hippius.com/api)
            hippius_key: HIPPIUS_KEY for authentication
            hippius_key_password: Password to decrypt the hippius_key if encrypted
            account_name: Name of the account to use (uses active account if None)
        """
        self.api_url = api_url or "https://api.hippius.com/api"
        self._hippius_key = hippius_key
        self._hippius_key_password = hippius_key_password
        self._account_name = account_name

        # Initialize httpx client with timeout
        self._client = httpx.AsyncClient(
            base_url=self.api_url,
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=True,
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    def _get_hippius_key(self, hippius_key: Optional[str] = None) -> str:
        """
        Get the HIPPIUS_KEY for authentication.

        Args:
            hippius_key: Optional hippius_key to use (uses config if None)

        Returns:
            str: The HIPPIUS_KEY

        Raises:
            ValueError: If no hippius_key is available
        """
        # Use provided key first
        if hippius_key:
            return hippius_key

        # Use instance key if set
        if self._hippius_key:
            return self._hippius_key

        # Try to get from config
        config_key = get_hippius_key(self._hippius_key_password, self._account_name)
        if config_key:
            return config_key

        raise ValueError(
            "No HIPPIUS_KEY available. Please provide hippius_key or configure it using 'hippius account login'"
        )

    def _get_headers(self, hippius_key: Optional[str] = None) -> Dict[str, str]:
        """
        Get HTTP headers with authentication.

        Args:
            hippius_key: Optional hippius_key to use

        Returns:
            Dict[str, str]: Headers with authentication token
        """
        key = self._get_hippius_key(hippius_key)
        return {
            "Authorization": f"Token {key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @retry_on_error(retries=3, backoff=5.0)
    async def pin_file(
        self,
        cid: str,
        filename: Optional[str] = None,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pin a file to IPFS and submit to blockchain.

        Maps to: POST /storage-control/requests/ with request_type="Pin"

        Args:
            cid: Content Identifier (CID) of the file to pin
            filename: Optional original filename
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            Dict[str, Any]: Response with request_id and status

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        payload = {
            "cid": cid,
            "request_type": "Pin",
        }

        if filename:
            payload["original_name"] = filename

        response = await self._client.post(
            "/storage-control/requests/",
            json=payload,
            headers=headers,
        )

        response.raise_for_status()
        return response.json()

    @retry_on_error(retries=3, backoff=5.0)
    async def unpin_file(
        self,
        cid: str,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Unpin a file from IPFS and cancel storage on blockchain.

        Maps to: POST /storage-control/requests/ with request_type="Unpin"

        Args:
            cid: Content Identifier (CID) of the file to unpin
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            Dict[str, Any]: Response with request_id and status

        Raises:
            HippiusFailedSubstrateDelete: If the unpin request fails
        """
        headers = self._get_headers(hippius_key)

        payload = {
            "cid": cid,
            "request_type": "Unpin",
        }

        try:
            response = await self._client.post(
                "/storage-control/requests/",
                json=payload,
                headers=headers,
            )

            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise HippiusFailedSubstrateDelete(f"Failed to unpin file: {str(e)}")

    @retry_on_error(retries=3, backoff=5.0)
    async def list_files(
        self,
        hippius_key: Optional[str] = None,
        cid: Optional[str] = None,
        include_pending: bool = False,
        search: Optional[str] = None,
        ordering: Optional[str] = None,
        page: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        List files stored by the authenticated user.

        Maps to: GET /storage-control/files/

        Args:
            hippius_key: Optional HIPPIUS_KEY (uses config if None)
            cid: Optional CID filter
            include_pending: Include files with pending status
            search: A search term to filter files
            ordering: Which field to use when ordering the results
            page: A page number within the paginated result set

        Returns:
            List[Dict[str, Any]]: List of file objects with pinning and miner status

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        params = {}
        if cid:
            params["cid"] = cid
        if include_pending:
            params["include_pending"] = "true"
        if search:
            params["search"] = search
        if ordering:
            params["ordering"] = ordering
        if page:
            params["page"] = str(page)

        response = await self._client.get(
            "/storage-control/files/",
            headers=headers,
            params=params,
        )

        response.raise_for_status()
        data = response.json()

        # API returns paginated results
        if isinstance(data, dict) and "results" in data:
            return data["results"]

        return data if isinstance(data, list) else []

    @retry_on_error(retries=3, backoff=5.0)
    async def get_file_details(
        self,
        file_id: str,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific file.

        Maps to: GET /storage-control/files/{file_id}/

        Args:
            file_id: The file ID (not CID)
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            Dict[str, Any]: Detailed file information including all pinned miners

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        response = await self._client.get(
            f"/storage-control/files/{file_id}/",
            headers=headers,
        )

        response.raise_for_status()
        return response.json()

    @retry_on_error(retries=3, backoff=5.0)
    async def sync_file_pins(
        self,
        file_id: Optional[str] = None,
        cid: Optional[str] = None,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Synchronize active miner pins for a file.

        Maps to: POST /storage-control/files/{file_id}/pins/sync/
                 or POST /storage-control/files/cid/{cid}/pins/sync/

        Args:
            file_id: The file ID (either file_id or cid required)
            cid: The content ID (either file_id or cid required)
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            Dict[str, Any]: Sync result with updated pin status

        Raises:
            ValueError: If neither file_id nor cid is provided
            HippiusAPIError: If the API request fails
        """
        if not file_id and not cid:
            raise ValueError("Either file_id or cid must be provided")

        headers = self._get_headers(hippius_key)

        if file_id:
            url = f"/storage-control/files/{file_id}/pins/sync/"
        else:
            url = f"/storage-control/files/cid/{cid}/pins/sync/"

        response = await self._client.post(
            url,
            headers=headers,
        )

        response.raise_for_status()
        return response.json()

    @retry_on_error(retries=3, backoff=5.0)
    async def upload_file(
        self,
        file_path: str,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        [DEPRECATED] Upload a file via multipart form.

        This method is deprecated. The SDK now uploads files to the local IPFS node
        and pins them via /storage-control/requests/ instead of using /storage-control/upload/.

        Use HippiusClient.upload_file() instead, which handles:
        1. Upload to local IPFS node -> get CID
        2. Pin CID to Hippius API via /storage-control/requests/

        Args:
            file_path: Path to the file to upload
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Raises:
            NotImplementedError: This method is deprecated
        """
        raise NotImplementedError(
            "HippiusApiClient.upload_file() is deprecated. "
            "The SDK no longer uses the /storage-control/upload/ endpoint. "
            "Use HippiusClient.upload_file() instead, which uploads to local IPFS "
            "and pins via /storage-control/requests/."
        )

    @retry_on_error(retries=3, backoff=5.0)
    async def list_uploads(
        self,
        hippius_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List authenticated user's uploads.

        Maps to: GET /storage-control/uploads/

        Args:
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            List[Dict[str, Any]]: List of upload objects

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        response = await self._client.get(
            "/storage-control/uploads/",
            headers=headers,
        )

        response.raise_for_status()
        data = response.json()

        # API returns paginated results
        if isinstance(data, dict) and "results" in data:
            return data["results"]

        return data if isinstance(data, list) else []

    @retry_on_error(retries=3, backoff=5.0)
    async def get_upload_details(
        self,
        upload_id: str,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get details of a specific upload.

        Maps to: GET /storage-control/uploads/{id}/

        Args:
            upload_id: The upload ID
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            Dict[str, Any]: Upload metadata

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        response = await self._client.get(
            f"/storage-control/uploads/{upload_id}/",
            headers=headers,
        )

        response.raise_for_status()
        return response.json()

    @retry_on_error(retries=3, backoff=5.0)
    async def storage_request(
        self,
        files: List[Dict[str, str]],
        miner_ids: Optional[List[str]] = None,
        hippius_key: Optional[str] = None,
    ) -> str:
        """
        Submit a storage request for files.

        Maps to: POST /storage-control/requests/ with type="Pin"

        Args:
            files: List of file objects with 'cid' and 'filename'
            miner_ids: Optional list of miner IDs (may not be supported by API)
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            str: Request ID

        Raises:
            HippiusAPIError: If the API request fails
        """
        headers = self._get_headers(hippius_key)

        # For multiple files, make multiple requests
        # API doesn't seem to support batch operations based on the spec
        request_ids = []

        for file_info in files:
            payload = {
                "type": "Pin",
                "cid": file_info.get("cid") or file_info.get("fileHash"),
                "filename": file_info.get("filename")
                or file_info.get("fileName", "unknown"),
            }

            response = await self._client.post(
                "/storage-control/requests/",
                json=payload,
                headers=headers,
            )

            response.raise_for_status()
            result = response.json()
            request_ids.append(result.get("request_id", result.get("id", "")))

        # Return first request ID for compatibility
        return request_ids[0] if request_ids else ""

    async def check_storage_request_exists(
        self,
        cid: str,
        hippius_key: Optional[str] = None,
    ) -> bool:
        """
        Check if a storage request exists for the given CID.

        Args:
            cid: Content Identifier (CID) to check
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            bool: True if the CID exists in storage, False otherwise
        """
        try:
            files = await self.list_files(hippius_key=hippius_key, cid=cid)
            return len(files) > 0
        except Exception:
            # If we can't check, assume it doesn't exist
            return False

    async def cancel_storage_request(
        self,
        cid: str,
        hippius_key: Optional[str] = None,
    ) -> str:
        """
        Cancel a storage request by unpinning the file.

        Args:
            cid: Content Identifier (CID) of the file to cancel
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            str: Request ID or status message

        Raises:
            HippiusFailedSubstrateDelete: If the cancel request fails
        """
        result = await self.unpin_file(cid, hippius_key)
        return result.get("request_id", result.get("id", ""))

    @retry_on_error(retries=3, backoff=5.0)
    async def get_account_balance(
        self,
        hippius_key: Optional[str] = None,
    ) -> Dict[str, float]:
        """Get the credit balance for the authenticated account.

        Maps to: GET /billing/credits/balance/

        Args:
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            float: Credit balance (1 credit = 1 USD)

        Raises:
            HippiusAPIError: If the API request fails
            HippiusAuthenticationError: If authentication fails (401/403)
        """
        headers = self._get_headers(hippius_key)

        response = await self._client.get(
            "/billing/credits/balance/",
            headers=headers,
        )

        response.raise_for_status()
        return response.json()

    async def get_user_files(
        self,
        hippius_key: Optional[str] = None,
        truncate_miners: bool = True,
        max_miners: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Get detailed information about all files stored by the user.

        Args:
            hippius_key: Optional HIPPIUS_KEY (uses config if None)
            truncate_miners: Whether to truncate long miner lists (for compatibility)
            max_miners: Maximum number of miners to include (for compatibility)

        Returns:
            List[Dict[str, Any]]: List of file objects
        """
        files = await self.list_files(hippius_key=hippius_key)

        # Transform to match substrate client format
        processed_files = []
        for file in files:
            processed_file = {
                "cid": file.get("cid"),
                "file_hash": file.get("cid"),  # Compatibility
                "file_name": file.get("filename", file.get("name", "unknown")),
                "miner_ids": file.get("miner_ids", []),
                "miner_count": len(file.get("miner_ids", [])),
                "file_size": file.get("size", file.get("file_size", 0)),
                "selected_validator": file.get("selected_validator"),
                "status": file.get("status"),
            }

            # Truncate miners if requested
            if truncate_miners and max_miners > 0:
                processed_file["miner_ids"] = processed_file["miner_ids"][:max_miners]

            # Add formatted file size
            if processed_file["file_size"]:
                from hippius_sdk.utils import format_size

                processed_file["size_formatted"] = format_size(
                    processed_file["file_size"]
                )
            else:
                processed_file["size_formatted"] = "Unknown"

            processed_files.append(processed_file)

        return processed_files

    async def get_pinning_status(
        self,
        hippius_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get the status of file pinning requests for the account.

        Args:
            hippius_key: Optional HIPPIUS_KEY (uses config if None)

        Returns:
            List[Dict[str, Any]]: List of storage requests with status information
        """
        # This is similar to get_user_files but may include pending requests
        return await self.get_user_files(
            hippius_key=hippius_key, truncate_miners=False, max_miners=0
        )
