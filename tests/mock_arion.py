"""
Deterministic mock for ArionClient.

Returns realistic dicts (not MagicMocks) matching ArionClient method signatures.
Records all method calls for test assertions.
"""

import os
from typing import Any, Dict, List, Optional, Tuple


class MockArionClient:
    """
    A deterministic mock that mimics ArionClient behavior for tests.

    Attributes:
        calls: List of (method_name, args, kwargs) tuples for assertion
        upload_response: Default upload response (override per-test)
        download_response: Default download response (override per-test)
        delete_response: Default delete response (override per-test)
        can_upload_response: Default can_upload response (override per-test)
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        account_address: str | None = None,
    ) -> None:
        self.base_url = base_url or "https://arion.hippius.com"
        self._api_token = api_token
        self._account_address = account_address
        self.calls: List[Tuple[str, tuple, dict]] = []

        # Default responses — override these in tests
        self.upload_response: Dict[str, Any] = {
            "file_id": "mock-file-id-001",
            "size_bytes": 1024,
            "size_formatted": "1.00 KB",
            "filename": "test.txt",
            "upload_id": "mock-upload-001",
            "timestamp": 1700000000,
        }

        self.download_response: Dict[str, Any] = {
            "output_path": "/tmp/mock_download.bin",
            "size_bytes": 2048,
            "size_formatted": "2.00 KB",
            "file_id": "mock-file-id-001",
        }

        # Bytes returned by download_bytes
        self.download_bytes_content: bytes = b"mock file content"

        self.delete_response: Dict[str, str] = {
            "status": "deleted",
            "file_id": "mock-file-id-001",
        }

        self.can_upload_allowed: bool = True
        self.can_upload_error: str | None = None

    def _record(self, method: str, args: tuple, kwargs: dict) -> None:
        self.calls.append((method, args, kwargs))

    async def upload_file(
        self,
        file_path: str,
        file_name: str | None = None,
    ) -> Dict[str, Any]:
        self._record("upload_file", (file_path,), {"file_name": file_name})
        resp = dict(self.upload_response)
        if file_name:
            resp["filename"] = file_name
        elif file_path:
            resp["filename"] = os.path.basename(file_path)
        return resp

    async def download_file(
        self,
        file_id: str,
        output_path: str,
        chunk_size: int = 65536,
    ) -> Dict[str, Any]:
        self._record(
            "download_file", (file_id, output_path), {"chunk_size": chunk_size}
        )
        # Write real bytes to disk so callers can verify content
        with open(output_path, "wb") as f:
            f.write(self.download_bytes_content)
        resp = dict(self.download_response)
        resp["output_path"] = output_path
        resp["file_id"] = file_id
        resp["size_bytes"] = len(self.download_bytes_content)
        return resp

    async def download_bytes(
        self,
        file_id: str,
        chunk_size: int = 65536,
    ) -> bytes:
        self._record("download_bytes", (file_id,), {"chunk_size": chunk_size})
        return self.download_bytes_content

    async def delete_file(
        self,
        file_id: str,
    ) -> Dict[str, str]:
        self._record("delete_file", (file_id,), {})
        resp = dict(self.delete_response)
        resp["file_id"] = file_id
        return resp

    async def can_upload(
        self,
        size_bytes: int,
    ) -> Dict[str, Any]:
        self._record("can_upload", (size_bytes,), {})
        return {
            "result": self.can_upload_allowed,
            "error": self.can_upload_error,
        }

    async def list_files(self) -> list:
        self._record("list_files", (), {})
        raise NotImplementedError("List not yet available on Arion")

    async def close(self) -> None:
        self._record("close", (), {})

    async def __aenter__(self) -> "MockArionClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def assert_called(self, method: str, times: int = 1) -> None:
        """Assert a method was called exactly `times` times."""
        count = sum(1 for m, _, _ in self.calls if m == method)
        assert count == times, f"Expected {method} called {times} time(s), got {count}"

    def assert_not_called(self, method: str) -> None:
        """Assert a method was never called."""
        self.assert_called(method, 0)

    def get_call_args(self, method: str, index: int = 0) -> Tuple[tuple, dict]:
        """Get the (args, kwargs) for the Nth call to `method`."""
        matching = [(a, k) for m, a, k in self.calls if m == method]
        return matching[index]
