import json
import os
from typing import Any, Dict

import httpx


class AsyncIPFSClient:
    """
    Asynchronous IPFS client using httpx.
    """

    def __init__(
        self, api_url: str = "http://localhost:5001", gateway: str = "https://ipfs.io"
    ):
        # Handle multiaddr format
        if api_url and api_url.startswith("/"):
            # Extract host and port from multiaddr
            try:
                parts = api_url.split("/")
                # Handle /ip4/127.0.0.1/tcp/5001
                if len(parts) >= 5 and parts[1] in ["ip4", "ip6"]:
                    host = parts[2]
                    port = parts[4]
                    api_url = f"https://{host}:{port}"
                    print(f"Converted multiaddr {api_url} to HTTP URL {api_url}")
                else:
                    print(f"Warning: Unsupported multiaddr format: {api_url}")
                    print("Falling back to default: http://localhost:5001")
                    api_url = "http://localhost:5001"
            except Exception as e:
                print(f"Error parsing multiaddr: {e}")
                print("Falling back to default: http://localhost:5001")
                api_url = "http://localhost:5001"
        self.api_url = api_url
        self.gateway = gateway
        self.client = httpx.AsyncClient(timeout=60.0)

    async def close(self):
        """Close the httpx client."""
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def add_file(self, file_path: str) -> Dict[str, Any]:
        """
        Add a file to IPFS.

        Args:
            file_path: Path to the file to add

        Returns:
            Dict containing the CID and other information
        """
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = await self.client.post(f"{self.api_url}/api/v0/add", files=files)
            response.raise_for_status()
            return response.json()

    async def add_bytes(self, data: bytes, filename: str = "file") -> Dict[str, Any]:
        """
        Add bytes to IPFS.

        Args:
            data: Bytes to add
            filename: Name to give the file (default: "file")

        Returns:
            Dict containing the CID and other information
        """
        files = {"file": (filename, data)}
        response = await self.client.post(f"{self.api_url}/api/v0/add", files=files)
        response.raise_for_status()
        return response.json()

    async def add_str(self, content: str, filename: str = "file") -> Dict[str, Any]:
        """
        Add a string to IPFS.

        Args:
            content: String to add
            filename: Name to give the file (default: "file")

        Returns:
            Dict containing the CID and other information
        """
        return await self.add_bytes(content.encode(), filename)

    async def cat(self, cid: str) -> bytes:
        """
        Retrieve content from IPFS by its CID.

        Args:
            cid: Content Identifier to retrieve

        Returns:
            Content as bytes
        """
        response = await self.client.post(f"{self.api_url}/api/v0/cat?arg={cid}")
        response.raise_for_status()
        return response.content

    async def pin(self, cid: str) -> Dict[str, Any]:
        """
        Pin content by CID.

        Args:
            cid: Content Identifier to pin

        Returns:
            Response from the IPFS node
        """
        response = await self.client.post(f"{self.api_url}/api/v0/pin/add?arg={cid}")
        response.raise_for_status()
        return response.json()

    async def ls(self, cid: str) -> Dict[str, Any]:
        """
        List objects linked to the specified CID.

        Args:
            cid: Content Identifier

        Returns:
            Dict with links information
        """
        response = await self.client.post(f"{self.api_url}/api/v0/ls?arg={cid}")
        response.raise_for_status()
        return response.json()

    async def exists(self, cid: str) -> bool:
        """
        Check if content exists.

        Args:
            cid: Content Identifier to check

        Returns:
            True if content exists, False otherwise
        """
        try:
            await self.client.head(f"{self.gateway}/ipfs/{cid}")
            return True
        except httpx.HTTPError:
            return False

    async def download_file(self, cid: str, output_path: str) -> str:
        """
        Download content from IPFS to a file.

        Args:
            cid: Content identifier
            output_path: Path where to save the file

        Returns:
            Path to the saved file
        """
        content = await self.cat(cid)
        with open(output_path, "wb") as f:
            f.write(content)
        return output_path

    async def add_directory(
        self, dir_path: str, recursive: bool = True
    ) -> Dict[str, Any]:
        """
        Add a directory to IPFS.

        Args:
            dir_path: Path to the directory to add

        Returns:
            Dict containing the CID and other information about the directory

        Raises:
            FileNotFoundError: If the directory doesn't exist
            httpx.HTTPError: If the IPFS API request fails
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory {dir_path} not found")

        # Collect all files in the directory
        files = []
        for root, _, filenames in os.walk(dir_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, dir_path)

                with open(file_path, "rb") as f:
                    file_content = f.read()

                # Add the file to the multipart request
                files.append(
                    ("file", (rel_path, file_content, "application/octet-stream"))
                )

        # Make the request with directory flags
        response = await self.client.post(
            f"{self.api_url}/api/v0/add?recursive=true&wrap-with-directory=true",
            files=files,
            timeout=300.0,  # 5 minute timeout for directory uploads
        )
        response.raise_for_status()

        # The IPFS API returns a JSON object for each file, one per line
        # The last one should be the directory itself
        lines = response.text.strip().split("\n")
        if not lines:
            raise ValueError("Empty response from IPFS API")

        return json.loads(lines[-1])
