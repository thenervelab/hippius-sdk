import json
import os
from typing import Any, Dict

import httpx


class AsyncIPFSClient:
    """
    Asynchronous IPFS client using httpx.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:5001",
        gateway: str = "https://get.hippius.network",
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
        self.client = httpx.AsyncClient(timeout=300, follow_redirects=True)

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
            file_content = f.read()
            filename = os.path.basename(file_path)
            # Specify file with name and content type to ensure consistent handling
            files = {"file": (filename, file_content, "application/octet-stream")}
            # Explicitly set wrap-with-directory=false to prevent wrapping in directory
            response = await self.client.post(
                f"{self.api_url}/api/v0/add?wrap-with-directory=false", files=files
            )
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
        # Specify file with name and content type to ensure consistent handling
        files = {"file": (filename, data, "application/octet-stream")}
        # Explicitly set wrap-with-directory=false to prevent wrapping in directory
        response = await self.client.post(
            f"{self.api_url}/api/v0/add?wrap-with-directory=false", files=files
        )
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

    async def unpin(self, cid: str) -> Dict[str, Any]:
        """
        Unpin content by CID.

        Args:
            cid: Content Identifier to unpin

        Returns:
            Response from the IPFS node
        """

        response = await self.client.post(f"{self.api_url}/api/v0/pin/rm?arg={cid}")

        response.raise_for_status()
        result = response.json()
        return result

    async def ls(self, cid: str) -> Dict[str, Any]:
        """
        List objects linked to the specified CID.
        Detects if the CID is a directory and returns links to its contents.

        Args:
            cid: Content Identifier

        Returns:
            Dict with links information and is_directory flag
        """
        # Try using the direct IPFS API first (most reliable)
        response = await self.client.post(f"{self.api_url}/api/v0/ls?arg={cid}")
        response.raise_for_status()
        result = response.json()

        # Add a flag to indicate if this is a directory.
        # A directory has Links and typically more than one or has Type=1
        is_directory = False
        if "Objects" in result and len(result["Objects"]) > 0:
            obj = result["Objects"][0]
            if "Links" in obj and len(obj["Links"]) > 0:
                # It has links, likely a directory
                is_directory = True
                # Check if any links have Type=1 (directory)
                for link in obj["Links"]:
                    if link.get("Type") == 1:
                        is_directory = True
                        break

        # Add the flag to the result
        result["is_directory"] = is_directory
        return result

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

    async def download_file(
        self, cid: str, output_path: str, skip_directory_check: bool = False
    ) -> str:
        """
        Download content from IPFS to a file.
        If the CID is a directory, it will create a directory and download all files.

        Args:
            cid: Content identifier
            output_path: Path where to save the file/directory
            skip_directory_check: If True, skip directory check (useful for erasure code chunks)

        Returns:
            Path to the saved file/directory
        """
        # Skip directory check if requested (useful for erasure code chunks)
        if not skip_directory_check:
            # First, check if this is a directory using the improved ls function
            try:
                ls_result = await self.ls(cid)
                if ls_result.get("is_directory", False):
                    # It's a directory, use the get command to download it properly
                    return await self.download_directory(cid, output_path)
            except Exception:
                # If ls check fails, continue with regular file download
                pass

        # If we reached here, treat it as a regular file
        try:
            # Regular file download
            content = await self.cat(cid)
            # Ensure the parent directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(content)
            return output_path
        except Exception as e:
            # Only try directory fallback if not skipping directory check
            if not skip_directory_check:
                try:
                    return await self.download_directory(cid, output_path)
                except Exception:
                    pass
            # Raise the original error
            raise e

    async def download_directory(self, cid: str, output_path: str) -> str:
        """
        Download a directory from IPFS by recursively fetching its contents.

        Args:
            cid: Content identifier of the directory
            output_path: Path where to save the directory

        Returns:
            Path to the saved directory
        """
        # First, get the directory listing to find all contents
        try:
            import uuid

            # Handle potential file/directory collision
            if os.path.exists(output_path) and not os.path.isdir(output_path):
                # Generate unique path by adding a UUID suffix
                output_path = f"{output_path}_{str(uuid.uuid4())[:8]}"

            ls_result = await self.ls(cid)

            # Create target directory
            os.makedirs(output_path, exist_ok=True)

            # Extract all links from the directory listing
            links = []
            if "Objects" in ls_result and ls_result["Objects"]:
                for obj in ls_result["Objects"]:
                    if "Links" in obj:
                        links.extend(obj["Links"])

            # Download each item (file or directory)
            for link in links:
                link_name = link.get("Name")
                link_hash = link.get("Hash")
                link_type = link.get("Type")

                if not (link_name and link_hash):
                    continue  # Skip if missing essential data

                # Build the target path
                target_path = os.path.join(output_path, link_name)

                if link_type == 1 or str(link_type) == "1" or link_type == "dir":
                    # It's a directory - recursively download
                    await self.download_directory(link_hash, target_path)
                else:
                    # It's a file - download it
                    try:
                        content = await self.cat(link_hash)
                        os.makedirs(
                            os.path.dirname(os.path.abspath(target_path)), exist_ok=True
                        )
                        with open(target_path, "wb") as f:
                            f.write(content)
                    except Exception as file_error:
                        print(f"Failed to download file {link_name}: {str(file_error)}")

            return output_path

        except Exception as e:
            raise RuntimeError(
                f"Failed to download directory using 'get' command: {str(e)}"
            )

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
