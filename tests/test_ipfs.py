"""
Tests for the AsyncIPFSClient and IPFSClient classes using pytest style.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest
import pytest_asyncio

from hippius_sdk.ipfs import IPFSClient
from hippius_sdk.ipfs_core import AsyncIPFSClient


class MockResponse:
    """A custom mock response class that properly handles async methods."""

    def __init__(self, status_code=200, json_data=None, content=None, text=None):
        self.status_code = status_code
        self._json_data = json_data or {"Hash": "QmTest123", "Size": "123"}
        self.content = content or b"Test content"
        self.text = text or '{"Hash":"QmTest123","Size":"123"}'

    def json(self):
        """
        In AsyncIPFSClient, response.json() is called without await,
        which means ipfs_core.py is treating json() as a synchronous method.
        """
        return self._json_data

    def raise_for_status(self):
        """
        In AsyncIPFSClient, response.raise_for_status() is called without await,
        which means ipfs_core.py is treating raise_for_status() as a synchronous method.
        """
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("Error", request=None, response=self)
        return None


@pytest_asyncio.fixture
async def mock_httpx_client():
    """Create a mock httpx client with properly configured async returns."""
    client = AsyncMock()

    # Configure standard response
    response = MockResponse()

    # Set up the client methods to return the response
    client.post.return_value = response
    client.get.return_value = response
    client.head.return_value = response

    # Make aclose properly awaitable
    client.aclose = AsyncMock()

    return client


@pytest_asyncio.fixture
async def mock_dir_response():
    """Create a mock response for directory tests."""
    return MockResponse(
        text='{"Hash":"QmFile123","Name":"test_file.txt"}\n{"Hash":"QmDir123","Name":"temp_dir"}',
        json_data={"Hash": "QmDir123", "Name": "temp_dir"},
    )


@pytest_asyncio.fixture
async def async_ipfs_client(monkeypatch, mock_httpx_client):
    """Create an AsyncIPFSClient with mocked httpx client."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: mock_httpx_client)
    client = AsyncIPFSClient(api_url="http://localhost:5001")
    return client


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(b"Test content for IPFS")
    temp_file.close()
    yield temp_file.name
    os.unlink(temp_file.name)


@pytest.fixture
def temp_dir():
    """Create a temporary directory with a file for testing."""
    temp_dir = tempfile.mkdtemp()
    with open(os.path.join(temp_dir, "test_file.txt"), "w") as f:
        f.write("Test content in directory")
    yield temp_dir
    os.unlink(os.path.join(temp_dir, "test_file.txt"))
    os.rmdir(temp_dir)


@pytest.mark.asyncio
async def test_add_file(async_ipfs_client, temp_file, mock_httpx_client):
    """Test adding a file to IPFS."""
    result = await async_ipfs_client.add_file(temp_file)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    args, kwargs = mock_httpx_client.post.call_args
    assert args[0] == "http://localhost:5001/api/v0/add"
    assert "files" in kwargs

    # Check the result
    assert result == {"Hash": "QmTest123", "Size": "123"}


@pytest.mark.asyncio
async def test_add_bytes(async_ipfs_client, mock_httpx_client):
    """Test adding bytes to IPFS."""
    data = b"Test bytes"
    filename = "test_bytes.txt"

    result = await async_ipfs_client.add_bytes(data, filename)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    args, kwargs = mock_httpx_client.post.call_args
    assert args[0] == "http://localhost:5001/api/v0/add"
    assert "files" in kwargs
    assert kwargs["files"]["file"][0] == filename

    # Check the result
    assert result == {"Hash": "QmTest123", "Size": "123"}


@pytest.mark.asyncio
async def test_add_str(async_ipfs_client, mock_httpx_client):
    """Test adding a string to IPFS."""
    content = "Test string"
    filename = "test_string.txt"

    result = await async_ipfs_client.add_str(content, filename)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    args, kwargs = mock_httpx_client.post.call_args
    assert args[0] == "http://localhost:5001/api/v0/add"
    assert "files" in kwargs
    assert kwargs["files"]["file"][0] == filename

    # Check the result
    assert result == {"Hash": "QmTest123", "Size": "123"}


@pytest.mark.asyncio
async def test_cat(async_ipfs_client, mock_httpx_client):
    """Test retrieving content from IPFS."""
    cid = "QmTest123"

    result = await async_ipfs_client.cat(cid)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    assert (
        mock_httpx_client.post.call_args[0][0]
        == f"http://localhost:5001/api/v0/cat?arg={cid}"
    )

    # Check the result
    assert result == b"Test content"


@pytest.mark.asyncio
async def test_pin(async_ipfs_client, mock_httpx_client):
    """Test pinning content in IPFS."""
    cid = "QmTest123"

    result = await async_ipfs_client.pin(cid)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    assert (
        mock_httpx_client.post.call_args[0][0]
        == f"http://localhost:5001/api/v0/pin/add?arg={cid}"
    )

    # Check the result
    assert result == {"Hash": "QmTest123", "Size": "123"}


@pytest.mark.asyncio
async def test_ls(async_ipfs_client, mock_httpx_client):
    """Test listing objects linked to the specified CID."""
    cid = "QmTest123"

    result = await async_ipfs_client.ls(cid)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    assert (
        mock_httpx_client.post.call_args[0][0]
        == f"http://localhost:5001/api/v0/ls?arg={cid}"
    )

    # Check the result
    assert result == {"Hash": "QmTest123", "Size": "123"}


@pytest.mark.asyncio
async def test_exists_true(async_ipfs_client, mock_httpx_client):
    """Test checking if content exists (true case)."""
    cid = "QmTest123"

    result = await async_ipfs_client.exists(cid)

    # Verify the correct endpoint was called
    mock_httpx_client.head.assert_called_once()
    assert mock_httpx_client.head.call_args[0][0] == f"https://ipfs.io/ipfs/{cid}"

    # Check the result
    assert result is True


@pytest.mark.asyncio
async def test_exists_false(async_ipfs_client, mock_httpx_client):
    """Test checking if content exists (false case)."""
    cid = "QmNonexistent"

    # Set up the mock to raise an exception
    mock_httpx_client.head.side_effect = httpx.HTTPError("Not found")

    result = await async_ipfs_client.exists(cid)

    # Verify the correct endpoint was called
    mock_httpx_client.head.assert_called_once()
    assert mock_httpx_client.head.call_args[0][0] == f"https://ipfs.io/ipfs/{cid}"

    # Check the result
    assert result is False


@pytest.mark.asyncio
async def test_download_file(async_ipfs_client, mock_httpx_client, tmp_path):
    """Test downloading content from IPFS to a file."""
    cid = "QmTest123"
    output_path = os.path.join(tmp_path, "downloaded_file.txt")

    result = await async_ipfs_client.download_file(cid, output_path)

    # Verify the correct endpoint was called
    mock_httpx_client.post.assert_called_once()
    assert (
        mock_httpx_client.post.call_args[0][0]
        == f"http://localhost:5001/api/v0/cat?arg={cid}"
    )

    # Check the file was written correctly
    assert os.path.exists(output_path)
    with open(output_path, "rb") as f:
        content = f.read()
    assert content == b"Test content"

    # Check the result
    assert result == output_path


@pytest.mark.asyncio
async def test_add_directory(
    async_ipfs_client, temp_dir, mock_httpx_client, mock_dir_response
):
    """Test adding a directory to IPFS."""
    # Update the mock client to return our directory-specific response
    mock_httpx_client.post.return_value = mock_dir_response

    # Call the method
    result = await async_ipfs_client.add_directory(temp_dir)

    print(result, type(result))

    # Verify the correct endpoint was called with directory flags
    mock_httpx_client.post.assert_called_once()
    args, kwargs = mock_httpx_client.post.call_args
    assert "http://localhost:5001/api/v0/add" in args[0]
    assert "recursive=true" in args[0]
    assert "wrap-with-directory=true" in args[0]
    assert "files" in kwargs

    # Check the result
    assert result == {"Hash": "QmDir123", "Name": "temp_dir"}


@pytest.mark.asyncio
async def test_client_context_manager(mock_httpx_client):
    """Test using the AsyncIPFSClient as a context manager."""
    with patch("httpx.AsyncClient", return_value=mock_httpx_client):
        async with AsyncIPFSClient() as client:
            result = await client.add_str("Test context manager")
            assert result == {"Hash": "QmTest123", "Size": "123"}

        # Verify aclose was properly awaited
        mock_httpx_client.aclose.assert_awaited_once()


# IPFSClient tests that use the AsyncIPFSClient


@pytest.fixture
def mock_async_ipfs_client():
    """Create a mock AsyncIPFSClient."""
    client = AsyncMock()

    # Configure the mock to return awaitable values
    async def add_file_mock(*args, **kwargs):
        return {"Hash": "QmTest123"}

    async def add_directory_mock(*args, **kwargs):
        return {"Hash": "QmDir123"}

    async def cat_mock(*args, **kwargs):
        return b"Test content"

    async def ls_mock(*args, **kwargs):
        return True

    async def pin_mock(*args, **kwargs):
        return {"Pins": ["QmTest123"]}

    client.add_file = add_file_mock
    client.add_directory = add_directory_mock
    client.cat = cat_mock
    client.ls = ls_mock
    client.pin = pin_mock
    return client


@pytest.mark.asyncio
async def test_ipfs_client_upload_file(temp_file):
    """Test IPFSClient.upload_file method."""
    mock_client = AsyncMock()
    mock_client.add_file = AsyncMock(return_value={"Hash": "QmTest123"})
    mock_async_ipfs_client = MagicMock(return_value=mock_client)

    with patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        client = IPFSClient(api_url="http://localhost:5001")
        result = await client.upload_file(temp_file)

        # Verify AsyncIPFSClient.add_file was called
        mock_client.add_file.assert_called_once_with(temp_file)

        # Check the result
        assert result["cid"] == "QmTest123"
        assert result["filename"] == os.path.basename(temp_file)
        assert "size_bytes" in result
        assert "size_formatted" in result
        assert result["encrypted"] is False


@pytest.mark.asyncio
async def test_ipfs_client_upload_directory(temp_dir):
    """Test IPFSClient.upload_directory method."""
    # Create a properly mocked async client
    mock_client = AsyncMock()
    mock_client.add_directory.return_value = {"Hash": "QmDir123"}
    
    # Create a mock class for AsyncIPFSClient
    mock_async_ipfs_client = MagicMock(return_value=mock_client)
    
    # Patch the module namespace to include our mock AsyncIPFSClient
    with patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        client = IPFSClient(api_url="http://localhost:5001")
        result = await client.upload_directory(temp_dir)

        # Verify AsyncIPFSClient.add_directory was called
        assert mock_client.add_directory.call_count == 1

        # Check the result
        assert result["cid"] == "QmDir123"
        assert result["dirname"] == os.path.basename(temp_dir)
        assert "file_count" in result
        assert "total_size_bytes" in result
        assert "encrypted" in result


@pytest.mark.asyncio
async def test_ipfs_client_cat():
    """Test IPFSClient.cat method."""
    mock_client = AsyncMock()
    mock_client.cat = AsyncMock(return_value=b"Test content")
    mock_async_ipfs_client = MagicMock(return_value=mock_client)
    
    with patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        client = IPFSClient(api_url="http://localhost:5001")
        result = await client.cat("QmTest123")

        # Verify AsyncIPFSClient.cat was called
        assert mock_client.cat.call_count == 1

        # Check the result
        assert result["content"] == b"Test content"
        assert result["size_bytes"] == len(b"Test content")
        assert "size_formatted" in result
        assert "preview" in result
        assert "is_text" in result


@pytest.mark.asyncio
async def test_ipfs_client_exists():
    """Test IPFSClient.exists method."""
    mock_client = AsyncMock()
    mock_client.ls = AsyncMock(return_value=True)
    mock_async_ipfs_client = MagicMock(return_value=mock_client)
    
    with patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        client = IPFSClient(api_url="http://localhost:5001")
        result = await client.exists("QmTest123")

        # Verify AsyncIPFSClient.ls was called
        assert mock_client.ls.call_count == 1

        # Check the result
        assert result["exists"] is True
        assert result["cid"] == "QmTest123"
        assert "formatted_cid" in result
        assert "gateway_url" in result


@pytest.mark.asyncio
async def test_ipfs_client_pin():
    """Test IPFSClient.pin method."""
    mock_client = AsyncMock()
    mock_client.pin = AsyncMock(return_value={"Pins": ["QmTest123"]})
    mock_async_ipfs_client = MagicMock(return_value=mock_client)
    
    with patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        client = IPFSClient(api_url="http://localhost:5001")
        result = await client.pin("QmTest123")

        # Verify AsyncIPFSClient.pin was called
        assert mock_client.pin.call_count == 1

        # Check the result
        assert result["success"] is True
        assert result["cid"] == "QmTest123"
        assert "formatted_cid" in result
        assert "message" in result


@pytest.mark.asyncio
async def test_ipfs_client_download_file(tmp_path):
    """Test IPFSClient.download_file method with mocked requests.get."""
    test_cid = "QmTest123"
    output_path = os.path.join(tmp_path, "downloaded.txt")
    mock_client = AsyncMock()
    mock_async_ipfs_client = MagicMock(return_value=mock_client)

    with patch("requests.get") as mock_get, \
         patch.dict("hippius_sdk.ipfs.__dict__", {"AsyncIPFSClient": mock_async_ipfs_client}):
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.iter_content.return_value = [b"Test ", b"content"]
        mock_get.return_value = mock_response

        client = IPFSClient(gateway="https://ipfs.example.com")
        result = await client.download_file(test_cid, output_path)

        # Verify requests.get was called
        mock_get.assert_called_once_with(
            f"https://ipfs.example.com/ipfs/{test_cid}", stream=True
        )

        # Check the result
        assert result["success"] is True
        assert result["output_path"] == output_path
        assert "size_bytes" in result
        assert "size_formatted" in result
        assert "elapsed_seconds" in result
        assert result["decrypted"] is False
