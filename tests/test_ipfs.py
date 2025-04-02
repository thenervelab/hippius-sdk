"""
Tests for the IPFS client.
"""

import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from hippius_sdk.ipfs import IPFSClient


class TestIPFSClient(unittest.TestCase):
    """Test cases for the IPFS client."""

    def setUp(self):
        """Set up test fixtures."""
        self.gateway = "https://ipfs.example.com"
        # Use None as api_url to avoid attempts to connect to default Hippius node during tests
        self.client = IPFSClient(gateway=self.gateway, api_url=None)

        # Create a temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"Test content for IPFS")
        self.temp_file.close()

        # Create a temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()
        with open(os.path.join(self.temp_dir, "test_file.txt"), "w") as f:
            f.write("Test content in directory")

    def tearDown(self):
        """Tear down test fixtures."""
        os.unlink(self.temp_file.name)
        os.unlink(os.path.join(self.temp_dir, "test_file.txt"))
        os.rmdir(self.temp_dir)

    @patch("ipfshttpclient.connect")
    def test_init_with_api_url(self, mock_connect):
        """Test initializing with an API URL."""
        mock_client = MagicMock()
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")

        mock_connect.assert_called_once_with("http://localhost:5001")
        self.assertEqual(client.client, mock_client)
        self.assertEqual(client.base_url, "https://localhost")

    @patch("ipfshttpclient.connect")
    def test_init_with_defaults(self, mock_connect):
        """Test initializing with default values."""
        mock_client = MagicMock()
        mock_connect.return_value = mock_client

        client = IPFSClient()

        # Should connect to the default Hippius relay node
        mock_connect.assert_called_once_with("http://relay-fr.hippius.network:5001")
        self.assertEqual(client.client, mock_client)
        self.assertEqual(client.base_url, "https://relay-fr.hippius.network")

    @patch("ipfshttpclient.connect")
    def test_init_without_api_url(self, mock_connect):
        """Test initializing with api_url=None."""
        mock_client = MagicMock()
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url=None)

        mock_connect.assert_called_once_with()
        self.assertEqual(client.client, mock_client)
        self.assertIsNone(client.base_url)

    @patch("ipfshttpclient.connect")
    def test_init_connection_error(self, mock_connect):
        """Test handling connection error during initialization."""
        mock_connect.side_effect = Exception("Connection error")

        client = IPFSClient(gateway=self.gateway, api_url=None)

        mock_connect.assert_called_once_with()
        self.assertIsNone(client.client)

    @patch("ipfshttpclient.connect")
    def test_init_connection_error_with_fallback(self, mock_connect):
        """Test handling connection error with fallback attempt."""
        # First connection fails
        mock_connect.side_effect = [
            ipfshttpclient.exceptions.ConnectionError("Connection error"),
            MagicMock(),  # Second connection succeeds (fallback to local daemon)
        ]

        client = IPFSClient(gateway=self.gateway, api_url="http://unavailable:5001")

        # Should have called connect twice - once for provided URL, once for fallback
        self.assertEqual(mock_connect.call_count, 2)
        mock_connect.assert_any_call("http://unavailable:5001")
        mock_connect.assert_any_call()
        self.assertIsNotNone(client.client)
        self.assertEqual(client.base_url, "https://unavailable")

    @patch("ipfshttpclient.connect")
    def test_upload_file(self, mock_connect):
        """Test uploading a file."""
        mock_client = MagicMock()
        mock_client.add.return_value = {"Hash": "QmTest123"}
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        cid = client.upload_file(self.temp_file.name)

        mock_client.add.assert_called_once_with(self.temp_file.name)
        self.assertEqual(cid, "QmTest123")

    @patch("ipfshttpclient.connect")
    @patch("requests.post")
    def test_upload_file_via_http_api(self, mock_post, mock_connect):
        """Test uploading a file via HTTP API fallback."""
        # Make ipfshttpclient connection fail
        mock_connect.side_effect = ipfshttpclient.exceptions.ConnectionError(
            "Connection error"
        )

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"Hash": "QmTest123"}
        mock_post.return_value = mock_response

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        cid = client.upload_file(self.temp_file.name)

        # Verify the HTTP request was made
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0][0], "https://localhost/api/v0/add")
        self.assertEqual(cid, "QmTest123")

    @patch("ipfshttpclient.connect")
    def test_upload_file_no_client(self, mock_connect):
        """Test uploading a file without a client."""
        mock_connect.side_effect = Exception("Connection error")

        client = IPFSClient(gateway=self.gateway, api_url=None)

        with self.assertRaises(ConnectionError):
            client.upload_file(self.temp_file.name)

    @patch("ipfshttpclient.connect")
    def test_upload_directory(self, mock_connect):
        """Test uploading a directory."""
        mock_client = MagicMock()
        mock_client.add.return_value = [
            {"Hash": "QmFile123", "Name": "test_file.txt"},
            {"Hash": "QmDir123", "Name": "temp_dir"},
        ]
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        cid = client.upload_directory(self.temp_dir)

        mock_client.add.assert_called_once_with(self.temp_dir, recursive=True)
        self.assertEqual(cid, "QmDir123")

    @patch("ipfshttpclient.connect")
    @patch("requests.post")
    def test_upload_directory_via_http_api(self, mock_post, mock_connect):
        """Test uploading a directory via HTTP API fallback."""
        # Make ipfshttpclient connection fail
        mock_connect.side_effect = ipfshttpclient.exceptions.ConnectionError(
            "Connection error"
        )

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.text = '{"Hash":"QmFile123","Name":"test_file.txt"}\n{"Hash":"QmDir123","Name":"temp_dir"}'
        mock_post.return_value = mock_response

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        cid = client.upload_directory(self.temp_dir)

        # Verify the HTTP request was made
        mock_post.assert_called_once()
        self.assertTrue("recursive=true" in mock_post.call_args[0][0])
        self.assertEqual(cid, "QmDir123")

    @patch("requests.get")
    def test_download_file(self, mock_get):
        """Test downloading a file."""
        mock_response = MagicMock()
        mock_response.iter_content.return_value = [b"chunk1", b"chunk2"]
        mock_get.return_value = mock_response

        with tempfile.NamedTemporaryFile() as output_file:
            self.client.download_file("QmTest123", output_file.name)

            mock_get.assert_called_once_with(
                f"{self.gateway}/ipfs/QmTest123", stream=True
            )
            mock_response.raise_for_status.assert_called_once()

            output_file.seek(0)
            content = output_file.read()
            self.assertEqual(content, b"chunk1chunk2")

    @patch("ipfshttpclient.connect")
    def test_cat_with_client(self, mock_connect):
        """Test getting file content with a client."""
        mock_client = MagicMock()
        mock_client.cat.return_value = b"test content"
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        content = client.cat("QmTest123")

        mock_client.cat.assert_called_once_with("QmTest123")
        self.assertEqual(content, b"test content")

    @patch("requests.get")
    def test_cat_without_client(self, mock_get):
        """Test getting file content without a client."""
        mock_response = MagicMock()
        mock_response.content = b"test content"
        mock_get.return_value = mock_response

        content = self.client.cat("QmTest123")

        mock_get.assert_called_once_with(f"{self.gateway}/ipfs/QmTest123")
        mock_response.raise_for_status.assert_called_once()
        self.assertEqual(content, b"test content")

    @patch("ipfshttpclient.connect")
    def test_exists_with_client(self, mock_connect):
        """Test checking if a CID exists with a client."""
        mock_client = MagicMock()
        mock_client.ls.return_value = {"Objects": [{"Hash": "QmTest123"}]}
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        exists = client.exists("QmTest123")

        mock_client.ls.assert_called_once_with("QmTest123")
        self.assertTrue(exists)

    @patch("requests.head")
    def test_exists_without_client(self, mock_head):
        """Test checking if a CID exists without a client."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response

        exists = self.client.exists("QmTest123")

        mock_head.assert_called_once_with(f"{self.gateway}/ipfs/QmTest123")
        self.assertTrue(exists)

    @patch("ipfshttpclient.connect")
    def test_pin(self, mock_connect):
        """Test pinning a CID."""
        mock_client = MagicMock()
        mock_client.pin.add.return_value = {"Pins": ["QmTest123"]}
        mock_connect.return_value = mock_client

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        success = client.pin("QmTest123")

        mock_client.pin.add.assert_called_once_with("QmTest123")
        self.assertTrue(success)

    @patch("ipfshttpclient.connect")
    @patch("requests.post")
    def test_pin_via_http_api(self, mock_post, mock_connect):
        """Test pinning a CID via HTTP API."""
        # Make ipfshttpclient connection fail
        mock_connect.side_effect = ipfshttpclient.exceptions.ConnectionError(
            "Connection error"
        )

        # Mock HTTP response
        mock_response = MagicMock()
        mock_post.return_value = mock_response

        client = IPFSClient(gateway=self.gateway, api_url="http://localhost:5001")
        success = client.pin("QmTest123")

        # Verify the HTTP request was made
        mock_post.assert_called_once()
        self.assertEqual(
            mock_post.call_args[0][0], "https://localhost/api/v0/pin/add?arg=QmTest123"
        )
        self.assertTrue(success)

    def test_pin_no_client(self):
        """Test pinning a CID without a client."""
        with self.assertRaises(ConnectionError):
            self.client.pin("QmTest123")


if __name__ == "__main__":
    unittest.main()
