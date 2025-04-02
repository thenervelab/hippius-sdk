"""
Tests for the Substrate client.
"""

import unittest
from unittest.mock import patch, MagicMock

from hippius_sdk.substrate import SubstrateClient
from substrateinterface.exceptions import SubstrateRequestException


class TestSubstrateClient(unittest.TestCase):
    """Test cases for the Substrate client."""

    def setUp(self):
        """Set up test fixtures."""
        self.url = "wss://hippius.example.com"

        # Setup mock for SubstrateInterface
        self.patcher = patch("hippius_sdk.substrate.SubstrateInterface")
        self.mock_substrate_interface = self.patcher.start()
        self.mock_substrate = MagicMock()
        self.mock_substrate_interface.return_value = self.mock_substrate

        # Setup mock for Keypair
        self.keypair_patcher = patch("hippius_sdk.substrate.Keypair")
        self.mock_keypair_class = self.keypair_patcher.start()
        self.mock_keypair = MagicMock()
        self.mock_keypair.ss58_address = (
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        self.mock_keypair_class.create_from_private_key.return_value = self.mock_keypair

    def tearDown(self):
        """Tear down test fixtures."""
        self.patcher.stop()
        self.keypair_patcher.stop()

    def test_init_without_private_key(self):
        """Test initializing without a private key."""
        client = SubstrateClient(url=self.url)

        self.mock_substrate_interface.assert_called_once_with(url=self.url)
        self.assertEqual(client.substrate, self.mock_substrate)
        self.assertIsNone(client.keypair)

    def test_init_with_private_key(self):
        """Test initializing with a private key."""
        private_key = (
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        client = SubstrateClient(url=self.url, private_key=private_key)

        self.mock_substrate_interface.assert_called_once_with(url=self.url)
        self.mock_keypair_class.create_from_private_key.assert_called_once_with(
            private_key
        )
        self.assertEqual(client.substrate, self.mock_substrate)
        self.assertEqual(client.keypair, self.mock_keypair)

    def test_set_private_key(self):
        """Test setting a private key after initialization."""
        client = SubstrateClient(url=self.url)
        private_key = (
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )

        client.set_private_key(private_key)

        self.mock_keypair_class.create_from_private_key.assert_called_once_with(
            private_key
        )
        self.assertEqual(client.keypair, self.mock_keypair)

    def test_store_cid_without_keypair(self):
        """Test storing a CID without a keypair."""
        client = SubstrateClient(url=self.url)

        with self.assertRaises(ValueError):
            client.store_cid("QmTest123")

    def test_store_cid_with_keypair(self):
        """Test storing a CID with a keypair."""
        private_key = (
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        client = SubstrateClient(url=self.url, private_key=private_key)

        # Mock the compose_call, create_signed_extrinsic, and submit_extrinsic methods
        mock_call = MagicMock()
        self.mock_substrate.compose_call.return_value = mock_call

        mock_extrinsic = MagicMock()
        self.mock_substrate.create_signed_extrinsic.return_value = mock_extrinsic

        mock_receipt = MagicMock()
        mock_receipt.extrinsic_hash = "0xabcdef1234567890"
        self.mock_substrate.submit_extrinsic.return_value = mock_receipt

        # Call the method
        cid = "QmTest123"
        metadata = {"key": "value"}
        tx_hash = client.store_cid(cid, metadata)

        # Verify the calls
        self.mock_substrate.compose_call.assert_called_once_with(
            call_module="HippiusStorage",
            call_function="store_cid",
            call_params={"cid": cid, "metadata": str(metadata)},
        )

        self.mock_substrate.create_signed_extrinsic.assert_called_once_with(
            call=mock_call, keypair=self.mock_keypair
        )

        self.mock_substrate.submit_extrinsic.assert_called_once_with(
            extrinsic=mock_extrinsic, wait_for_inclusion=True
        )

        self.assertEqual(tx_hash, "0xabcdef1234567890")

    def test_get_cid_metadata(self):
        """Test retrieving CID metadata."""
        client = SubstrateClient(url=self.url)

        # Mock the query method
        mock_result = MagicMock()
        mock_result.value = "sample metadata"
        self.mock_substrate.query.return_value = mock_result

        # Call the method
        cid = "QmTest123"
        metadata = client.get_cid_metadata(cid)

        # Verify the calls
        self.mock_substrate.query.assert_called_once_with(
            module="HippiusStorage", storage_function="CIDMetadata", params=[cid]
        )

        self.assertEqual(metadata, {"metadata": "sample metadata"})

    def test_get_cid_metadata_not_found(self):
        """Test retrieving CID metadata when the CID is not found."""
        client = SubstrateClient(url=self.url)

        # Mock the query method
        mock_result = MagicMock()
        mock_result.value = None
        self.mock_substrate.query.return_value = mock_result

        # Call the method
        cid = "QmTest123"
        with self.assertRaises(ValueError):
            client.get_cid_metadata(cid)

    def test_get_account_cids(self):
        """Test retrieving CIDs associated with an account."""
        client = SubstrateClient(url=self.url)

        # Mock the query_map method
        mock_item1 = (MagicMock(), MagicMock())
        mock_item1[1].value = "QmTest123"

        mock_item2 = (MagicMock(), MagicMock())
        mock_item2[1].value = "QmTest456"

        self.mock_substrate.query_map.return_value = [mock_item1, mock_item2]

        # Call the method
        account_address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        cids = client.get_account_cids(account_address)

        # Verify the calls
        self.mock_substrate.query_map.assert_called_once_with(
            module="HippiusStorage",
            storage_function="AccountCIDs",
            params=[account_address],
        )

        self.assertEqual(cids, ["QmTest123", "QmTest456"])

    def test_delete_cid(self):
        """Test deleting a CID from the blockchain."""
        private_key = (
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        client = SubstrateClient(url=self.url, private_key=private_key)

        # Mock the compose_call, create_signed_extrinsic, and submit_extrinsic methods
        mock_call = MagicMock()
        self.mock_substrate.compose_call.return_value = mock_call

        mock_extrinsic = MagicMock()
        self.mock_substrate.create_signed_extrinsic.return_value = mock_extrinsic

        mock_receipt = MagicMock()
        mock_receipt.extrinsic_hash = "0xabcdef1234567890"
        self.mock_substrate.submit_extrinsic.return_value = mock_receipt

        # Call the method
        cid = "QmTest123"
        tx_hash = client.delete_cid(cid)

        # Verify the calls
        self.mock_substrate.compose_call.assert_called_once_with(
            call_module="HippiusStorage",
            call_function="delete_cid",
            call_params={"cid": cid},
        )

        self.mock_substrate.create_signed_extrinsic.assert_called_once_with(
            call=mock_call, keypair=self.mock_keypair
        )

        self.mock_substrate.submit_extrinsic.assert_called_once_with(
            extrinsic=mock_extrinsic, wait_for_inclusion=True
        )

        self.assertEqual(tx_hash, "0xabcdef1234567890")

    def test_get_storage_fee(self):
        """Test getting the storage fee for a file size."""
        client = SubstrateClient(url=self.url)

        # Mock the query method
        mock_result = MagicMock()
        mock_result.value = 0.1  # 0.1 tokens per MB
        self.mock_substrate.query.return_value = mock_result

        # Call the method
        file_size_mb = 10.0
        fee = client.get_storage_fee(file_size_mb)

        # Verify the calls
        self.mock_substrate.query.assert_called_once_with(
            module="HippiusStorage", storage_function="StorageFeePerMB"
        )

        self.assertEqual(fee, 1.0)  # 0.1 * 10.0 = 1.0

    def test_get_account_balance(self):
        """Test getting the balance of an account."""
        client = SubstrateClient(url=self.url, private_key="0x1234")

        # Mock the query method
        mock_result = MagicMock()
        mock_result.value = {
            "data": {
                "free": 1000000000000000000,  # 1 token
                "reserved": 500000000000000000,  # 0.5 tokens
                "miscFrozen": 200000000000000000,  # 0.2 tokens
                "feeFrozen": 100000000000000000,  # 0.1 tokens
            }
        }
        self.mock_substrate.query.return_value = mock_result

        # Call the method
        balance = client.get_account_balance()

        # Verify the calls
        self.mock_substrate.query.assert_called_once_with(
            module="System",
            storage_function="Account",
            params=[self.mock_keypair.ss58_address],
        )

        expected_balance = {
            "free": 1.0,
            "reserved": 0.5,
            "total": 1.5,
            "misc_frozen": 0.2,
            "fee_frozen": 0.1,
        }

        self.assertEqual(balance, expected_balance)


if __name__ == "__main__":
    unittest.main()
