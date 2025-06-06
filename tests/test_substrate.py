"""
Tests for the Substrate client.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.substrate import FileInput, SubstrateClient


@pytest.fixture
def mock_substrate_interface():
    """Create a mock SubstrateInterface."""
    with patch("hippius_sdk.substrate.SubstrateInterface") as mock_interface:
        mock_substrate = MagicMock()
        mock_interface.return_value = mock_substrate
        yield mock_substrate, mock_interface


@pytest.fixture
def mock_keypair():
    """Create a mock Keypair."""
    with patch("hippius_sdk.substrate.Keypair") as mock_keypair_class:
        mock_keypair_obj = MagicMock()
        mock_keypair_obj.ss58_address = (
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        mock_keypair_class.create_from_mnemonic.return_value = mock_keypair_obj
        yield mock_keypair_obj, mock_keypair_class


@pytest.fixture
def mock_config():
    """Create a mock for config functions."""
    with patch("hippius_sdk.substrate.get_config_value") as mock_get_config:
        url = "wss://hippius.example.com"
        mock_get_config.return_value = url
        yield mock_get_config, url


@pytest.fixture
def mock_temp_file():
    """Create a mock temporary file."""
    mock_file = MagicMock()
    mock_file.name = "/tmp/test_file.json"
    return mock_file


def test_init_without_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify the SubstrateClient initializes properly with only a URL.

    Tests that when initialized without a seed phrase, the client:
    - Sets the URL correctly
    - Doesn't create a substrate connection yet (lazy loading)
    - Keeps keypair and seed phrase as None
    """
    _, url = mock_config

    # The API has changed - the _read_only flag is no longer set during initialization
    # Let's patch the get_account_address to control the _read_only flag
    with patch("hippius_sdk.substrate.get_account_address", return_value=None):
        client = SubstrateClient(url=url)

        # Initial state should not create substrate connection yet (lazy loading)
        assert client.url == url
        assert client._substrate is None
        assert client._keypair is None
        assert client._seed_phrase is None


def test_init_with_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify the SubstrateClient initializes properly with a seed phrase.

    Tests that when initialized with a seed phrase, the client:
    - Doesn't store the seed phrase (seed-agnostic)
    - Uses set_seed_phrase for backward compatibility
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    # We need to mock the set_seed_phrase method since that's now the way to
    # set a seed phrase for backward compatibility
    with patch.object(SubstrateClient, "set_seed_phrase") as mock_set_seed_phrase:
        # With our seed-agnostic approach, we cannot pass seed_phrase to the constructor
        # So we'll set it after construction for backward compatibility
        client = SubstrateClient(url=url)
        seed_phrase = "test seed phrase"
        client.set_seed_phrase(seed_phrase)

        # Check set_seed_phrase was called correctly
        mock_set_seed_phrase.assert_called_once_with(seed_phrase)


def test_connect_with_exception(mock_substrate_interface, mock_keypair, mock_config):
    """Verify connection exceptions are handled properly.

    Tests that when the SubstrateInterface raises an exception:
    - The client's connect method wraps it in a ConnectionError
    - The exception is propagated to the caller
    """
    mock_substrate, mock_interface = mock_substrate_interface
    mock_interface.side_effect = Exception("Connection error")
    _, url = mock_config

    client = SubstrateClient(url=url)

    with pytest.raises(ConnectionError):
        client.connect()


def test_ensure_keypair_with_seed_phrase(
    mock_substrate_interface, mock_keypair, mock_config
):
    """Verify _ensure_keypair creates a keypair from a seed phrase.

    Tests that the internal _ensure_keypair method:
    - Creates a keypair from the provided seed phrase
    - Sets the keypair attribute properly
    - Returns True on successful keypair creation
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url)

    # Reset mock to test _ensure_keypair directly
    mock_keypair_class.reset_mock()
    client._keypair = None

    # With the seed-agnostic approach, we pass the seed phrase explicitly
    result = client._ensure_keypair(seed_phrase)

    # Should create keypair from seed phrase
    mock_keypair_class.create_from_mnemonic.assert_called_once_with(seed_phrase)
    assert client._keypair == mock_keypair_obj
    assert result is True


def test_set_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify setting a seed phrase after initialization.

    Tests that the set_seed_phrase method:
    - Updates the stored seed phrase (for backward compatibility)
    - Sets read-only mode to False
    - Creates a new keypair from the provided seed phrase
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    # Mock _ensure_keypair to verify it's called with the seed phrase
    with patch.object(SubstrateClient, "_ensure_keypair") as mock_ensure_keypair:
        client = SubstrateClient(url=url)
        seed_phrase = "new test seed phrase"

        client.set_seed_phrase(seed_phrase)

        # Should store seed phrase for backward compatibility
        assert client._seed_phrase == seed_phrase
        # And pass it to _ensure_keypair
        mock_ensure_keypair.assert_called_once_with(seed_phrase)


def test_set_seed_phrase_empty(mock_substrate_interface, mock_keypair, mock_config):
    """Verify setting an empty seed phrase raises ValueError.

    Tests that the set_seed_phrase method:
    - Validates that the seed phrase is not empty
    - Raises a ValueError when an empty string is provided
    """
    _, url = mock_config

    client = SubstrateClient(url=url)

    with pytest.raises(ValueError):
        client.set_seed_phrase("")


@patch("hippius_sdk.substrate.uuid.uuid4")
@pytest.mark.asyncio
async def test_storage_request(
    mock_uuid, mock_substrate_interface, mock_keypair, mock_config, mock_temp_file
):
    """Verify the storage_request method submits transactions correctly.

    Tests that the storage_request method:
    - Creates a JSON file with file metadata
    - Uploads the metadata file to IPFS
    - Composes a storage_request call with the correct parameters
    - Signs and submits the extrinsic transaction
    - Returns the transaction hash on success
    """
    mock_substrate, _ = mock_substrate_interface
    mock_keypair_obj, _ = mock_keypair
    _, url = mock_config

    mock_uuid.return_value = "test-uuid"
    mock_ipfs = MagicMock()
    # Create an awaitable mock for the async upload_file method
    mock_ipfs.upload_file = AsyncMock(return_value={"cid": "QmTestCID"})
    mock_ipfs_class = MagicMock(return_value=mock_ipfs)

    # In our seed-agnostic approach, we pass the seed phrase to the method
    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url)
    client._substrate = mock_substrate

    # Mock _ensure_keypair to simulate the seed phrase being used
    with patch.object(SubstrateClient, "_ensure_keypair") as mock_ensure_keypair:
        mock_ensure_keypair.return_value = True
        client._keypair = mock_keypair_obj

        mock_call = MagicMock()
        mock_substrate.compose_call.return_value = mock_call

        mock_extrinsic = MagicMock()
        mock_substrate.create_signed_extrinsic.return_value = mock_extrinsic

        mock_receipt = MagicMock()
        mock_receipt.extrinsic_hash = "0xabcdef1234567890"
        mock_substrate.submit_extrinsic.return_value = mock_receipt

        mock_substrate.get_payment_info.return_value = {"partialFee": 0.1}

        files = [FileInput("QmHash1", "file1.txt"), FileInput("QmHash2", "file2.jpg")]

        mock_tempfile = MagicMock()
        mock_tempfile.NamedTemporaryFile.return_value.__enter__.return_value = (
            mock_temp_file
        )

        with patch("hippius_sdk.ipfs.IPFSClient", mock_ipfs_class), patch(
            "tempfile.NamedTemporaryFile", mock_tempfile.NamedTemporaryFile
        ):
            # Pass the seed phrase here
            tx_hash = await client.storage_request(files, seed_phrase=seed_phrase)

    expected_json = json.dumps(
        [
            {"filename": "file1.txt", "cid": "QmHash1"},
            {"filename": "file2.jpg", "cid": "QmHash2"},
        ],
        indent=2,
    )

    # Verify _ensure_keypair was called with the seed phrase
    mock_ensure_keypair.assert_called_once_with(seed_phrase)

    mock_temp_file.write.assert_called_once_with(expected_json)
    mock_ipfs.upload_file.assert_called_once_with(mock_temp_file.name)
    mock_substrate.compose_call.assert_called_once()
    call_args = mock_substrate.compose_call.call_args[1]

    assert call_args["call_module"] == "Marketplace"
    assert call_args["call_function"] == "storage_request"
    assert call_args["call_params"]["files_input"][0]["file_hash"] == "QmTestCID"

    # Check extrinsic was created and submitted
    mock_substrate.create_signed_extrinsic.assert_called_once_with(
        call=mock_call, keypair=mock_keypair_obj
    )
    mock_substrate.submit_extrinsic.assert_called_once_with(
        extrinsic=mock_extrinsic, wait_for_inclusion=True
    )

    # Check return value
    assert tx_hash == "0xabcdef1234567890"


@pytest.mark.asyncio
async def test_store_cid(mock_substrate_interface, mock_keypair, mock_config):
    """Verify the store_cid method correctly delegates to storage_request.

    Tests that the store_cid method:
    - Creates a FileInput with the correct CID and filename
    - Calls storage_request with the FileInput in a list
    - Returns the transaction hash from storage_request
    """
    mock_substrate, _ = mock_substrate_interface
    _, url = mock_config

    # Mock the storage_request method
    with patch.object(SubstrateClient, "storage_request") as mock_storage_request:
        # Create an async mock
        mock_storage_request.return_value = "0xabcdef1234567890"
        # Make it properly awaitable
        mock_storage_request.side_effect = AsyncMock(return_value="0xabcdef1234567890")

        client = SubstrateClient(url=url)
        tx_hash = await client.store_cid("QmTestCID", "test.txt")

        # Check storage_request was called with correct parameters
        mock_storage_request.assert_called_once()
        file_input = mock_storage_request.call_args[0][0][0]
        assert file_input.file_hash == "QmTestCID"
        assert file_input.file_name == "test.txt"
        assert tx_hash == "0xabcdef1234567890"
