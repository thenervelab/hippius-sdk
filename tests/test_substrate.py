"""
Tests for the Substrate client.
"""

import json
from unittest.mock import MagicMock, patch, AsyncMock

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
        mock_keypair_obj.ss58_address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
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
    - Stores the seed phrase correctly
    - Sets read-only mode to False
    - Creates a keypair from the provided seed phrase
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url, seed_phrase=seed_phrase)

    # Check seed phrase is stored and keypair is created
    assert client._seed_phrase == seed_phrase
    assert client._read_only is False
    mock_keypair_class.create_from_mnemonic.assert_called_with(seed_phrase)


def test_connect(mock_substrate_interface, mock_keypair, mock_config):
    """Verify the client can connect to a Substrate node.
    
    Tests that the connect method:
    - Initializes the SubstrateInterface with the correct parameters
    - Sets the _substrate attribute with the connection
    - Returns True on successful connection
    """
    mock_substrate, mock_interface = mock_substrate_interface
    _, url = mock_config

    client = SubstrateClient(url=url)
    result = client.connect()

    # Should have connected to substrate
    mock_interface.assert_called_once_with(
        url=url,
        ss58_format=42,
        type_registry_preset="substrate-node-template",
    )
    assert client._substrate == mock_substrate
    assert result is True


def test_connect_with_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify connecting with a seed phrase creates a keypair.
    
    Tests that when connecting with a seed phrase:
    - The client creates a keypair from the seed phrase
    - The account address is set from the keypair's SS58 address
    - The client is not in read-only mode
    - The connection returns True for success
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    mock_keypair_class.reset_mock()

    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url, seed_phrase=seed_phrase)

    mock_keypair_class.reset_mock()
    result = client.connect()

    mock_keypair_class.create_from_mnemonic.assert_called_once_with(seed_phrase)
    assert client._keypair == mock_keypair_obj
    assert client._account_address == mock_keypair_obj.ss58_address
    assert client._read_only is False
    assert result is True


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


def test_ensure_keypair_with_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify _ensure_keypair creates a keypair from a seed phrase.
    
    Tests that the internal _ensure_keypair method:
    - Creates a keypair from the stored seed phrase when keypair is None
    - Sets the keypair attribute properly
    - Returns True on successful keypair creation
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url, seed_phrase=seed_phrase)

    # Reset mock to test _ensure_keypair directly
    mock_keypair_class.reset_mock()
    client._keypair = None

    result = client._ensure_keypair()

    # Should create keypair from seed phrase
    mock_keypair_class.create_from_mnemonic.assert_called_once_with(seed_phrase)
    assert client._keypair == mock_keypair_obj
    assert result is True


def test_set_seed_phrase(mock_substrate_interface, mock_keypair, mock_config):
    """Verify setting a seed phrase after initialization.
    
    Tests that the set_seed_phrase method:
    - Updates the stored seed phrase
    - Sets read-only mode to False
    - Creates a new keypair from the provided seed phrase
    """
    mock_keypair_obj, mock_keypair_class = mock_keypair
    _, url = mock_config

    client = SubstrateClient(url=url)
    seed_phrase = "new test seed phrase"

    client.set_seed_phrase(seed_phrase)

    # Should store seed phrase and create keypair
    assert client._seed_phrase == seed_phrase
    assert client._read_only is False
    mock_keypair_class.create_from_mnemonic.assert_called_with(seed_phrase)


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
async def test_storage_request(mock_uuid, mock_substrate_interface, mock_keypair, mock_config,
                         mock_temp_file):
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

    seed_phrase = "test seed phrase"
    client = SubstrateClient(url=url, seed_phrase=seed_phrase)
    client._substrate = mock_substrate

    mock_call = MagicMock()
    mock_substrate.compose_call.return_value = mock_call

    mock_extrinsic = MagicMock()
    mock_substrate.create_signed_extrinsic.return_value = mock_extrinsic

    mock_receipt = MagicMock()
    mock_receipt.extrinsic_hash = "0xabcdef1234567890"
    mock_substrate.submit_extrinsic.return_value = mock_receipt

    mock_substrate.get_payment_info.return_value = {"partialFee": 0.1}

    files = [
        FileInput("QmHash1", "file1.txt"),
        FileInput("QmHash2", "file2.jpg")
    ]

    mock_tempfile = MagicMock()
    mock_tempfile.NamedTemporaryFile.return_value.__enter__.return_value = mock_temp_file

    with patch("hippius_sdk.ipfs.IPFSClient", mock_ipfs_class), \
            patch("tempfile.NamedTemporaryFile", mock_tempfile.NamedTemporaryFile):
        tx_hash = await client.storage_request(files)

    expected_json = json.dumps([
        {"filename": "file1.txt", "cid": "QmHash1"},
        {"filename": "file2.jpg", "cid": "QmHash2"}
    ], indent=2)

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
    with patch.object(SubstrateClient, 'storage_request') as mock_storage_request:
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


def test_get_user_files_from_profile(mock_substrate_interface, mock_keypair, mock_config):
    """Verify retrieval of user files from the blockchain profile.
    
    Tests that the get_user_files_from_profile method:
    - Queries the IpfsPallet UserProfile storage for the account
    - Converts the hex-encoded CID to an IPFS CID format
    - Retrieves the profile content from IPFS
    - Parses the JSON content with file metadata 
    - Returns the file list with correct hash, name, and size
    """
    mock_substrate, _ = mock_substrate_interface
    _, url = mock_config

    client = SubstrateClient(url=url)
    client._substrate = mock_substrate
    client._account_address = "test_account_address"

    mock_result = MagicMock()
    mock_result.value = "1234abcd"  # Hex-encoded CID
    mock_substrate.query.return_value = mock_result

    # Mock IPFSClient
    mock_ipfs = MagicMock()
    mock_ipfs.cat.return_value = {
        "is_text": True,
        "content": json.dumps({
            "files": [
                {
                    "file_hash": "QmTestFile1",
                    "file_name": "test_file1.txt",
                    "size": 1024
                }
            ]
        })
    }

    with patch.object(SubstrateClient, '_hex_to_ipfs_cid', return_value="QmProfileCID"):
        with patch("hippius_sdk.ipfs.IPFSClient", return_value=mock_ipfs):
            files = client.get_user_files_from_profile()
            mock_substrate.query.assert_called_once_with(
                module="IpfsPallet",
                storage_function="UserProfile",
                params=["test_account_address"]
            )

            mock_ipfs.cat.assert_called_once_with("QmProfileCID")

            assert len(files) == 1
            assert files[0]["file_hash"] == "QmTestFile1"
            assert files[0]["file_name"] == "test_file1.txt"
            assert files[0]["file_size"] == 1024
