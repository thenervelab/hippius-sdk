"""
Tests for the pinning status functionality.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hippius_sdk.substrate import SubstrateClient


@pytest.fixture
def mock_substrate_interface():
    """Create a mock SubstrateInterface."""
    with patch("hippius_sdk.substrate.SubstrateInterface") as mock_interface:
        mock_substrate = MagicMock()
        mock_interface.return_value = mock_substrate
        yield mock_substrate, mock_interface


@pytest.fixture
def mock_config():
    """Create a mock for config functions."""
    with patch("hippius_sdk.substrate.get_config_value") as mock_get_config, patch(
        "hippius_sdk.substrate.get_seed_phrase"
    ) as mock_get_seed, patch(
        "hippius_sdk.substrate.get_active_account"
    ) as mock_get_active, patch(
        "hippius_sdk.substrate.get_account_address"
    ) as mock_get_addr:
        url = "wss://hippius.example.com"
        mock_get_config.return_value = url
        mock_get_seed.return_value = None
        mock_get_active.return_value = None
        mock_get_addr.return_value = None
        yield mock_get_config, url


@pytest.mark.asyncio
async def test_get_pinning_status(mock_substrate_interface, mock_config):
    """Test the get_pinning_status method in SubstrateClient.

    Tests that the get_pinning_status method:
    - Queries the blockchain for storage requests
    - Properly processes the response
    - Returns a well-formatted list of requests
    """
    mock_substrate, _ = mock_substrate_interface
    _, url = mock_config

    # Create mock data for the test
    file_hash_hex = "516d51706936675836537969623333726e414e78423951584d477431684d5646636855576b53396e415231365978"

    # Create a mock key - in query_map this would be something like ScaleBytes
    mock_key = MagicMock()
    # Add properties for debugging
    mock_key.__str__ = MagicMock(return_value=file_hash_hex)
    # Make the key indexable to support file_hash_hex access
    mock_key.__getitem__ = MagicMock(
        side_effect=lambda idx: file_hash_hex if idx == 1 else "account"
    )

    # Create a mock value with the request details
    # Using a mock address instead of a real one
    mock_address = "5MOCK_ADDRESS_FOR_TESTING_PURPOSES_ONLY_XXXXXXXXXXXXX"
    mock_data = {
        "totalReplicas": 5,
        "owner": mock_address,
        "fileHash": file_hash_hex,
        "fileName": "files_list_test.json",
        "lastChargedAt": 12345,
        "createdAt": 12340,
        "minerIds": ["miner1", "miner2"],
        "selectedValidator": "validator1",
        "isAssigned": True,
    }

    # Create a custom class that provides both attribute and dictionary access
    class AttrDict:
        def __init__(self, data):
            self._data = data

        def __getattr__(self, name):
            if name in self._data:
                return self._data[name]
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}'"
            )

        def get(self, key, default=None):
            return self._data.get(key, default)

        def __dir__(self):
            return list(self._data.keys())

        def __str__(self):
            return str(self._data)

        # Make the object iterable like a dictionary
        def __iter__(self):
            return iter(self._data)

        # Allow dictionary-like access with []
        def __getitem__(self, key):
            return self._data[key]

        # Support .items() for iteration
        def items(self):
            return self._data.items()

        # Support checking for key existence with 'in'
        def __contains__(self, key):
            return key in self._data

        @property
        def value(self):
            return self._data

    # Create an instance of our custom class
    mock_value = AttrDict(mock_data)

    # Make query_map return an iterable of (key, value) pairs
    mock_substrate.query_map.return_value = [(mock_key, mock_value)]

    # Create a client instance and add the mock substrate
    client = SubstrateClient(url=url)
    client._substrate = mock_substrate
    client._account_address = mock_address

    # Mock the _hex_to_ipfs_cid method to return a predictable value
    with patch.object(client, "_hex_to_ipfs_cid", return_value="QmTestCid"), patch(
        "hippius_sdk.substrate.initialize_substrate_connection"
    ) as mock_init:
        # Make initialize_substrate_connection return the mock substrate and our test address
        mock_init.return_value = (mock_substrate, mock_address)

        # Call get_pinning_status with explicit address to bypass any config retrieval
        result = client.get_pinning_status(account_address=mock_address)

    # Check the method called the blockchain API correctly
    mock_substrate.query_map.assert_called_once_with(
        module="IpfsPallet",
        storage_function="UserStorageRequests",
        params=[mock_address],
    )

    # Print the actual result for debugging
    print("\nRESULT STRUCTURE:")
    print(f"Length of result: {len(result)}")
    print("First item contents:")
    for key, value in result[0].items():
        print(f"  {key}: {value} (type: {type(value)})")

    # Check the result structure
    assert len(result) == 1
    request = result[0]

    # Verify all fields were correctly processed
    assert request["cid"] == "QmTestCid"

    # Helper function to check fields by multiple possible names
    def get_field(data, *field_names):
        for name in field_names:
            if name in data:
                return data[name]
        return None

    # Check file name field
    file_name = get_field(request, "file_name", "fileName")
    assert (
        file_name == "files_list_test.json"
    ), f"Expected file_name to be 'files_list_test.json', got {file_name}"

    # Verify remaining fields
    total_replicas = get_field(request, "total_replicas", "totalReplicas")
    assert total_replicas == 5, f"Expected total_replicas to be 5, got {total_replicas}"

    owner = get_field(request, "owner")
    assert owner == mock_address, f"Expected owner to be '{mock_address}', got {owner}"

    created_at = get_field(request, "created_at", "createdAt")
    assert created_at == 12340, f"Expected created_at to be 12340, got {created_at}"

    last_charged_at = get_field(request, "last_charged_at", "lastChargedAt")
    assert (
        last_charged_at == 12345
    ), f"Expected last_charged_at to be 12345, got {last_charged_at}"

    # Check that we have miner_ids in some form
    miner_ids = get_field(request, "miner_ids", "minerIds")
    assert miner_ids is not None, "No miner_ids field found"
    assert len(miner_ids) == 2, f"Expected 2 miner_ids, got {len(miner_ids)}"

    # Check validator and assignment
    validator = get_field(request, "selected_validator", "selectedValidator")
    assert (
        validator == "validator1"
    ), f"Expected validator to be 'validator1', got {validator}"

    is_assigned = get_field(request, "is_assigned", "isAssigned")
    assert is_assigned is True, f"Expected is_assigned to be True, got {is_assigned}"


@pytest.mark.asyncio
async def test_get_pinning_status_empty_result(mock_substrate_interface, mock_config):
    """Test the get_pinning_status method when no results are found."""
    mock_substrate, _ = mock_substrate_interface
    _, url = mock_config

    # Create mock response with empty value
    mock_result = MagicMock()
    mock_result.value = []

    # Set up the mock query_map
    mock_substrate.query_map.return_value = mock_result

    # Create a client instance
    client = SubstrateClient(url=url)
    client._substrate = mock_substrate
    # Using a mock address that matches the one in test_get_pinning_status
    mock_address = "5MOCK_ADDRESS_FOR_TESTING_PURPOSES_ONLY_XXXXXXXXXXXXX"
    client._account_address = mock_address

    # Mock initialize_substrate_connection
    with patch("hippius_sdk.substrate.initialize_substrate_connection") as mock_init:
        mock_init.return_value = (mock_substrate, mock_address)

        # Get the pinning status
        result = client.get_pinning_status(account_address=mock_address)

    # Check the result is an empty list
    assert result == []
