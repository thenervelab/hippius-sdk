# Hippius SDK

A Python SDK for interacting with Hippius blockchain storage, designed specifically for ML developers working with Bittensor.

## Features

- IPFS operations: Upload and download files to/from IPFS
- Multiple connection methods for IPFS (RPC or HTTP API)
- Simple and intuitive API for ML developers

**Coming Soon**: Substrate blockchain integration for decentralized storage references

## Installation

```bash
# Using pip
pip install hippius-sdk

# Using Poetry
poetry add hippius-sdk
```

## Quick Start

```python
from hippius_sdk import HippiusClient

# Initialize the client with default connections to Hippius network
client = HippiusClient()

# Or specify custom endpoints
client = HippiusClient(
    ipfs_gateway="https://ipfs.io",                       # For downloads (default)
    ipfs_api_url="http://relay-fr.hippius.network:5001",  # For uploads (default)
)

# Upload a file to IPFS
result = client.upload_file("path/to/your/model.pt")
cid = result["cid"]
print(f"File uploaded with CID: {cid}")

# Download a file from IPFS
client.download_file(cid, "path/to/save/model.pt")

# Check if a file exists
exists = client.exists(cid)
print(f"File exists: {exists}")

# Get file content directly
content = client.cat(cid)

# Pin a file to ensure it stays on the network
success = client.pin(cid)
```

## Detailed Usage

### IPFS Operations

```python
from hippius_sdk import IPFSClient

# Initialize the IPFS client (uses Hippius relay node by default)
ipfs_client = IPFSClient()

# Or specify custom endpoints
ipfs_client = IPFSClient(
    gateway="https://ipfs.io",                       # For downloads
    api_url="http://relay-fr.hippius.network:5001"   # For uploads
)

# Upload a file
cid = ipfs_client.upload_file("path/to/your/file.txt")

# Upload a directory
cid = ipfs_client.upload_directory("path/to/your/directory")

# Download a file
ipfs_client.download_file(cid, "path/to/save/file.txt")

# Check if a CID exists
exists = ipfs_client.exists(cid)

# Get file content directly
content = ipfs_client.cat(cid)

# Pin a file
success = ipfs_client.pin(cid)
```

### IPFS Connection Methods

The SDK provides robust connection handling for IPFS:

1. **RPC Connection (Default)**: Attempts to connect to the IPFS node via its RPC port (typically 5001) using the `ipfshttpclient` library.

2. **HTTP API Fallback**: If the RPC connection fails, the SDK automatically falls back to using the HTTP REST API (same approach as used in web browsers).

This dual approach ensures maximum compatibility across different environments. The fallback happens automatically, so you don't need to worry about it.

## Coming Soon

The following features are planned for future releases:

- Substrate blockchain integration for decentralized storage references
- Storage management and data availability guarantees
- Advanced metadata management and search
- Support for multi-part uploads of large files

## Development

```bash
# Clone the repository
git clone https://github.com/your-username/hippius-sdk.git
cd hippius-sdk

# Install dependencies
poetry install

# Run tests
poetry run pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
