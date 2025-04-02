# Hippius SDK

A Python SDK for interacting with Hippius blockchain storage, designed specifically for ML developers working with Bittensor.

## Features

- IPFS operations: Upload and download files to/from IPFS
- Multiple connection methods for IPFS (RPC or HTTP API)
- Human-readable formatting of file sizes and CIDs
- Simple and intuitive API for ML developers
- Substrate blockchain integration for decentralized storage references

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
print(f"File uploaded with CID: {result['cid']}")
print(f"File size: {result['size_formatted']}")

# Download a file from IPFS
dl_result = client.download_file(result['cid'], "path/to/save/model.pt")
print(f"Download successful in {dl_result['elapsed_seconds']} seconds")
print(f"File size: {dl_result['size_formatted']}")

# Check if a file exists
exists_result = client.exists(result['cid'])
print(f"File exists: {exists_result['exists']}")
print(f"Gateway URL: {exists_result['gateway_url']}")

# Get file content directly
content_result = client.cat(result['cid'])
if content_result['is_text']:
    print(f"Content preview: {content_result['text_preview']}")
else:
    print(f"Binary content (hex): {content_result['hex_preview']}")
print(f"Content size: {content_result['size_formatted']}")

# Pin a file to ensure it stays on the network
pin_result = client.pin(result['cid'])
print(f"Pinning successful: {pin_result['success']}")
print(f"Message: {pin_result['message']}")

# Format a CID for display
formatted_cid = client.format_cid(result['cid'])
print(f"Formatted CID: {formatted_cid}")

# Format file size for display
formatted_size = client.format_size(1024 * 1024)
print(f"Formatted size: {formatted_size}")  # Output: 1.00 MB
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
result = ipfs_client.upload_file("path/to/your/file.txt")
cid = result["cid"]
size = result["size_formatted"]

# Upload a directory
dir_result = ipfs_client.upload_directory("path/to/your/directory")
dir_cid = dir_result["cid"]
file_count = dir_result["file_count"]
total_size = dir_result["size_formatted"]

# Download a file
dl_result = ipfs_client.download_file(cid, "path/to/save/file.txt")
success = dl_result["success"]
elapsed_time = dl_result["elapsed_seconds"]

# Check if a CID exists
exists_result = ipfs_client.exists(cid)
exists = exists_result["exists"]
gateway_url = exists_result["gateway_url"]

# Get file content directly
content_result = ipfs_client.cat(cid)
content = content_result["content"]
is_text = content_result["is_text"]
preview = content_result["text_preview"] if is_text else content_result["hex_preview"]

# Pin a file
pin_result = ipfs_client.pin(cid)
success = pin_result["success"]
message = pin_result["message"]

# Format a CID
formatted_cid = ipfs_client.format_cid("6261666b7265696134...")  # Hex-encoded CID
# Will return a proper formatted CID like "bafkrei..."

# Format a file size
human_readable = ipfs_client.format_size(1048576)  # 1 MB
```

### IPFS Connection Methods

The SDK provides robust connection handling for IPFS:

1. **RPC Connection (Default)**: Attempts to connect to the IPFS node via its RPC port (typically 5001) using the `ipfshttpclient` library.

2. **HTTP API Fallback**: If the RPC connection fails, the SDK automatically falls back to using the HTTP REST API (same approach as used in web browsers).

This dual approach ensures maximum compatibility across different environments. The fallback happens automatically, so you don't need to worry about it.

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
