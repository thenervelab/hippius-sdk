# Hippius

A Python SDK and CLI for interacting with Hippius blockchain storage, designed specifically for ML developers working with Bittensor.

## Features

- IPFS operations: Upload and download files to/from IPFS
- Multiple connection methods for IPFS (RPC or HTTP API)
- Human-readable formatting of file sizes and CIDs
- Simple and intuitive API for ML developers
- Substrate blockchain integration for decentralized storage references
- End-to-end encryption for secure file storage and retrieval
- Built-in CLI tools for encryption key generation

## Installation

```bash
# Using pip
pip install hippius

# Using Poetry
poetry add hippius

# With clipboard support for encryption key utility
poetry add hippius -E clipboard
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

## Encryption Support

Hippius SDK supports end-to-end encryption for secure file storage and retrieval using the NaCl (libsodium) cryptography library.

### Generating an Encryption Key

```bash
# After installing the SDK, you can use the built-in command-line tool:
hippius-keygen

# Generate and copy to clipboard (requires pyperclip)
hippius-keygen --copy
```

### Setting Up Encryption

The SDK can be configured to use encryption in several ways:

1. Through environment variables (recommended for development):
   ```
   # In your .env file
   HIPPIUS_ENCRYPTION_KEY=your-base64-encoded-key
   HIPPIUS_ENCRYPT_BY_DEFAULT=true
   ```

2. Directly in code:
   ```python
   import base64
   from hippius_sdk import HippiusClient
   
   # Decode the base64 key
   encryption_key = base64.b64decode("your-base64-encoded-key")
   
   # Initialize client with encryption enabled
   client = HippiusClient(
       encrypt_by_default=True,
       encryption_key=encryption_key
   )
   
   # Or generate a new key programmatically
   encoded_key = client.generate_encryption_key()
   print(f"Generated key: {encoded_key}")
   ```

### Using Encryption

Once configured, encryption works transparently:

```python
# Upload with encryption (uses default setting)
result = client.upload_file("sensitive_data.txt")

# Explicitly enable/disable encryption for a specific operation
encrypted_result = client.upload_file("sensitive_data.txt", encrypt=True)
unencrypted_result = client.upload_file("public_data.txt", encrypt=False)

# Download and decrypt automatically
dl_result = client.download_file(encrypted_result['cid'], "decrypted_file.txt")

# Explicitly control decryption
decrypted_result = client.download_file(encrypted_result['cid'], "output.txt", decrypt=True)
raw_result = client.download_file(encrypted_result['cid'], "still_encrypted.txt", decrypt=False)

# View encrypted content
content = client.cat(encrypted_result['cid'], decrypt=True)
```

## Erasure Coding

Hippius SDK supports Reed-Solomon erasure coding for reliable and resilient file storage. This allows files to be split into chunks with added redundancy, so that the original file can be reconstructed even if some chunks are lost.

### Erasure Coding Concepts

- **k**: The number of data chunks needed to reconstruct the original file
- **m**: The total number of chunks created (m > k)
- The file can be reconstructed from any k chunks out of m total chunks
- Higher redundancy (m-k) provides better protection against chunk loss

### Using Erasure Coding

```python
from hippius_sdk import HippiusClient

client = HippiusClient()

# Erasure code a file with default parameters (k=3, m=5)
result = client.erasure_code_file("large_file.mp4")
metadata_cid = result["metadata_cid"]

# Use custom parameters for more redundancy
result = client.erasure_code_file(
    file_path="important_data.zip",
    k=4,               # Need 4 chunks to reconstruct
    m=10,              # Create 10 chunks total (6 redundant)
    chunk_size=2097152,  # 2MB chunks
    encrypt=True       # Encrypt before splitting
)

# Store erasure-coded file in Hippius marketplace
result = client.store_erasure_coded_file(
    file_path="critical_backup.tar",
    k=3,
    m=5,
    encrypt=True,
    miner_ids=["miner1", "miner2", "miner3"]
)

# Reconstruct a file from its metadata
reconstructed_path = client.reconstruct_from_erasure_code(
    metadata_cid=metadata_cid,
    output_file="reconstructed_file.mp4"
)
```

### When to Use Erasure Coding

Erasure coding is particularly useful for:

- Large files where reliability is critical
- Long-term archival storage
- Data that must survive partial network failures
- Situations where higher redundancy is needed without full replication

### Advanced Features

#### Small File Handling

The SDK automatically adjusts parameters for small files:

- If a file is too small to be split into `k` chunks, the SDK will adjust the chunk size
- For very small files, the content is split into exactly `k` sub-blocks
- Parameters are always optimized to provide the requested level of redundancy

#### Robust Storage in Marketplace

When using `store_erasure_coded_file`, the SDK now:

- Stores both the metadata file AND all encoded chunks in the marketplace
- Ensures miners can access all necessary data for redundancy and retrieval
- Reports total number of files stored for verification

#### CLI Commands

The CLI provides powerful commands for erasure coding:

```bash
# Basic usage with automatic parameter adjustment
hippius erasure-code myfile.txt

# Specify custom parameters
hippius erasure-code large_video.mp4 --k 4 --m 8 --chunk-size 4194304

# For smaller files, using smaller parameters
hippius erasure-code small_doc.txt --k 2 --m 5 --chunk-size 4096

# Reconstruct a file from its metadata CID
hippius reconstruct QmMetadataCID reconstructed_file.mp4
```

The CLI provides detailed output during the process, including:
- Automatic parameter adjustments for optimal encoding
- Progress of chunk creation and upload
- Storage confirmation in the marketplace
- Instructions for reconstruction

## Command Line Interface

The Hippius SDK includes a powerful command-line interface (CLI) that provides access to all major features of the SDK directly from your terminal.

### Basic Usage

```bash
# Get help and list available commands
hippius --help

# Set global options
hippius --gateway https://ipfs.io --api-url https://relay-fr.hippius.network --verbose
```

### IPFS Operations

```bash
# Download a file from IPFS
hippius download QmCID123 output_file.txt

# Check if a CID exists
hippius exists QmCID123

# Display file content
hippius cat QmCID123

# Store a file on IPFS and Hippius Marketplace
hippius store my_file.txt

# Store a directory on IPFS and Hippius Marketplace
hippius store-dir ./my_directory
```

### Account Operations

```bash
# Check available credits for an account
hippius credits

# Check credits for a specific account
hippius credits 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH

# View files stored by an account
hippius files

# View files for a specific account
hippius files 5H1QBRF7T7dgKwzVGCgS4wioudvMRf9K4NEDzfuKLnuyBNzH

# Show all miners for each file
hippius files --all-miners
```

### Encryption

```bash
# Generate an encryption key
hippius keygen

# Generate and copy to clipboard
hippius keygen --copy

# Upload with encryption
hippius store my_file.txt --encrypt

# Download and decrypt
hippius download QmCID123 output_file.txt --decrypt
```

### Erasure Coding

```bash
# Erasure code a file with default parameters (k=3, m=5)
hippius erasure-code large_file.mp4

# Erasure code with custom parameters
hippius erasure-code important_data.zip --k 4 --m 10 --chunk-size 2097152 --encrypt

# Reconstruct a file from its metadata
hippius reconstruct QmMetadataCID reconstructed_file.mp4
```

### Using Environment Variables

The CLI automatically reads from your `.env` file for common settings:

```
IPFS_GATEWAY=https://ipfs.io
IPFS_API_URL=https://relay-fr.hippius.network
SUBSTRATE_URL=wss://rpc.hippius.network
SUBSTRATE_SEED_PHRASE="your twelve word seed phrase..."
SUBSTRATE_DEFAULT_MINERS=miner1,miner2,miner3
HIPPIUS_ENCRYPTION_KEY=your-base64-encoded-key
HIPPIUS_ENCRYPT_BY_DEFAULT=true|false
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

# With encryption and clipboard support
poetry install -E clipboard

# Run tests
poetry run pytest
```

## Testing Locally

You can test Hippius locally during development or before publishing to PyPI. Here's how to test both the SDK and CLI components:

### 1. Install in Development Mode

The easiest way to test everything together is to install the package in development mode:

```bash
# In the root directory of the project
poetry install

# With encryption and clipboard support
poetry install -E clipboard
```

This makes both the SDK and CLI available while still allowing you to make changes to the code.

### 2. Testing the CLI

After installing in development mode, you can run the CLI commands directly:

```bash
# Basic commands
hippius --help
hippius download QmCID123 output_file.txt
hippius keygen

# To see what commands would do without actually running them, add --verbose
hippius --verbose store myfile.txt
```

If you want to test CLI changes without reinstalling the package:

```bash
# Run the CLI module directly
python -m hippius_sdk.cli download QmCID123 output_file.txt

# Or make it executable and run it directly
chmod +x hippius_sdk/cli.py
./hippius_sdk/cli.py download QmCID123 output_file.txt
```

### 3. Testing the SDK

To test the SDK components, you can create a small test script:

```python
# test_script.py
from hippius_sdk import HippiusClient
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Create a client
client = HippiusClient()

# Test a simple operation
print("Testing IPFS client...")
try:
    result = client.exists("QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx")
    print(f"Result: {result}")
except Exception as e:
    print(f"Error: {e}")
```

Then run it:

```bash
python test_script.py
```

### 4. Running Unit Tests

You can use pytest to run the test suite:

```bash
# Run all tests
poetry run pytest

# Run specific tests
poetry run pytest tests/test_ipfs.py

# Run a specific test function
poetry run pytest tests/test_ipfs.py::test_upload_file
```

### 5. Building and Testing the Package

If you want to test the exact package that will be uploaded to PyPI:

```bash
# Build the package
poetry build

# Install the built package in a virtual environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate
pip install dist/hippius-0.1.0-py3-none-any.whl

# Test the installed package
hippius --help
```

### Troubleshooting Local Testing

1. **IPFS Connection Issues**: Make sure you have either:
   - A local IPFS daemon running (`ipfs daemon` in a separate terminal)
   - Or proper environment variables set in `.env` for remote connections

2. **Missing Dependencies**: If you get import errors, ensure all dependencies are installed:
   ```bash
   poetry install --all-extras
   ```

3. **CLI Not Found**: If the `hippius` command isn't found after installing, try:
   ```bash
   # Verify it's installed
   poetry show hippius
   
   # Check your PATH
   which hippius
   ```

4. **Substrate Issues**: For marketplace operations, make sure your `.env` has the correct `SUBSTRATE_SEED_PHRASE` and `SUBSTRATE_URL` values.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
