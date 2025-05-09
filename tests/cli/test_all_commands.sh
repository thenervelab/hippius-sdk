#!/bin/bash
# Comprehensive test script for all major Hippius CLI commands

# Exit on any error
set -e

# Change to the project root directory and source the virtual environment
cd "$(dirname "$0")/../.."
source venv/bin/activate
# Ensure we're using Python 3
PYTHON="python3"
# Function to run a command and check its exit code
run_test() {
    local description="$1"
    local command="$2"
    
    echo -e "\n\033[1;34m==== Testing: $description ====\033[0m"
    echo "Command: $command"
    
    # Run the command
    eval "$command"
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo -e "\033[1;32m✓ Test passed\033[0m"
    else
        echo -e "\033[1;31m✗ Test failed with exit code $exit_code\033[0m"
        exit $exit_code
    fi
}

# Create test directories and files
echo -e "\n\033[1;33m==== Setting up test environment ====\033[0m"

# Create a test directory with multiple files
mkdir -p test_dir/nested_dir
echo "This is test file 1" > test_dir/test1.txt
echo "This is test file 2" > test_dir/test2.txt
echo "This is a nested file" > test_dir/nested_dir/nested_file.txt

# Create a separate test file
echo "This is a standalone file" > test_file.txt

# Create a small binary file for erasure coding tests
dd if=/dev/urandom of=test_binary.bin bs=1024 count=64

echo -e "\033[1;32m✓ Test environment created\033[0m"

echo -e "\n\033[1;34m==== Testing help commands ====\033[0m"

# Test help for all major commands
run_test "Main help" "$PYTHON -m hippius_sdk.cli -h"
run_test "download help" "$PYTHON -m hippius_sdk.cli download -h"
run_test "exists help" "$PYTHON -m hippius_sdk.cli exists -h"
run_test "cat help" "$PYTHON -m hippius_sdk.cli cat -h"
run_test "store help" "$PYTHON -m hippius_sdk.cli store -h"
run_test "store-dir help" "$PYTHON -m hippius_sdk.cli store-dir -h"
run_test "pinning-status help" "$PYTHON -m hippius_sdk.cli pinning-status -h"
run_test "delete help" "$PYTHON -m hippius_sdk.cli delete -h"
run_test "keygen help" "$PYTHON -m hippius_sdk.cli keygen -h"
run_test "credits help" "$PYTHON -m hippius_sdk.cli credits -h"
run_test "files help" "$PYTHON -m hippius_sdk.cli files -h"
run_test "ec-files help" "$PYTHON -m hippius_sdk.cli ec-files -h"
run_test "ec-delete help" "$PYTHON -m hippius_sdk.cli ec-delete -h"
run_test "erasure-code help" "$PYTHON -m hippius_sdk.cli erasure-code -h"
run_test "reconstruct help" "$PYTHON -m hippius_sdk.cli reconstruct -h"
run_test "config help" "$PYTHON -m hippius_sdk.cli config -h"
run_test "seed help" "$PYTHON -m hippius_sdk.cli seed -h"
run_test "account help" "$PYTHON -m hippius_sdk.cli account -h"
run_test "address help" "$PYTHON -m hippius_sdk.cli address -h"

echo -e "\n\033[1;34m==== Testing basic operations ====\033[0m"

# Test store command
run_test "store file" "$PYTHON -m hippius_sdk.cli store test_file.txt"

# Use the CID from the store command to test other commands
CID=$($PYTHON -m hippius_sdk.cli store test_file.txt | grep -o 'CID: [^ ]*' | cut -d' ' -f2)
echo "Stored file CID: $CID"

# Test exists command
run_test "exists command" "$PYTHON -m hippius_sdk.cli exists $CID"

# Test cat command
run_test "cat command" "$PYTHON -m hippius_sdk.cli cat $CID"

# Test download command
mkdir -p test_download
run_test "download command" "$PYTHON -m hippius_sdk.cli download $CID test_download/downloaded_file.txt"

echo -e "\n\033[1;34m==== Testing store-dir command ====\033[0m"

# Test store-dir with different flags
run_test "store-dir basic" "$PYTHON -m hippius_sdk.cli store-dir test_dir"
run_test "store-dir with --no-publish" "$PYTHON -m hippius_sdk.cli store-dir test_dir --no-publish"
run_test "store-dir with --publish" "$PYTHON -m hippius_sdk.cli store-dir test_dir --publish"

echo -e "\n\033[1;34m==== Testing erasure coding ====\033[0m"

# Test erasure coding with different parameters
run_test "erasure-code basic" "$PYTHON -m hippius_sdk.cli erasure-code test_binary.bin --k 2 --m 3"
run_test "erasure-code with --no-publish" "$PYTHON -m hippius_sdk.cli erasure-code test_binary.bin --k 2 --m 3 --no-publish"

# Get the metadata CID from the erasure-code command
METADATA_CID=$($PYTHON -m hippius_sdk.cli erasure-code test_binary.bin --k 2 --m 3 | grep -o 'Metadata CID: [^ ]*' | cut -d' ' -f3)
echo "Erasure-coded file metadata CID: $METADATA_CID"

# Test reconstruct command
run_test "reconstruct command" "$PYTHON -m hippius_sdk.cli reconstruct $METADATA_CID test_download/reconstructed_file.bin"

echo -e "\n\033[1;34m==== Testing configuration ====\033[0m"

# Test config commands
run_test "config list" "$PYTHON -m hippius_sdk.cli config list"
run_test "config get" "$PYTHON -m hippius_sdk.cli config get ipfs gateway"

echo -e "\n\033[1;34m==== Testing encryption ====\033[0m"

# Test global encryption flags with store
run_test "store with --no-encrypt" "$PYTHON -m hippius_sdk.cli --no-encrypt store test_file.txt"
run_test "store with --encrypt" "$PYTHON -m hippius_sdk.cli --encrypt store test_file.txt"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_dir
rm -f test_file.txt test_binary.bin
rm -rf test_download

echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All tests completed successfully! ====\033[0m"