#!/bin/bash
# Test script for erasure-code and delete commands

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

# Create test files
echo -e "\n\033[1;33m==== Setting up test environment ====\033[0m"

# Create various test files
echo "This is a simple text file" > test_file.txt
dd if=/dev/urandom of=test_binary_small.bin bs=1024 count=4
mkdir -p downloads
mkdir -p reconstruct_dir

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test erasure-code help
run_test "erasure-code help" "$PYTHON -m hippius_sdk.cli erasure-code -h"

# Test delete help  
run_test "delete help" "$PYTHON -m hippius_sdk.cli delete -h"

# Test ec-delete help
run_test "ec-delete help" "$PYTHON -m hippius_sdk.cli ec-delete -h"

echo -e "\n\033[1;33m==== Testing erasure-code command ====\033[0m"

# Test erasure-code with no-publish flag (should not require password)
run_test "erasure-code with --no-publish" "$PYTHON -m hippius_sdk.cli erasure-code test_binary_small.bin --no-publish --k 2 --m 3"

# Get the metadata CID from erasure coding output
METADATA_CID=$($PYTHON -m hippius_sdk.cli erasure-code test_binary_small.bin --no-publish --k 2 --m 3 | grep -o 'Metadata CID: [^ ]*' | cut -d' ' -f3)
echo "Erasure-code metadata CID: $METADATA_CID"

# Test uploading a text file
run_test "Upload text file" "$PYTHON -m hippius_sdk.cli store test_file.txt --no-publish"
FILE_CID=$($PYTHON -m hippius_sdk.cli store test_file.txt --no-publish | grep -o 'IPFS CID: [^ ]*' | cut -d' ' -f3)
echo "Uploaded file CID: $FILE_CID"

echo -e "\n\033[1;33m==== Testing reconstruction from erasure-coded file ====\033[0m"

# Test reconstruct command
run_test "Reconstruct erasure-coded file" "$PYTHON -m hippius_sdk.cli reconstruct $METADATA_CID downloads/reconstructed.bin"

# Verify the reconstructed file exists and has content
if [ -f "downloads/reconstructed.bin" ]; then
    if [ -s "downloads/reconstructed.bin" ]; then
        echo -e "\033[1;32m✓ Reconstructed file exists and has content\033[0m"
        
        # Compare file size with original
        ORIG_SIZE=$(stat -f%z test_binary_small.bin)
        RECON_SIZE=$(stat -f%z downloads/reconstructed.bin)
        if [ "$ORIG_SIZE" -eq "$RECON_SIZE" ]; then
            echo -e "\033[1;32m✓ Reconstructed file has the same size as original\033[0m"
        else
            echo -e "\033[1;31m✗ File size mismatch: Original=$ORIG_SIZE, Reconstructed=$RECON_SIZE\033[0m"
        fi
    else
        echo -e "\033[1;31m✗ Reconstructed file exists but is empty\033[0m"
    fi
else
    echo -e "\033[1;31m✗ Reconstructed file does not exist\033[0m"
fi

echo -e "\n\033[1;33m==== Testing delete command ====\033[0m"

# Test delete command with force flag
run_test "Delete file with --force" "$PYTHON -m hippius_sdk.cli delete $FILE_CID --force"

# Test if deleted file no longer exists (may still exist in cache)
echo "Checking if deleted file still exists..."
$PYTHON -m hippius_sdk.cli exists $FILE_CID || echo -e "\033[1;32m✓ File was successfully deleted\033[0m"

echo -e "\n\033[1;33m==== Testing ec-delete command ====\033[0m"

# Test ec-delete command with force flag
run_test "EC-Delete metadata file with --force" "$PYTHON -m hippius_sdk.cli ec-delete $METADATA_CID --force"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_file.txt test_binary_small.bin downloads reconstruct_dir
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All erasure-code and delete tests completed successfully! ====\033[0m"