#!/bin/bash
# Focused test script for the download command

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

# Create test download directories
mkdir -p downloads/file
mkdir -p downloads/dir

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test help for download command
run_test "download help" "$PYTHON -m hippius_sdk.cli download -h"

# Upload test files to get CIDs
echo -e "\n\033[1;33m==== Uploading test files to get CIDs ====\033[0m"

# Upload a regular file and get its CID
FILE_CID=$($PYTHON -m hippius_sdk.cli store test_file.txt | grep -o 'CID: [^ ]*' | cut -d' ' -f2)
echo "Uploaded file CID: $FILE_CID"

# Upload a directory and get its CID
DIR_CID=$($PYTHON -m hippius_sdk.cli store-dir test_dir | grep -o 'Directory CID: [^ ]*' | cut -d' ' -f3)
echo "Uploaded directory CID: $DIR_CID"

echo -e "\n\033[1;34m==== Testing download command ====\033[0m"

# Test basic file download
run_test "Basic file download" "$PYTHON -m hippius_sdk.cli download $FILE_CID downloads/file/downloaded_file.txt"

# Check if the downloaded file matches the original
echo -e "\nVerifying downloaded file content..."
ORIGINAL=$(cat test_file.txt)
DOWNLOADED=$(cat downloads/file/downloaded_file.txt)
if [ "$ORIGINAL" = "$DOWNLOADED" ]; then
    echo -e "\033[1;32m✓ Downloaded file content matches original\033[0m"
else
    echo -e "\033[1;31m✗ Downloaded file content does not match original\033[0m"
    echo "Original: $ORIGINAL"
    echo "Downloaded: $DOWNLOADED"
    exit 1
fi

# Test directory download
run_test "Directory download" "$PYTHON -m hippius_sdk.cli download $DIR_CID downloads/dir/"

# Check if directory structure is preserved
echo -e "\nVerifying directory structure..."
if [ -f "downloads/dir/test1.txt" ] && [ -f "downloads/dir/test2.txt" ] && [ -f "downloads/dir/nested_dir/nested_file.txt" ]; then
    echo -e "\033[1;32m✓ Directory structure preserved\033[0m"
    
    # Verify content of one of the files in the directory
    ORIGINAL=$(cat test_dir/test1.txt)
    DOWNLOADED=$(cat downloads/dir/test1.txt)
    if [ "$ORIGINAL" = "$DOWNLOADED" ]; then
        echo -e "\033[1;32m✓ Downloaded directory file content matches original\033[0m"
    else
        echo -e "\033[1;31m✗ Downloaded directory file content does not match original\033[0m"
        exit 1
    fi
else
    echo -e "\033[1;31m✗ Directory structure not preserved\033[0m"
    ls -la downloads/dir/
    exit 1
fi

# Test downloading to a non-existent directory (should create it)
run_test "Download to new directory" "$PYTHON -m hippius_sdk.cli download $FILE_CID downloads/new_dir/new_file.txt"

# Test downloading a non-existent CID
echo -e "\n\033[1;34m==== Testing error handling ====\033[0m"
echo "Testing download of a non-existent CID (expecting an error):"
$PYTHON -m hippius_sdk.cli download QmThisIsNotARealCID downloads/file/nonexistent.txt || echo -e "\033[1;32m✓ Expected error correctly handled\033[0m"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_dir test_file.txt downloads
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All download command tests completed successfully! ====\033[0m"