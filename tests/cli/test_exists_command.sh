#!/bin/bash
# Focused test script for the exists command

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

# Create a test file
echo "This is a test file" > test_file.txt

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test help for exists command
run_test "exists help" "$PYTHON -m hippius_sdk.cli exists -h"

# Upload test file to get CID
echo -e "\n\033[1;33m==== Uploading test file to get CID ====\033[0m"

# Upload a regular file and get its CID
FILE_CID=$($PYTHON -m hippius_sdk.cli store test_file.txt --no-publish | grep -o 'IPFS CID: [^ ]*' | cut -d' ' -f3)
echo "Uploaded file CID: $FILE_CID"

echo -e "\n\033[1;34m==== Testing exists command ====\033[0m"

# Test exists with a valid CID
run_test "Check valid CID exists" "$PYTHON -m hippius_sdk.cli exists $FILE_CID"

# Test exists with a non-existent CID
echo -e "\n\033[1;34m==== Testing error handling ====\033[0m"
echo "Testing exists with a non-existent CID (expecting an error):"
# Using || for failure case which is expected
$PYTHON -m hippius_sdk.cli exists QmThisIsNotARealCID || echo -e "\033[1;32m✓ Expected error correctly handled\033[0m"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -f test_file.txt
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All exists command tests completed successfully! ====\033[0m"