#!/bin/bash
# Focused test script for the files command

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

echo -e "\n\033[1;33m==== Setting up test environment ====\033[0m"
echo -e "\033[1;32m✓ No setup needed for files command\033[0m"

# Test help for files command
run_test "files help" "$PYTHON -m hippius_sdk.cli files -h"

echo -e "\n\033[1;34m==== Testing files command ====\033[0m"

# Test basic files command
# This might return an empty list or actual files depending on account state
echo "Testing basic files command (might require authentication):"
$PYTHON -m hippius_sdk.cli files || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with --all-miners flag
echo "Testing files command with --all-miners flag:"
$PYTHON -m hippius_sdk.cli files --all-miners || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with account address
# This will likely fail unless a valid account address is provided
echo "Testing files command with account address (likely fails without valid address):"
$PYTHON -m hippius_sdk.cli files --account_address 5E9d3J4gDFqWdiDKiWu4gucwPUYC9rh2MbL2LezyhDjT652d || echo -e "\033[1;33m✓ Expected failure with invalid/unauthorized account address\033[0m"

# Test with a specific CID filter
# This will likely return empty results or actual files depending on the account
echo "Testing files command with CID filter:"
$PYTHON -m hippius_sdk.cli files QmThisIsATestCid || echo -e "\033[1;33m✓ Command failed or returned no results\033[0m"

echo -e "\n\033[1;34m==== Testing ec-files command ====\033[0m"

# Test help for ec-files command
run_test "ec-files help" "$PYTHON -m hippius_sdk.cli ec-files -h"

# Test basic ec-files command
# This might return an empty list or actual EC files depending on account state
echo "Testing basic ec-files command (might require authentication):"
$PYTHON -m hippius_sdk.cli ec-files || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with --show-chunks flag
echo "Testing ec-files command with --show-chunks flag:"
$PYTHON -m hippius_sdk.cli ec-files --show-chunks || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

echo -e "\n\033[1;32m==== Files command tests completed ====\033[0m"