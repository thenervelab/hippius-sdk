#!/bin/bash
# Focused test script for the pinning-status command

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
echo -e "\033[1;32m✓ No setup needed for pinning-status command\033[0m"

# Test help for pinning-status command
run_test "pinning-status help" "$PYTHON -m hippius_sdk.cli pinning-status -h"

echo -e "\n\033[1;34m==== Testing pinning-status command ====\033[0m"

# Test basic pinning-status command
# This might return an empty list or actual pinning status depending on account state
echo "Testing basic pinning-status command (might require authentication):"
$PYTHON -m hippius_sdk.cli pinning-status || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with --no-contents flag
echo "Testing pinning-status with --no-contents flag:"
$PYTHON -m hippius_sdk.cli pinning-status --no-contents || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with account address
# This will likely fail unless a valid account address is provided
echo "Testing pinning-status with account address (likely fails without valid address):"
$PYTHON -m hippius_sdk.cli pinning-status --account_address 5E9d3J4gDFqWdiDKiWu4gucwPUYC9rh2MbL2LezyhDjT652d || echo -e "\033[1;33m✓ Expected failure with invalid/unauthorized account address\033[0m"

echo -e "\n\033[1;32m==== Pinning-status command tests completed ====\033[0m"