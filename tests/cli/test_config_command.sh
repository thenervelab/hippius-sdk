#!/bin/bash
# Focused test script for the config command

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
echo -e "\033[1;32m✓ No setup needed for config command\033[0m"

# Test help for config command
run_test "config help" "$PYTHON -m hippius_sdk.cli config -h"

echo -e "\n\033[1;34m==== Testing config list command ====\033[0m"

# Test config list command
run_test "config list" "$PYTHON -m hippius_sdk.cli config list"

echo -e "\n\033[1;34m==== Testing config get command ====\033[0m"

# Test config get for various sections
run_test "config get ipfs gateway" "$PYTHON -m hippius_sdk.cli config get ipfs gateway"
run_test "config get ipfs api_url" "$PYTHON -m hippius_sdk.cli config get ipfs api_url"

# Test getting config values from another section
run_test "config get substrate url" "$PYTHON -m hippius_sdk.cli config get substrate url"
run_test "config get encryption encrypt_by_default" "$PYTHON -m hippius_sdk.cli config get encryption encrypt_by_default"

# Skip testing config set as it would modify the user's configuration

echo -e "\n\033[1;32m==== Config command tests completed ====\033[0m"