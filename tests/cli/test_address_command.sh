#!/bin/bash
# Focused test script for the address command

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
echo -e "\033[1;32m✓ No setup needed for address command\033[0m"

# Test help for address command
run_test "address help" "$PYTHON -m hippius_sdk.cli address -h"

echo -e "\n\033[1;34m==== Testing address get-default command ====\033[0m"

# Test address get-default command
run_test "address get-default" "$PYTHON -m hippius_sdk.cli address get-default"

# Skip testing set-default and clear-default as they would modify the user's configuration

echo -e "\n\033[1;32m==== Address command tests completed ====\033[0m"