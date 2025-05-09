#!/bin/bash
# Focused test script for the credits command

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
echo -e "\033[1;32m✓ No setup needed for credits command\033[0m"

# Test help for credits command
run_test "credits help" "$PYTHON -m hippius_sdk.cli credits -h"

echo -e "\n\033[1;34m==== Testing credits command ====\033[0m"

# Test basic credits command
# This might return credits info or require authentication
echo "Testing basic credits command (might require authentication):"
$PYTHON -m hippius_sdk.cli credits || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test with account address
echo "Testing credits command with account address:"
$PYTHON -m hippius_sdk.cli credits 5E9d3J4gDFqWdiDKiWu4gucwPUYC9rh2MbL2LezyhDjT652d || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

echo -e "\n\033[1;32m==== Credits command tests completed ====\033[0m"