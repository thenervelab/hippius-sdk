#!/bin/bash
# Test script focused on the store command

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
echo "This is test file 1" > test_file1.txt
echo "This is test file 2" > test_file2.txt
echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test store command help
run_test "store help" "$PYTHON -m hippius_sdk.cli store -h"

# Test store with different flags
run_test "store basic" "$PYTHON -m hippius_sdk.cli store test_file1.txt"
run_test "store with --no-encrypt (global flag)" "$PYTHON -m hippius_sdk.cli --no-encrypt store test_file2.txt"
run_test "store with --encrypt (global flag)" "$PYTHON -m hippius_sdk.cli --encrypt store test_file1.txt"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -f test_file1.txt test_file2.txt
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All tests completed successfully! ====\033[0m"