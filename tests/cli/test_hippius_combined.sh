#!/bin/bash
# Comprehensive test script for Hippius CLI with focus on store-dir and encryption flags

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

echo -e "\033[1;32m✓ Test environment created\033[0m"

echo -e "\n\033[1;34m==== Testing basic CLI functionality ====\033[0m"

# Test help commands
run_test "Main help" "$PYTHON -m hippius_sdk.cli -h"
run_test "store-dir help" "$PYTHON -m hippius_sdk.cli store-dir -h"
run_test "store help" "$PYTHON -m hippius_sdk.cli store -h"

echo -e "\n\033[1;34m==== Testing store-dir command with --no-publish flag ====\033[0m"

# Test store-dir with different flags
run_test "store-dir basic" "$PYTHON -m hippius_sdk.cli store-dir test_dir"
run_test "store-dir with --no-publish" "$PYTHON -m hippius_sdk.cli store-dir test_dir --no-publish"
run_test "store-dir with --publish" "$PYTHON -m hippius_sdk.cli store-dir test_dir --publish"

echo -e "\n\033[1;34m==== Testing global encryption flags ====\033[0m"

# Test global encryption flags with store
run_test "store with --no-encrypt" "$PYTHON -m hippius_sdk.cli --no-encrypt store test_file.txt"
run_test "store with --encrypt" "$PYTHON -m hippius_sdk.cli --encrypt store test_file.txt"

# Test global encryption flags with store-dir
run_test "store-dir with --encrypt" "$PYTHON -m hippius_sdk.cli --encrypt store-dir test_dir"
run_test "store-dir with --no-encrypt" "$PYTHON -m hippius_sdk.cli --no-encrypt store-dir test_dir"

echo -e "\n\033[1;34m==== Testing combined flags ====\033[0m"

# Test combinations of flags
run_test "store-dir with --no-publish and --encrypt" "$PYTHON -m hippius_sdk.cli --encrypt store-dir test_dir --no-publish"
run_test "store-dir with --no-publish and --no-encrypt" "$PYTHON -m hippius_sdk.cli --no-encrypt store-dir test_dir --no-publish"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_dir
rm -f test_file.txt
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All tests completed successfully! ====\033[0m"