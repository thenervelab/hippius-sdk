#!/bin/bash
# Focused test script for the cat command

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

# Create test files of different types
echo "This is a small text file for testing" > small_text.txt
echo '{"name": "John", "age": 30, "city": "New York"}' > json_file.json

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test help for cat command
run_test "cat help" "$PYTHON -m hippius_sdk.cli cat -h"

# Upload test files to get CIDs
echo -e "\n\033[1;33m==== Uploading test files to get CIDs ====\033[0m"

# Upload the text file and get its CID
TEXT_CID=$($PYTHON -m hippius_sdk.cli store small_text.txt | grep -o 'CID: [^ ]*' | cut -d' ' -f2)
echo "Uploaded text file CID: $TEXT_CID"

# Upload the JSON file and get its CID
JSON_CID=$($PYTHON -m hippius_sdk.cli store json_file.json | grep -o 'CID: [^ ]*' | cut -d' ' -f2)
echo "Uploaded JSON file CID: $JSON_CID"

echo -e "\n\033[1;34m==== Testing cat command ====\033[0m"

# Test cat with a valid text CID
run_test "Cat text file" "$PYTHON -m hippius_sdk.cli cat $TEXT_CID"

# Test cat with a JSON file
run_test "Cat JSON file" "$PYTHON -m hippius_sdk.cli cat $JSON_CID"

# Test cat with max size limit
run_test "Cat with max size limit" "$PYTHON -m hippius_sdk.cli cat $TEXT_CID --max-size 10"

# Test cat with a non-existent CID
echo -e "\n\033[1;34m==== Testing error handling ====\033[0m"
echo "Testing cat with a non-existent CID (expecting an error):"
$PYTHON -m hippius_sdk.cli cat QmThisIsNotARealCID || echo -e "\033[1;32m✓ Expected error correctly handled\033[0m"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -f small_text.txt json_file.json
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All cat command tests completed successfully! ====\033[0m"