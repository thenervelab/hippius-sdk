#!/bin/bash
# Focused test script for the keygen command

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
echo -e "\033[1;32m✓ No setup needed for keygen command\033[0m"

# Test help for keygen command
run_test "keygen help" "$PYTHON -m hippius_sdk.cli keygen -h"

echo -e "\n\033[1;34m==== Testing keygen command ====\033[0m"

# Test basic keygen without saving
run_test "Basic keygen" "$PYTHON -m hippius_sdk.cli keygen"

# Verify the key format
echo -e "\nVerifying encryption key format (should be base64 encoded, 32-bytes when decoded)..."
# Extract key after "Your encryption key:" line
KEY=$($PYTHON -m hippius_sdk.cli keygen | grep -A1 "Your encryption key:" | tail -1 | xargs)

if [[ $KEY =~ ^[A-Za-z0-9+/]{42,44}[=]{0,2}$ ]]; then
    echo -e "\033[1;32m✓ Key format looks valid (base64-encoded 32-byte key)\033[0m"
else
    echo -e "\033[1;31m✗ Key format doesn't match expected pattern\033[0m"
    echo "Key: $KEY"
    exit 1
fi

# Test keygen with save option (will save to config)
# We'll redirect the output because we don't want to overwrite any existing key in the real config
echo -e "\nSkipping test for --save option to avoid modifying user's config"

echo -e "\n\033[1;32m==== All keygen command tests completed successfully! ====\033[0m"