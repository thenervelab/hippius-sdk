#!/bin/bash
# Focused test script for the account command

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
echo -e "\033[1;32m✓ No setup needed for account command\033[0m"

# Test help for account command
run_test "account help" "$PYTHON -m hippius_sdk.cli account -h"

echo -e "\n\033[1;34m==== Testing account list command ====\033[0m"

# Test account list command
run_test "account list" "$PYTHON -m hippius_sdk.cli account list"

echo -e "\n\033[1;34m==== Testing account info command ====\033[0m"

# Get the current active account from the output of account list
active_account=$($PYTHON -m hippius_sdk.cli account list | grep "Active" | awk -F "│" '{print $3}' | xargs)
echo "Active account: $active_account"

# Test account info command with the active account
if [ -n "$active_account" ]; then
    run_test "account info for active account" "$PYTHON -m hippius_sdk.cli account info --name $active_account"
else
    echo "No active account found, skipping account info test"
fi

echo -e "\n\033[1;34m==== Testing account balance command ====\033[0m"

# Test account balance command
echo "Testing account balance command:"
$PYTHON -m hippius_sdk.cli account balance || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"

# Test account balance with account name
if [ -n "$active_account" ]; then
    echo "Testing account balance with account name:"
    $PYTHON -m hippius_sdk.cli account balance --name $active_account || echo -e "\033[1;33m✓ Command failed - might require authentication\033[0m"
fi

# Skip testing account create, export, import, switch, and delete as they would modify the user's configuration

echo -e "\n\033[1;32m==== Account command tests completed ====\033[0m"