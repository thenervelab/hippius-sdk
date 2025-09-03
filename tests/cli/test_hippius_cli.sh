#!/bin/bash
# Comprehensive test script for Hippius CLI functionality

# Exit on any error
set -e

# Change to the project root directory and source the virtual environment
cd "$(dirname "$0")/../.."
source venv/bin/activate

# Source test environment variables
source "$(dirname "$0")/cli/.env.test"

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
mkdir -p test_files/nested_dir
echo "This is test file 1" > test_files/test1.txt
echo "This is test file 2" > test_files/test2.txt
echo "This is a nested file" > test_files/nested_dir/nested_file.txt

# Create a small binary file for erasure coding tests
dd if=/dev/urandom of=test_files/small_binary.bin bs=1024 count=512

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Run basic help tests
run_test "Main help" "$PYTHON -m hippius_sdk.cli -h"
run_test "Download help" "$PYTHON -m hippius_sdk.cli download -h"
run_test "Store help" "$PYTHON -m hippius_sdk.cli store -h"
run_test "Store-dir help" "$PYTHON -m hippius_sdk.cli store-dir -h"
run_test "Erasure-code help" "$PYTHON -m hippius_sdk.cli erasure-code -h"

# Test miner command help
run_test "Miner help" "$PYTHON -m hippius_sdk.cli miner -h"
run_test "Miner register-coldkey help" "$PYTHON -m hippius_sdk.cli miner register-coldkey -h"
run_test "Miner register-hotkey help" "$PYTHON -m hippius_sdk.cli miner register-hotkey -h"
run_test "Miner verify-node help" "$PYTHON -m hippius_sdk.cli miner verify-node -h"
run_test "Miner verify-coldkey-node help" "$PYTHON -m hippius_sdk.cli miner verify-coldkey-node -h"

# Test configuration commands
run_test "Config list" "$PYTHON -m hippius_sdk.cli config list"

# Test store command with different flags
run_test "Store file" "$PYTHON -m hippius_sdk.cli store test_files/test1.txt"
run_test "Store file with no-encrypt" "$PYTHON -m hippius_sdk.cli store test_files/test2.txt --no-encrypt"

# Test store-dir command with different flags
run_test "Store directory" "$PYTHON -m hippius_sdk.cli store-dir test_files"
run_test "Store directory with no-publish" "$PYTHON -m hippius_sdk.cli store-dir test_files --no-publish"
run_test "Store directory with publish flag" "$PYTHON -m hippius_sdk.cli store-dir test_files --publish"

# Test erasure coding with different parameters
run_test "Erasure code with default parameters" "$PYTHON -m hippius_sdk.cli erasure-code test_files/small_binary.bin"
run_test "Erasure code with custom k,m" "$PYTHON -m hippius_sdk.cli erasure-code test_files/small_binary.bin --k 2 --m 3"
run_test "Erasure code with no-publish" "$PYTHON -m hippius_sdk.cli erasure-code test_files/small_binary.bin --no-publish"
run_test "Erasure code with custom chunk size" "$PYTHON -m hippius_sdk.cli erasure-code test_files/small_binary.bin --chunk-size 1"

# Test miner registration commands (dry-run mode to avoid actual blockchain transactions)
echo -e "\n\033[1;33m==== Testing Miner Registration Commands (Dry Run) ====\033[0m"
echo "Using test data from environment variables:"
echo "  Node ID: $TEST_NODE_ID"
echo "  Coldkey: $TEST_COLDKEY_ADDRESS"

# Test register-coldkey with various parameter combinations
run_test "Miner register-coldkey dry-run with ipfs-priv-b64" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Miner register-coldkey dry-run with all optional params" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type ComputeMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id 12D3KooWBhzNWgT7Wt1KqvBcGjDnZ8XkF4FzGJkNS2bTnWJzBq4Q \
    --pay-in-credits \
    --expires-in 20 \
    --block-width u64 \
    --domain 'TEST::REGISTER::v1' \
    --nonce-hex 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
    --dry-run"

run_test "Miner register-coldkey dry-run Validator type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type Validator \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id 12D3KooWBhzNWgT7Wt1KqvBcGjDnZ8XkF4FzGJkNS2bTnWJzBq4Q \
    --dry-run"

# Test register-hotkey with various parameter combinations
run_test "Miner register-hotkey dry-run with ipfs-priv-b64" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Miner register-hotkey dry-run with all optional params" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type GpuMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id 12D3KooWBhzNWgT7Wt1KqvBcGjDnZ8XkF4FzGJkNS2bTnWJzBq4Q \
    --pay-in-credits \
    --expires-in 15 \
    --block-width u32 \
    --domain 'CUSTOM::REGISTER::v2' \
    --dry-run"

run_test "Miner register-hotkey dry-run StorageS3 type" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageS3 \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

# Test error handling - missing required parameters
echo -e "\n\033[1;33m==== Testing Miner Command Error Handling ====\033[0m"

# Function to test command failure (expecting exit code 2 for argument errors)
run_failure_test() {
    local description="$1"
    local command="$2"
    
    echo -e "\n\033[1;34m==== Testing Error: $description ====\033[0m"
    echo "Command: $command"
    
    # Run the command and expect it to fail
    eval "$command" 2>/dev/null
    local exit_code=$?
    
    if [ $exit_code -eq 2 ] || [ $exit_code -eq 1 ]; then
        echo -e "\033[1;32m✓ Test passed (correctly failed with exit code $exit_code)\033[0m"
    else
        echo -e "\033[1;31m✗ Test failed: expected failure but got exit code $exit_code\033[0m"
        exit 1
    fi
}

# Test missing required arguments
run_failure_test "Missing node-id for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey --node-priv-hex $TEST_NODE_PRIV_HEX --node-type StorageMiner --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Missing node-type for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey --node-id $TEST_NODE_ID --node-priv-hex $TEST_NODE_PRIV_HEX --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Missing ipfs config for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey --node-id $TEST_NODE_ID --node-priv-hex $TEST_NODE_PRIV_HEX --node-type StorageMiner"

run_failure_test "Missing coldkey for register-hotkey" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey --node-id $TEST_NODE_ID --node-priv-hex $TEST_NODE_PRIV_HEX --node-type StorageMiner --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Invalid node-type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey --node-id $TEST_NODE_ID --node-priv-hex $TEST_NODE_PRIV_HEX --node-type InvalidType --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Invalid block-width" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey --node-id $TEST_NODE_ID --node-priv-hex $TEST_NODE_PRIV_HEX --node-type StorageMiner --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 --block-width u128 --dry-run"

echo -e "\n\033[1;32m✓ All miner command tests completed successfully!\033[0m"

# Test exists command
# Note: We need a valid CID for this test
# This will use the CID from the first store command
run_test "Check file exists" "$PYTHON -m hippius_sdk.cli exists \$($PYTHON -m hippius_sdk.cli store test_files/test1.txt | grep -o 'CID: [^ ]*' | cut -d' ' -f2)"

# Test combination of flags
run_test "Store with combined flags" "$PYTHON -m hippius_sdk.cli store test_files/test1.txt --no-encrypt --verbose"
run_test "Store-dir with combined flags" "$PYTHON -m hippius_sdk.cli store-dir test_files --no-publish --verbose"

# Test with local IPFS if available
if [[ -n "$(which ipfs)" ]]; then
    run_test "Store with local IPFS" "$PYTHON -m hippius_sdk.cli store test_files/test1.txt --local-ipfs"
fi

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_files
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All tests completed successfully! ====\033[0m"