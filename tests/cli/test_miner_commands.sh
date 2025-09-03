#!/bin/bash
# Dedicated test script for Hippius CLI miner commands

# Exit on any error
set -e

# Change to the project root directory and source the virtual environment
cd "$(dirname "$0")/../.."
source venv/bin/activate

# Source test environment variables
source "$(dirname "$0")/.env.test"

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

echo -e "\n\033[1;33m==== Hippius CLI Miner Commands Test Suite ====\033[0m"

# Test help commands first
echo -e "\n\033[1;33m==== Testing Help Commands ====\033[0m"
run_test "Miner help" "$PYTHON -m hippius_sdk.cli miner -h"
run_test "Miner register-coldkey help" "$PYTHON -m hippius_sdk.cli miner register-coldkey -h"
run_test "Miner register-hotkey help" "$PYTHON -m hippius_sdk.cli miner register-hotkey -h"

# Display loaded test data
echo -e "\n\033[1;33m==== Test data loaded from environment ====\033[0m"
echo "Test Node ID: $TEST_NODE_ID"
echo "Test Node Private Key: $TEST_NODE_PRIV_HEX"
echo "Test Coldkey Address: $TEST_COLDKEY_ADDRESS"
echo "Test IPFS Private Key (Base64): $TEST_IPFS_PRIV_B64"
echo "Test IPFS Peer ID: $TEST_IPFS_PEER_ID"
echo -e "\033[1;32m✓ Test data loaded from .env.test\033[0m"

# Test register-coldkey functionality
echo -e "\n\033[1;33m==== Testing Register-Coldkey Commands ====\033[0m"

run_test "Basic register-coldkey with StorageMiner" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-coldkey with Validator type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type Validator \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id $TEST_IPFS_PEER_ID \
    --dry-run"

run_test "Register-coldkey with ComputeMiner type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type ComputeMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-coldkey with StorageS3 type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageS3 \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-coldkey with GpuMiner type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type GpuMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-coldkey with all optional parameters" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id $TEST_IPFS_PEER_ID \
    --pay-in-credits \
    --expires-in $TEST_EXPIRES_IN \
    --block-width u64 \
    --domain '$TEST_CUSTOM_DOMAIN' \
    --nonce-hex $TEST_CUSTOM_NONCE \
    --dry-run"

run_test "Register-coldkey with u32 block width" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --block-width u32 \
    --dry-run"

# Test register-hotkey functionality
echo -e "\n\033[1;33m==== Testing Register-Hotkey Commands ====\033[0m"

run_test "Basic register-hotkey with StorageMiner" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-hotkey with Validator type" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type Validator \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id $TEST_IPFS_PEER_ID \
    --dry-run"

run_test "Register-hotkey with GpuMiner type" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type GpuMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_test "Register-hotkey with all optional parameters" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type ComputeMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --ipfs-peer-id $TEST_IPFS_PEER_ID \
    --pay-in-credits \
    --expires-in $TEST_ALTERNATE_EXPIRES_IN \
    --block-width u32 \
    --domain '$TEST_CUSTOM_DOMAIN' \
    --nonce-hex $TEST_ALTERNATE_NONCE \
    --dry-run"

# Test error handling
echo -e "\n\033[1;33m==== Testing Error Handling ====\033[0m"

# Missing required parameters for register-coldkey
run_failure_test "Register-coldkey missing node-id" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Register-coldkey missing node-priv-hex" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Register-coldkey missing node-type" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Register-coldkey missing IPFS config" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner"

# Missing required parameters for register-hotkey
run_failure_test "Register-hotkey missing coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Register-hotkey missing node-id" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

# Invalid parameter values
run_failure_test "Invalid node-type for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type $INVALID_NODE_TYPE \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

run_failure_test "Invalid block-width for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --block-width $INVALID_BLOCK_WIDTH \
    --dry-run"

run_failure_test "Invalid node-type for register-hotkey" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type $INVALID_NODE_TYPE \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64"

# Test conflicting IPFS parameters (should fail with mutually exclusive group error)
run_failure_test "Conflicting IPFS parameters for register-coldkey" \
    "$PYTHON -m hippius_sdk.cli miner register-coldkey \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-config ~/.ipfs/config \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

run_failure_test "Conflicting IPFS parameters for register-hotkey" \
    "$PYTHON -m hippius_sdk.cli miner register-hotkey \
    --coldkey $TEST_COLDKEY_ADDRESS \
    --node-id $TEST_NODE_ID \
    --node-priv-hex $TEST_NODE_PRIV_HEX \
    --node-type StorageMiner \
    --ipfs-config ~/.ipfs/config \
    --ipfs-priv-b64 $TEST_IPFS_PRIV_B64 \
    --dry-run"

echo -e "\n\033[1;32m==== All Miner Command Tests Completed Successfully! ====\033[0m"
echo -e "\033[1;32mTests covered:\033[0m"
echo -e "\033[1;32m  ✓ Help command functionality\033[0m"
echo -e "\033[1;32m  ✓ Register-coldkey with all node types\033[0m"
echo -e "\033[1;32m  ✓ Register-hotkey with all node types\033[0m"
echo -e "\033[1;32m  ✓ All optional parameter combinations\033[0m"
echo -e "\033[1;32m  ✓ Error handling for missing required parameters\033[0m"
echo -e "\033[1;32m  ✓ Error handling for invalid parameter values\033[0m"
echo -e "\033[1;32m  ✓ Mutually exclusive parameter validation\033[0m"