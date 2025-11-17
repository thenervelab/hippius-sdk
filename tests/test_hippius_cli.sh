#!/bin/bash
# Hippius CLI E2E Test Suite
# Tests basic CLI functionality and exit codes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Get script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source "$PROJECT_ROOT/.venv/bin/activate"

# Test data directory
TEST_DATA_DIR="$SCRIPT_DIR/test_cli_data"
mkdir -p "$TEST_DATA_DIR"

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}Cleaning up test data...${NC}"
    rm -rf "$TEST_DATA_DIR"
}
trap cleanup EXIT

# Helper function to run a test
run_test() {
    local test_name="$1"
    local expected_exit_code="${2:-0}"
    shift 2
    local cmd=("$@")

    TESTS_RUN=$((TESTS_RUN + 1))

    echo -e "\n${YELLOW}[TEST $TESTS_RUN]${NC} $test_name"
    echo -e "${BLUE}Command:${NC} ${cmd[*]}"

    set +e
    "${cmd[@]}" > /dev/null 2>&1
    actual_exit_code=$?
    set -e

    if [ $actual_exit_code -eq $expected_exit_code ]; then
        echo -e "${GREEN}✓ PASSED${NC} (exit code: $actual_exit_code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} (expected: $expected_exit_code, got: $actual_exit_code)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Create test files
create_test_data() {
    echo -e "${BLUE}Creating test data...${NC}"

    echo "This is a small test file for CLI tests" > "$TEST_DATA_DIR/small_file.txt"

    dd if=/dev/urandom of="$TEST_DATA_DIR/medium_file.bin" bs=1024 count=1024 2>/dev/null

    mkdir -p "$TEST_DATA_DIR/test_directory"
    echo "File 1" > "$TEST_DATA_DIR/test_directory/file1.txt"
    echo "File 2" > "$TEST_DATA_DIR/test_directory/file2.txt"
    echo "File 3" > "$TEST_DATA_DIR/test_directory/file3.txt"

    echo -e "${GREEN}Test data created${NC}"
}

# Test categories
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Hippius CLI E2E Test Suite${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

create_test_data

# 1. Help and Info Commands
echo -e "\n${BLUE}═══ 1. Help and Info Commands ═══${NC}"

run_test "Main help with -h" 0 python -m hippius_sdk.cli -h
run_test "Main help with --help" 0 python -m hippius_sdk.cli --help
run_test "Main help with no command" 1 python -m hippius_sdk.cli
run_test "Config help" 0 python -m hippius_sdk.cli config -h
run_test "Account help" 0 python -m hippius_sdk.cli account -h
run_test "Address help" 0 python -m hippius_sdk.cli address -h
run_test "Miner help" 0 python -m hippius_sdk.cli miner -h
run_test "Download help" 0 python -m hippius_sdk.cli download -h
run_test "Store help" 0 python -m hippius_sdk.cli store -h
run_test "Erasure-code help" 0 python -m hippius_sdk.cli erasure-code -h

# 2. Config Management
echo -e "\n${BLUE}═══ 2. Config Management ═══${NC}"

run_test "List all configuration" 0 python -m hippius_sdk.cli config list
run_test "Get specific config value" 0 python -m hippius_sdk.cli config get ipfs gateway
run_test "Set config value" 0 python -m hippius_sdk.cli config set test test_key test_value
run_test "Get previously set value" 0 python -m hippius_sdk.cli config get test test_key

# 3. Key Generation
echo -e "\n${BLUE}═══ 3. Key Generation ═══${NC}"

run_test "Generate encryption key" 0 python -m hippius_sdk.cli keygen

# 4. Account Management (basic commands that don't require account)
echo -e "\n${BLUE}═══ 4. Account Management ═══${NC}"

run_test "List accounts" 0 python -m hippius_sdk.cli account list

# 5. Address Management
echo -e "\n${BLUE}═══ 5. Address Management ═══${NC}"

# Note: get-default may return 0 or 1 depending on whether address is set
# We'll just accept any exit code by not running this test for now
# run_test "Get default address (may not be set)" python -m hippius_sdk.cli address get-default
run_test "Clear default address" 0 python -m hippius_sdk.cli address clear-default

# 6. Invalid Commands (should fail with exit code 2 - argparse standard)
echo -e "\n${BLUE}═══ 6. Invalid Commands ═══${NC}"

run_test "Invalid command" 2 python -m hippius_sdk.cli invalid-command
run_test "Store without arguments" 2 python -m hippius_sdk.cli store
run_test "Download without arguments" 2 python -m hippius_sdk.cli download
run_test "Erasure-code without arguments" 2 python -m hippius_sdk.cli erasure-code

# Tests that require IPFS node (skip if not available)
echo -e "\n${BLUE}═══ 7. IPFS Operations (requires IPFS and credentials) ═══${NC}"

if [ -n "$HIPPIUS_KEY" ] && [ -n "$IPFS_NODE_URL" ]; then
    echo -e "${GREEN}HIPPIUS_KEY and IPFS_NODE_URL found, running IPFS tests${NC}"

    run_test "Check if known CID exists" python -m hippius_sdk.cli exists QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG

    run_test "Store small file" python -m hippius_sdk.cli store "$TEST_DATA_DIR/small_file.txt"

    run_test "List files" 0 python -m hippius_sdk.cli files

    run_test "Check credits" 0 python -m hippius_sdk.cli credits

else
    echo -e "${YELLOW}⊘ Skipping IPFS tests (HIPPIUS_KEY or IPFS_NODE_URL not set)${NC}"
fi

# Print summary
echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Test Summary${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "Total tests run:    ${BLUE}$TESTS_RUN${NC}"
echo -e "Tests passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed:       ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}\n"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}\n"
    exit 1
fi
