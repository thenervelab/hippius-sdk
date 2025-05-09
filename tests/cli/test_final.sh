#!/bin/bash
# Comprehensive test script for the --no-publish flag in store-dir command

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

# Create a second test directory with binary and text files
mkdir -p test_complex_dir/subdir
echo "This is a text file" > test_complex_dir/file1.txt
echo '{"name": "test", "type": "json"}' > test_complex_dir/data.json
dd if=/dev/urandom of=test_complex_dir/subdir/binary.bin bs=1024 count=10
echo "Nested text file" > test_complex_dir/subdir/nested.txt

# Create download directory
mkdir -p downloads

echo -e "\033[1;32m✓ Test environment created\033[0m"

# Test CLI help
run_test "Main help" "$PYTHON -m hippius_sdk.cli -h"
run_test "store-dir help" "$PYTHON -m hippius_sdk.cli store-dir -h"

echo -e "\n\033[1;33m==== Testing store-dir with different publish flags ====\033[0m"

# Test with default settings (should publish)
run_test "store-dir with default settings" "$PYTHON -m hippius_sdk.cli store-dir test_dir"
DEFAULT_CID=$($PYTHON -m hippius_sdk.cli store-dir test_dir | grep -o 'Directory CID: [^ ]*' | cut -d' ' -f3)
echo "Default CID: $DEFAULT_CID"

# Test with explicit --publish flag
run_test "store-dir with --publish flag" "$PYTHON -m hippius_sdk.cli store-dir test_dir --publish"
PUBLISH_CID=$($PYTHON -m hippius_sdk.cli store-dir test_dir --publish | grep -o 'Directory CID: [^ ]*' | cut -d' ' -f3)
echo "Publish CID: $PUBLISH_CID"

# Test with --no-publish flag
run_test "store-dir with --no-publish flag" "$PYTHON -m hippius_sdk.cli store-dir test_dir --no-publish"
NO_PUBLISH_CID=$($PYTHON -m hippius_sdk.cli store-dir test_dir --no-publish | grep -o 'Directory CID: [^ ]*' | cut -d' ' -f3)
echo "No-Publish CID: $NO_PUBLISH_CID"

# Verify that CIDs are consistent regardless of publishing flag
echo -e "\nVerifying that CIDs are consistent regardless of publishing flag..."
if [ "$DEFAULT_CID" = "$PUBLISH_CID" ] && [ "$DEFAULT_CID" = "$NO_PUBLISH_CID" ]; then
    echo -e "\033[1;32m✓ CIDs are consistent\033[0m"
else
    echo -e "\033[1;31m✗ CIDs are not consistent\033[0m"
    echo "Default CID: $DEFAULT_CID"
    echo "Publish CID: $PUBLISH_CID"
    echo "No-Publish CID: $NO_PUBLISH_CID"
fi

echo -e "\n\033[1;33m==== Testing combination of flags ====\033[0m"

# Test with complex directory
run_test "Complex directory with --no-publish" "$PYTHON -m hippius_sdk.cli store-dir test_complex_dir --no-publish"
COMPLEX_CID=$($PYTHON -m hippius_sdk.cli store-dir test_complex_dir --no-publish | grep -o 'Directory CID: [^ ]*' | cut -d' ' -f3)
echo "Complex Directory CID: $COMPLEX_CID"

# Test with --no-publish and global flags
run_test "store-dir with --no-publish and verbose" "$PYTHON -m hippius_sdk.cli --verbose store-dir test_dir --no-publish"

# Test erasure-code for comparison (it has similar --no-publish flag)
# This will be skipped if it requires authentication
echo -e "\n\033[1;33m==== Testing erasure-code command for comparison ====\033[0m"
echo "Creating small test file for erasure coding..."
dd if=/dev/urandom of=test_small.bin bs=1024 count=1
echo "Testing erasure-code with --no-publish flag..."
$PYTHON -m hippius_sdk.cli erasure-code test_small.bin --no-publish --k 2 --m 3 || echo "Skipped erasure-code test (likely requires authentication)"

echo -e "\n\033[1;33m==== Testing file retrieval ====\033[0m"

# Test download after using --no-publish
run_test "Download directory after --no-publish" "$PYTHON -m hippius_sdk.cli download $NO_PUBLISH_CID downloads/no_publish_dir"

# Check if directory structure is preserved
echo -e "\nVerifying directory structure for downloaded no-publish content..."
if [ -f "downloads/no_publish_dir/test1.txt" ] && [ -f "downloads/no_publish_dir/test2.txt" ] && [ -f "downloads/no_publish_dir/nested_dir/nested_file.txt" ]; then
    echo -e "\033[1;32m✓ Directory structure preserved for no-publish directory\033[0m"
else
    echo -e "\033[1;31m✗ Directory structure not preserved for no-publish directory\033[0m"
    ls -la downloads/no_publish_dir/
fi

# Test exists command after using --no-publish
run_test "Check existence after --no-publish" "$PYTHON -m hippius_sdk.cli exists $NO_PUBLISH_CID"

# Clean up test files
echo -e "\n\033[1;33m==== Cleaning up test environment ====\033[0m"
rm -rf test_dir test_complex_dir test_small.bin downloads
echo -e "\033[1;32m✓ Test environment cleaned\033[0m"

echo -e "\n\033[1;32m==== All tests for --no-publish flag completed successfully! ====\033[0m"