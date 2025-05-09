#!/bin/bash
# Master test script that runs all individual command test scripts

# Exit on any error
set -e

# Change to the project root directory and source the virtual environment
cd "$(dirname "$0")/../.."
source venv/bin/activate
# Ensure we're using Python 3
PYTHON="python3"
# Function to run a test script and check its exit code
run_test_script() {
    local script="$1"
    local script_name=$(basename "$script")
    
    echo -e "\n\033[1;34m====================================================\033[0m"
    echo -e "\033[1;34m==== Running test script: $script_name ====\033[0m"
    echo -e "\033[1;34m====================================================\033[0m"
    
    # Run the script
    bash "$script"
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo -e "\n\033[1;32m✓ Test script $script_name passed\033[0m"
    else
        echo -e "\n\033[1;31m✗ Test script $script_name failed with exit code $exit_code\033[0m"
        exit $exit_code
    fi
}

echo -e "\n\033[1;33m==== Starting all test scripts ====\033[0m"

# Run all test scripts
test_scripts=(
    "test_account_command.sh"
    "test_address_command.sh"
    "test_cat_command.sh" 
    "test_config_command.sh"
    "test_credits_command.sh"
    "test_download_command.sh"
    "test_erasure_delete.sh"
    "test_exists_command.sh"
    "test_files_command.sh"
    "test_keygen_command.sh"
    "test_pinning_status.sh"
    "test_seed_command.sh"
    "test_store_dir.sh"
    "test_store.sh"
)

# Counters for statistics
total_scripts=${#test_scripts[@]}
passed_scripts=0
failed_scripts=0
failed_script_names=()

# Define the script directory
SCRIPT_DIR="$(dirname "$0")"

# Loop through each test script
for script in "${test_scripts[@]}"; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        echo -e "\n\033[1;34mRunning $script...\033[0m"

        # Run the script but don't exit on error
        bash "$SCRIPT_DIR/$script"
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo -e "\033[1;32m✓ $script passed\033[0m"
            ((passed_scripts++))
        else
            echo -e "\033[1;31m✗ $script failed with exit code $exit_code\033[0m"
            ((failed_scripts++))
            failed_script_names+=("$script")
        fi
    else
        echo -e "\033[1;33m⚠ $script not found, skipping...\033[0m"
    fi
done

# Print summary
echo -e "\n\033[1;33m==== Test Summary ====\033[0m"
echo -e "Total scripts: $total_scripts"
echo -e "Passed: $passed_scripts"
echo -e "Failed: $failed_scripts"

if [ $failed_scripts -gt 0 ]; then
    echo -e "\n\033[1;31mThe following scripts failed:\033[0m"
    for script in "${failed_script_names[@]}"; do
        echo -e "- $script"
    done
    echo -e "\n\033[1;31m==== Some tests failed! ====\033[0m"
    exit 1
else
    echo -e "\n\033[1;32m==== All tests passed successfully! ====\033[0m"
fi