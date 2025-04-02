# Test Upload Directory

This directory contains sample files for testing the IPFS upload functionality of the Hippius SDK.

## Contents

- `test_file1.txt`: A simple text file
- `sample.json`: A JSON file with test data
- `nested/`: A directory containing nested files
  - `test_file2.txt`: A text file in a nested directory

## Usage

You can use this directory to test directory uploads with the Hippius SDK test script:

```bash
python test_hippius.py upload-dir test_upload
```

This should upload the entire directory structure to IPFS and return a CID that points to the directory. 