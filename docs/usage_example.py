"""
Example usage of the Hippius SDK.

This example demonstrates how to use the Hippius SDK to upload and download files from IPFS.
"""

import os
import shutil
from hippius_sdk import HippiusClient

# Configuration
IPFS_GATEWAY = "https://ipfs.io"  # Public IPFS gateway for downloads
IPFS_API_URL = "https://relay-fr.hippius.network"  # Hippius relay node for uploads

# Initialize the client
client = HippiusClient(
    ipfs_gateway=IPFS_GATEWAY,
    ipfs_api_url=IPFS_API_URL,
)

def upload_model_example():
    """Example of uploading an ML model to IPFS."""
    # In a real scenario, this would be your trained model file
    model_file = "example_model.pt"
    
    # Create a dummy file for this example
    with open(model_file, "w") as f:
        f.write("This is a dummy ML model for demonstration purposes.")
    
    try:
        print(f"Uploading model: {model_file}")
        
        # Upload the model to IPFS
        result = client.upload_file(file_path=model_file)
        
        cid = result["cid"]
        filename = result["filename"]
        size_bytes = result["size_bytes"]
        
        print(f"Model uploaded successfully!")
        print(f"CID: {cid}")
        print(f"Filename: {filename}")
        print(f"Size: {size_bytes} bytes")
        
        return cid
    
    finally:
        # Clean up the dummy file
        if os.path.exists(model_file):
            os.remove(model_file)

def download_model_example(cid):
    """Example of downloading a model from IPFS."""
    output_path = "downloaded_model.pt"
    
    try:
        print(f"Downloading model with CID: {cid}")
        
        # Download the file
        client.download_file(cid, output_path)
        
        print(f"Model downloaded successfully to: {output_path}")
        
        # Display the content (in a real scenario, you would load the model)
        with open(output_path, "r") as f:
            content = f.read()
            print(f"Model content: {content}")
        
    finally:
        # Clean up downloaded file
        if os.path.exists(output_path):
            os.remove(output_path)

def upload_dataset_example():
    """Example of uploading a dataset directory to IPFS."""
    dataset_dir = "example_dataset"
    
    # Create a dummy dataset directory for this example
    os.makedirs(dataset_dir, exist_ok=True)
    
    try:
        # Create some dummy files in the dataset directory
        with open(os.path.join(dataset_dir, "train.csv"), "w") as f:
            f.write("id,feature1,feature2,label\n1,0.1,0.2,0\n2,0.3,0.4,1\n")
        
        with open(os.path.join(dataset_dir, "test.csv"), "w") as f:
            f.write("id,feature1,feature2\n3,0.5,0.6\n4,0.7,0.8\n")
        
        with open(os.path.join(dataset_dir, "metadata.json"), "w") as f:
            f.write('{"name": "example_dataset", "version": "1.0.0", "features": ["feature1", "feature2"]}')
        
        print(f"Uploading dataset directory: {dataset_dir}")
        
        # Upload the directory to IPFS
        result = client.upload_directory(dir_path=dataset_dir)
        
        cid = result["cid"]
        dirname = result["dirname"]
        
        print(f"Dataset uploaded successfully!")
        print(f"CID: {cid}")
        print(f"Directory name: {dirname}")
        
        return cid
    
    finally:
        # Clean up the dummy directory
        if os.path.exists(dataset_dir):
            shutil.rmtree(dataset_dir)

def check_file_exists_example(cid):
    """Example of checking if a file exists on IPFS."""
    exists = client.exists(cid)
    print(f"CID {cid} exists on IPFS: {exists}")
    
    # Check a non-existent CID
    fake_cid = "QmThisIsNotARealCIDForTestingPurposes123456789"
    exists = client.exists(fake_cid)
    print(f"CID {fake_cid} exists on IPFS: {exists}")

def main():
    """Run the examples."""
    print("=== Hippius SDK Usage Example ===")
    
    # Upload a model
    model_cid = upload_model_example()
    print("\n")
    
    # Download the model
    download_model_example(model_cid)
    print("\n")
    
    # Upload a dataset
    dataset_cid = upload_dataset_example()
    print("\n")
    
    # Check if files exist
    check_file_exists_example(model_cid)
    print("\n")
    
    # Note: You can also pin CIDs to ensure they remain available
    # success = client.pin(model_cid)
    # print(f"Pinned {model_cid}: {success}")

if __name__ == "__main__":
    main() 