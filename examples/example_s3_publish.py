#!/usr/bin/env python3
"""
Test script for s3_publish and s3_download methods with timing
"""

import asyncio
import os
import subprocess
import time
from datetime import datetime

from hippius_sdk.client import HippiusClient
from hippius_sdk.ipfs import S3PublishResult, S3DownloadResult

import dotenv

dotenv.load_dotenv("../.env")


def generate_test_file(size_mb=2000):
    """Generate a test file using dd command"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"s3_download_{timestamp}.bin"

    print(f"🔧 Generating {size_mb}MB test file: {filename}")
    print("   This may take a few minutes...")

    start_time = time.time()

    # Use dd to generate random data
    cmd = ["dd", "if=/dev/urandom", f"of={filename}", "bs=1M", f"count={size_mb}"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    generation_time = time.time() - start_time

    if result.returncode != 0:
        print(f"❌ Failed to generate test file: {result.stderr}")
        return None

    file_size = os.path.getsize(filename)
    print(
        f"✅ Generated {filename} ({file_size / 1024 / 1024:.1f} MB) in {generation_time:.1f}s"
    )

    return filename


async def s3_publish_download_test():
    print("\n🔒 Testing s3_publish with encryption and s3_download with timing")
    print("📊 Using 2GB test file for realistic performance testing")

    # Generate test file
    test_file = generate_test_file(2000)  # 2000 MB = ~2GB
    if not test_file:
        print("❌ Failed to generate test file, aborting")
        return

    encrypted_file = test_file.replace(".bin", "_encrypted.bin")
    downloaded_file = test_file.replace(".bin", "_downloaded.bin")

    # Copy the file for encryption
    import shutil

    shutil.copy2(test_file, encrypted_file)
    print(f"📋 Created copy for encryption: {encrypted_file}")

    client = HippiusClient()

    seed_phrase = os.environ["HIPPIUS_SUBACCOUNT_PHRASE"]
    subaccount_id = os.environ["HIPPIUS_SUBACCOUNT_ID"]
    bucket_name = test_file.split(".")[0]

    try:
        # Upload with timing
        print("🔐 Publishing with encryption...")
        upload_start = time.time()

        result: S3PublishResult = await client.s3_publish(
            file_path=encrypted_file,
            encrypt=True,
            seed_phrase=seed_phrase,
            subaccount_id=subaccount_id,
            bucket_name=bucket_name,
            file_name="example_s3_publish",
            publish=False,
        )

        upload_time = time.time() - upload_start

        print("✅ UPLOAD SUCCESS!")
        print(f"   📦 CID: {result.cid}")
        print(f"   📄 File: {result.file_name}")
        print(f"   📏 Size: {result.size_bytes} bytes")
        print(f"   ⏱️  Upload Time: {upload_time:.2f} seconds")
        print(
            f"   🔐 Encryption Key: {result.encryption_key[:16] if result.encryption_key else None}..."
        )
        print(f"   🧾 Transaction: {result.tx_hash}")

        # Clean up downloaded file if it exists
        if os.path.exists(downloaded_file):
            os.remove(downloaded_file)

        # Download with timing
        print(f"\n📥 Downloading and decrypting to {downloaded_file}...")
        download_start = time.time()

        download_result: S3DownloadResult = await client.s3_download(
            cid=result.cid,
            output_path=downloaded_file,
            subaccount_id=subaccount_id,
            bucket_name=bucket_name,
            auto_decrypt=True,
        )

        download_time = time.time() - download_start

        print("✅ DOWNLOAD SUCCESS!")
        print(f"   📦 CID: {download_result.cid}")
        print(f"   📄 Output: {download_result.output_path}")
        print(f"   📏 Size: {download_result.size_bytes} bytes")
        print(f"   📏 Formatted Size: {download_result.size_formatted}")
        print(f"   ⏱️  Download Time: {download_time:.2f} seconds")
        print(f"   ⏱️  SDK Reported Time: {download_result.elapsed_seconds:.2f} seconds")
        print(f"   🔓 Decrypted: {download_result.decrypted}")

        # Performance comparison
        print("\n⚡ PERFORMANCE COMPARISON:")
        print(
            f"   📤 Upload: {upload_time:.2f}s ({result.size_bytes / 1024 / upload_time:.1f} KB/s)"
        )
        print(
            f"   📥 Download: {download_time:.2f}s ({download_result.size_bytes / 1024 / download_time:.1f} KB/s)"
        )

        if upload_time > 0 and download_time > 0:
            ratio = upload_time / download_time
            if ratio > 1:
                print(f"   🏃 Download is {ratio:.1f}x faster than upload")
            else:
                print(f"   🐌 Upload is {1 / ratio:.1f}x faster than download")

        # Verify files are identical (using hash comparison for large files)
        if os.path.exists(test_file) and os.path.exists(downloaded_file):
            print("\n🔍 Verifying file integrity...")
            import hashlib

            def file_hash(filepath):
                hash_sha256 = hashlib.sha256()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hash_sha256.update(chunk)
                return hash_sha256.hexdigest()

            original_hash = file_hash(test_file)
            downloaded_hash = file_hash(downloaded_file)

            if original_hash == downloaded_hash:
                print(
                    "   ✅ File integrity verified - original and downloaded files are identical!"
                )
            else:
                print("   ❌ File integrity check failed - files differ!")
                print(f"      Original hash:  {original_hash}")
                print(f"      Downloaded hash: {downloaded_hash}")

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # Clean up test files
        print("\n🧹 Cleaning up test files...")
        files_to_cleanup = [test_file, encrypted_file, downloaded_file]

        for file_path in files_to_cleanup:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"   🗑️  Deleted: {file_path}")
                except Exception as e:
                    print(f"   ⚠️  Could not delete {file_path}: {e}")

        print("✨ Cleanup completed!")


if __name__ == "__main__":
    asyncio.run(s3_publish_download_test())

    print("\n✨ Tests completed!")
