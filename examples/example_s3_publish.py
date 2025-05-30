#!/usr/bin/env python3
"""
Test script for s3_publish method
"""

import asyncio
import os

from hippius_sdk.client import HippiusClient
from hippius_sdk.ipfs import S3PublishResult


async def s3_encrypted():
    print("\n🔒 Testing s3_publish with encryption")

    # Create a copy for encryption test
    original_file = "test_file.txt"
    encrypted_file = "test_file_encrypted.txt"

    if not os.path.exists(original_file):
        print(f"❌ Original file {original_file} not found!")
        return

    # Copy the file
    import shutil

    shutil.copy2(original_file, encrypted_file)
    print(f"📋 Created copy: {encrypted_file}")

    client = HippiusClient()

    seed_phrase = input("Enter your raw seed phrase:\n").strip()

    try:
        print("🔐 Publishing with encryption...")

        result: S3PublishResult = await client.s3_publish(
            file_path=encrypted_file, encrypt=True, seed_phrase=seed_phrase
        )

        print("✅ SUCCESS!")
        print(f"   📦 CID: {result.cid}")
        print(f"   📄 File: {result.file_name}")
        print(f"   📏 Size: {result.size_bytes} bytes")
        print(
            f"   🔐 Encryption Key: {result.encryption_key[:16] if result.encryption_key else None}..."
        )
        print(f"   🧾 Transaction: {result.tx_hash}")
        print(f"   ⚠️  File {encrypted_file} is now encrypted!")

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(s3_encrypted())

    print("\n✨ Tests completed!")
