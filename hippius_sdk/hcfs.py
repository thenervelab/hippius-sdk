"""
HCFS (Hippius Confidential File System) integration.

Thin async wrapper around the hcfs_client PyO3 bindings.
Provides client-side encryption for file uploads/downloads via the HCFS protocol.

Upload model: persistent drive directory at ~/.hippius/drive/.
Files are copied into the drive dir and synced to the server via Drive.sync().
Downloads go through HcfsClient.download() directly.
"""

import asyncio
import hashlib
import logging
import os
import shutil
from typing import Optional

from hcfs_client import Drive, HcfsClient, HcfsClientConfig

logger = logging.getLogger(__name__)

# Default drive directory — sync root for HCFS files
DEFAULT_DRIVE_DIR = os.path.join(os.path.expanduser("~"), ".hippius", "drive")

# Per-account drives base directory
DRIVES_BASE_DIR = os.path.join(os.path.expanduser("~"), ".hippius", "drives")


def get_drive_dir(account_name: str) -> str:
    """Return the per-account drive directory: ~/.hippius/drives/<account_name>/"""
    return os.path.join(DRIVES_BASE_DIR, account_name)


# Metadata subdirectory within the drive dir (where enc_mnemonic.json etc. live)
HCFS_METADATA_SUBDIR = ".hippius"


class HcfsManager:
    """
    Manages HCFS encryption operations — init, upload, download, delete.

    Upload: copies file into the drive directory, then syncs.
    Download: uses HcfsClient.download() directly.
    Delete: removes file from drive directory, then syncs.
    """

    def __init__(
        self,
        drive_dir: str = DEFAULT_DRIVE_DIR,
        base_url: str = "https://arion.hippius.com",
        api_key: str = "",
        bearer_token: str = "",
        account_ss58: str = "",
        accept_invalid_certs: bool = False,
    ):
        self._drive_dir = drive_dir
        folder_hash = (
            hashlib.blake2b(account_ss58.encode(), digest_size=8).hexdigest()
            if account_ss58
            else ""
        )
        self._config = HcfsClientConfig(
            base_url,
            api_key,
            bearer_token,
            account_ss58,
            folder_hash,
            accept_invalid_certs=accept_invalid_certs,
        )
        self._drive = Drive(drive_dir)
        logger.debug(
            "HcfsManager init: drive_dir=%s base_url=%s account=%s token=%s",
            drive_dir,
            base_url,
            account_ss58,
            bearer_token[:8] + "..." if len(bearer_token) > 8 else bearer_token,
        )

    def is_initialized(self) -> bool:
        """Check if HCFS encryption has been initialized."""
        return self._drive.is_initialized()

    def init(self, password: str, existing_mnemonic: Optional[str] = None) -> str:
        """
        Initialize HCFS encryption.

        Generates or recovers a BIP-39 mnemonic, encrypts it with the password,
        and stores it in the drive directory.

        Returns the 24-word mnemonic phrase (caller should display for backup).
        """
        return self._drive.init(password, existing_mnemonic)

    def _configure_and_sync(self, password: str):
        """Configure drive, persist config, unlock, and sync."""
        self._drive.set_config(self._config)
        self._config.save(self._drive_dir)
        self._drive.unlock(password)
        self._drive.sync()

    async def upload(self, file_path: str, password: str) -> dict:
        """
        Encrypt and upload a file to the HCFS server.

        Copies the file into the drive directory, then syncs.
        Returns dict with file_id and size_bytes.
        """
        os.makedirs(self._drive_dir, exist_ok=True)
        dest = os.path.join(self._drive_dir, os.path.basename(file_path))
        shutil.copy2(file_path, dest)
        file_size = os.path.getsize(dest)

        def _sync():
            # Stage first to discover the file_id for the new file
            logger.debug("HCFS upload: staging drive at %s", self._drive_dir)
            plan, _, _, _, path_index = self._drive.stage()
            logger.debug(
                "HCFS upload: stage result uploads=%s path_index=%s",
                plan.uploads,
                path_index,
            )

            # Reverse-lookup: find the file_id for our file
            basename = os.path.basename(file_path)
            file_id = None
            for fid, path in path_index.items():
                if os.path.basename(path) == basename:
                    file_id = fid
                    break

            logger.debug("HCFS upload: configuring and syncing (file_id=%s)", file_id)
            self._configure_and_sync(password)
            logger.debug("HCFS upload: sync complete")

            return file_id

        file_id = await asyncio.to_thread(_sync)

        return {
            "file_id": file_id or os.path.basename(file_path),
            "size_bytes": file_size,
        }

    async def download(
        self, user_id: str, file_id: str, output_path: str, password: str
    ):
        """Download and decrypt a file from the HCFS server."""

        def _download():
            logger.debug(
                "HCFS download: user=%s file=%s output=%s",
                user_id,
                file_id,
                output_path,
            )
            client = HcfsClient(self._config)
            client.download(user_id, self._config.folder_hash, file_id, output_path)
            logger.debug("HCFS download: complete")

        await asyncio.to_thread(_download)

    async def delete(self, user_id: str, file_id: str, password: str):
        """Delete a file from the HCFS server by removing it from drive and syncing."""

        def _delete():
            # Stage to find the local path for this file_id
            logger.debug("HCFS delete: file_id=%s", file_id)
            plan, _, _, _, path_index = self._drive.stage()

            local_path_name = path_index.get(file_id)
            if local_path_name:
                full_path = os.path.join(self._drive_dir, local_path_name)
                if os.path.exists(full_path):
                    os.remove(full_path)

            # Sync to propagate deletion to server
            self._configure_and_sync(password)

        await asyncio.to_thread(_delete)

    async def list_files(self) -> tuple:
        """
        Stage the drive and return sync status.

        Returns (plan, local_count, remote_count, synced_count, path_index).
        """

        def _stage():
            return self._drive.stage()

        return await asyncio.to_thread(_stage)
