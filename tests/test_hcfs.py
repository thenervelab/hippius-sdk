"""
Tests for HCFS encryption integration.

Tests the hcfs_client-backed HcfsManager wrapper and ArionClient
encryption routing. All tests use mocks — no native module or network calls.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from hippius_sdk.arion import ArionClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_drive():
    """A mocked Drive instance."""
    drive = MagicMock()
    drive.is_initialized.return_value = True
    drive.init.return_value = "word " * 23 + "word"
    drive.stage.return_value = (
        MagicMock(
            uploads=["abc123"],
            downloads=[],
            local_deletes=[],
            remote_deletes=[],
            conflicts=[],
        ),
        1,  # local_count
        0,  # remote_count
        0,  # synced_count
        {"abc123": "sample.txt"},  # path_index
    )
    drive.sync.return_value = MagicMock(
        files_uploaded=1,
        files_downloaded=0,
        files_deleted_locally=0,
        files_deleted_remotely=0,
        conflicts_resolved=0,
        conflicts_skipped=0,
    )
    return drive


@pytest.fixture
def mock_drive_class(mock_drive):
    """Patch the Drive constructor to return the mock_drive."""
    with patch("hippius_sdk.hcfs.Drive", return_value=mock_drive) as cls:
        yield cls


@pytest.fixture
def mock_hcfs_client():
    """A mocked HcfsClient instance."""
    client = MagicMock()
    client.download.return_value = MagicMock(
        size_bytes=1024,
        revision_seq=1,
        revision_id="rev123",
    )
    return client


@pytest.fixture
def mock_hcfs_client_class(mock_hcfs_client):
    """Patch the HcfsClient constructor to return the mock."""
    with patch("hippius_sdk.hcfs.HcfsClient", return_value=mock_hcfs_client) as cls:
        yield cls


@pytest.fixture
def mock_config():
    """Patch HcfsClientConfig constructor."""
    with patch("hippius_sdk.hcfs.HcfsClientConfig") as cls:
        cls.return_value = MagicMock()
        yield cls


@pytest.fixture
def sample_file(tmp_path):
    """A small test file for upload tests."""
    f = tmp_path / "sample.txt"
    f.write_text("hello hippius encryption test")
    return str(f)


@pytest.fixture
def hcfs_manager(tmp_path, mock_drive_class, mock_config):
    """A ready-to-use HcfsManager with mocked Drive and config."""
    from hippius_sdk.hcfs import HcfsManager

    drive_dir = str(tmp_path / "drive")
    os.makedirs(drive_dir, exist_ok=True)
    return HcfsManager(
        drive_dir=drive_dir,
        base_url="https://arion.test",
        bearer_token="tok",
        account_ss58="5TestAddr",
    )


# ---------------------------------------------------------------------------
# HcfsManager — initialization
# ---------------------------------------------------------------------------


class TestHcfsManagerInit:
    def test_is_initialized_delegates_to_drive(self, hcfs_manager, mock_drive_class):
        drive_instance = mock_drive_class.return_value
        drive_instance.is_initialized.return_value = False
        assert hcfs_manager.is_initialized() is False

        drive_instance.is_initialized.return_value = True
        assert hcfs_manager.is_initialized() is True

    def test_init_delegates_to_drive(self, hcfs_manager, mock_drive_class):
        drive_instance = mock_drive_class.return_value
        mnemonic = hcfs_manager.init("testpass")

        drive_instance.init.assert_called_once_with("testpass", None)
        assert len(mnemonic.split()) == 24

    def test_init_with_recovery(self, hcfs_manager, mock_drive_class):
        drive_instance = mock_drive_class.return_value
        phrase = "word " * 23 + "word"
        hcfs_manager.init("pass", existing_mnemonic=phrase)

        drive_instance.init.assert_called_once_with("pass", phrase)


# ---------------------------------------------------------------------------
# HcfsManager — upload
# ---------------------------------------------------------------------------


class TestHcfsManagerUpload:
    @pytest.mark.asyncio
    async def test_upload_copies_file_and_syncs(
        self, hcfs_manager, mock_drive_class, sample_file
    ):
        drive_instance = mock_drive_class.return_value

        result = await hcfs_manager.upload(sample_file, "testpass")

        # File should be copied to drive dir
        dest = os.path.join(hcfs_manager._drive_dir, "sample.txt")
        assert os.path.exists(dest)

        # Drive should have been staged, configured, unlocked, and synced
        drive_instance.stage.assert_called_once()
        drive_instance.set_config.assert_called_once()
        drive_instance.unlock.assert_called_once_with("testpass")
        drive_instance.sync.assert_called_once()

        assert result["file_id"] == "abc123"
        assert result["size_bytes"] > 0

    @pytest.mark.asyncio
    async def test_upload_returns_basename_when_no_match(
        self, hcfs_manager, mock_drive_class, sample_file
    ):
        drive_instance = mock_drive_class.return_value
        # Empty path_index — no match
        drive_instance.stage.return_value = (
            MagicMock(uploads=[]),
            0,
            0,
            0,
            {},
        )

        result = await hcfs_manager.upload(sample_file, "testpass")
        assert result["file_id"] == "sample.txt"


# ---------------------------------------------------------------------------
# HcfsManager — download
# ---------------------------------------------------------------------------


class TestHcfsManagerDownload:
    @pytest.mark.asyncio
    async def test_download_uses_hcfs_client(
        self,
        hcfs_manager,
        mock_drive_class,
        mock_hcfs_client_class,
        mock_hcfs_client,
        tmp_path,
    ):
        output = str(tmp_path / "out.bin")

        await hcfs_manager.download("5Owner", "file123", output, "testpass")

        mock_hcfs_client.download.assert_called_once_with(
            "5Owner", hcfs_manager._config.folder_hash, "file123", output
        )


# ---------------------------------------------------------------------------
# HcfsManager — delete
# ---------------------------------------------------------------------------


class TestHcfsManagerDelete:
    @pytest.mark.asyncio
    async def test_delete_removes_file_and_syncs(
        self, hcfs_manager, mock_drive_class, tmp_path
    ):
        drive_instance = mock_drive_class.return_value

        # Create a file in the drive dir that maps to the file_id
        local_file = os.path.join(hcfs_manager._drive_dir, "sample.txt")
        with open(local_file, "w") as f:
            f.write("data")

        drive_instance.stage.return_value = (
            MagicMock(),
            1,
            0,
            0,
            {"file_id_abc": "sample.txt"},
        )

        await hcfs_manager.delete("5Owner", "file_id_abc", "testpass")

        assert not os.path.exists(local_file)
        drive_instance.sync.assert_called_once()


# ---------------------------------------------------------------------------
# ArionClient — encryption routing
# ---------------------------------------------------------------------------


class TestArionClientEncryptionRouting:
    @pytest.fixture
    def arion(self):
        return ArionClient(
            base_url="https://arion.test",
            api_token="test-token",
            account_address="5TestAddr",
        )

    def test_encryption_disabled_by_default(self, arion):
        assert arion.encryption_enabled is False

    def test_encryption_enabled_after_enable(
        self, arion, mock_drive_class, mock_config
    ):
        arion.enable_encryption("testpass123", config_dir="/tmp/test_drive")
        assert arion.encryption_enabled is True

    @pytest.mark.asyncio
    async def test_upload_routes_through_hcfs(
        self, arion, mock_drive_class, mock_config, sample_file
    ):
        arion.enable_encryption("testpass123", config_dir="/tmp/test_drive")

        mock_upload_result = {
            "file_id": "encrypted-file-001",
            "size_bytes": 28,
        }

        with patch.object(
            arion._hcfs_manager,
            "upload",
            new_callable=AsyncMock,
            return_value=mock_upload_result,
        ):
            result = await arion.upload_file(sample_file)

        assert result["file_id"] == "encrypted-file-001"
        assert result["encrypted"] is True

    @pytest.mark.asyncio
    async def test_download_routes_through_hcfs(
        self, arion, mock_drive_class, mock_config, tmp_path
    ):
        arion.enable_encryption("testpass123", config_dir="/tmp/test_drive")

        output_path = str(tmp_path / "decrypted.bin")

        with patch.object(
            arion._hcfs_manager, "download", new_callable=AsyncMock
        ) as mock_dl:
            result = await arion.download_file("file123", output_path)

        mock_dl.assert_awaited_once_with(
            "5TestAddr", "file123", output_path, "testpass123"
        )
        assert result["encrypted"] is True

    @pytest.mark.asyncio
    async def test_delete_routes_through_hcfs(
        self, arion, mock_drive_class, mock_config
    ):
        arion.enable_encryption("testpass123", config_dir="/tmp/test_drive")

        with patch.object(
            arion._hcfs_manager, "delete", new_callable=AsyncMock
        ) as mock_del:
            result = await arion.delete_file("file123")

        mock_del.assert_awaited_once_with("5TestAddr", "file123", "testpass123")
        assert result["status"] == "deleted"
        assert result["file_id"] == "file123"

    @pytest.mark.asyncio
    async def test_upload_fails_without_encryption(self, arion, sample_file):
        from hippius_sdk.errors import HippiusArionError

        with pytest.raises(
            HippiusArionError,
            match="HCFS encryption not enabled.*hippius account login",
        ):
            await arion.upload_file(sample_file)

    @pytest.mark.asyncio
    async def test_download_fails_without_encryption(self, arion, tmp_path):
        from hippius_sdk.errors import HippiusArionError

        with pytest.raises(
            HippiusArionError,
            match="HCFS encryption not enabled.*hippius account login",
        ):
            await arion.download_file("file123", str(tmp_path / "out.bin"))

    @pytest.mark.asyncio
    async def test_download_bytes_routes_through_hcfs(
        self, arion, mock_drive_class, mock_config, tmp_path
    ):
        arion.enable_encryption("testpass123", config_dir="/tmp/test_drive")

        async def mock_download(user_id, file_id, output_path, password):
            with open(output_path, "wb") as f:
                f.write(b"decrypted content")

        with patch.object(arion._hcfs_manager, "download", side_effect=mock_download):
            data = await arion.download_bytes("file123")

        assert data == b"decrypted content"


# ---------------------------------------------------------------------------
# CLI handlers — encryption management
# ---------------------------------------------------------------------------


class TestCliInitEncryption:
    @patch("hippius_sdk.cli_handlers_account.get_active_account", return_value="alice")
    @patch("hippius_sdk.cli_handlers_account.click.prompt")
    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=False)
    def test_init_encryption_creates_keys(
        self, mock_confirm, mock_prompt, mock_active, tmp_path
    ):
        from hippius_sdk.cli_handlers_account import handle_init_encryption

        mock_prompt.return_value = "testpassword"
        drives_base = str(tmp_path / "drives")

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = False
        mock_drive.init.return_value = "word " * 23 + "word"

        with patch(
            "hippius_sdk.cli_handlers_account.Drive", return_value=mock_drive
        ), patch("hippius_sdk.hcfs.DRIVES_BASE_DIR", drives_base):
            result = handle_init_encryption()

        assert result == 0
        mock_drive.init.assert_called_once_with("testpassword", None)

    @patch("hippius_sdk.cli_handlers_account.get_active_account", return_value="alice")
    @patch("hippius_sdk.cli_handlers_account.click.prompt")
    @patch("hippius_sdk.cli_handlers_account.click.confirm", return_value=True)
    def test_init_encryption_with_mnemonic(
        self, mock_confirm, mock_prompt, mock_active, tmp_path
    ):
        from hippius_sdk.cli_handlers_account import handle_init_encryption

        mnemonic = "word " * 23 + "word"
        mock_prompt.return_value = "newpass"
        drives_base = str(tmp_path / "drives")

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = True  # already initialized
        mock_drive.init.return_value = mnemonic

        with patch(
            "hippius_sdk.cli_handlers_account.Drive", return_value=mock_drive
        ), patch("hippius_sdk.hcfs.DRIVES_BASE_DIR", drives_base):
            result = handle_init_encryption(mnemonic=mnemonic)

        assert result == 0
        mock_drive.init.assert_called_once_with("newpass", mnemonic)

    def test_init_encryption_no_active_account(self):
        from hippius_sdk.cli_handlers_account import handle_init_encryption

        with patch(
            "hippius_sdk.cli_handlers_account.get_active_account", return_value=None
        ):
            result = handle_init_encryption()

        assert result == 1


class TestCliShowMnemonic:
    @patch("hippius_sdk.cli_handlers_account.get_active_account", return_value="alice")
    def test_show_mnemonic_not_initialized(self, mock_active, tmp_path):
        from hippius_sdk.cli_handlers_account import handle_show_mnemonic

        drives_base = str(tmp_path / "drives")

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = False

        with patch(
            "hippius_sdk.cli_handlers_account.Drive", return_value=mock_drive
        ), patch("hippius_sdk.hcfs.DRIVES_BASE_DIR", drives_base):
            result = handle_show_mnemonic()

        assert result == 1

    def test_show_mnemonic_no_active_account(self):
        from hippius_sdk.cli_handlers_account import handle_show_mnemonic

        with patch(
            "hippius_sdk.cli_handlers_account.get_active_account", return_value=None
        ):
            result = handle_show_mnemonic()

        assert result == 1


# ---------------------------------------------------------------------------
# Per-account drive isolation
# ---------------------------------------------------------------------------


class TestPerAccountDriveDir:
    def test_get_drive_dir_returns_per_account_path(self):
        from hippius_sdk.hcfs import get_drive_dir, DRIVES_BASE_DIR

        assert get_drive_dir("alice") == os.path.join(DRIVES_BASE_DIR, "alice")
        assert get_drive_dir("bob") == os.path.join(DRIVES_BASE_DIR, "bob")

    def test_different_accounts_get_different_dirs(self):
        from hippius_sdk.hcfs import get_drive_dir

        assert get_drive_dir("alice") != get_drive_dir("bob")


# ---------------------------------------------------------------------------
# CLI file handlers — encryption auto-detection
# ---------------------------------------------------------------------------


class TestCliEnableEncryption:
    @patch("hippius_sdk.cli_handlers_file.get_active_account", return_value="alice")
    def test_enables_encryption_when_initialized(self, mock_active):
        from hippius_sdk.cli_handlers_file import _enable_encryption

        client = ArionClient(
            base_url="https://arion.test",
            api_token="tok",
            account_address="5Addr",
        )

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = True

        with patch(
            "hippius_sdk.cli_handlers_file.Drive", return_value=mock_drive
        ), patch("hippius_sdk.hcfs.Drive", return_value=mock_drive), patch.dict(
            "os.environ", {"HIPPIUS_ENCRYPTION_PASSWORD": "testpass123"}
        ), patch(
            "hippius_sdk.hcfs.HcfsClientConfig"
        ):
            _enable_encryption(client)

        assert client.encryption_enabled is True

    @patch("hippius_sdk.cli_handlers_file.get_active_account", return_value="alice")
    def test_raises_when_not_initialized(self, mock_active):
        from hippius_sdk.cli_handlers_file import _enable_encryption

        client = ArionClient(
            base_url="https://arion.test",
            api_token="tok",
            account_address="5Addr",
        )

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = False

        with patch(
            "hippius_sdk.cli_handlers_file.Drive", return_value=mock_drive
        ), pytest.raises(SystemExit):
            _enable_encryption(client)

        assert client.encryption_enabled is False

    @patch("hippius_sdk.cli_handlers_file.get_active_account", return_value=None)
    def test_raises_when_no_active_account(self, mock_active):
        from hippius_sdk.cli_handlers_file import _enable_encryption

        client = ArionClient(
            base_url="https://arion.test",
            api_token="tok",
            account_address="5Addr",
        )

        with pytest.raises(SystemExit):
            _enable_encryption(client)

        assert client.encryption_enabled is False

    @patch("hippius_sdk.cli_handlers_file.get_active_account", return_value="alice")
    @patch("hippius_sdk.cli_handlers_file.click.prompt", return_value="testpass123")
    def test_prompts_for_password_when_no_env_var(self, mock_prompt, mock_active):
        from hippius_sdk.cli_handlers_file import _enable_encryption

        client = ArionClient(
            base_url="https://arion.test",
            api_token="tok",
            account_address="5Addr",
        )

        mock_drive = MagicMock()
        mock_drive.is_initialized.return_value = True

        with patch(
            "hippius_sdk.cli_handlers_file.Drive", return_value=mock_drive
        ), patch("hippius_sdk.hcfs.Drive", return_value=mock_drive), patch.dict(
            "os.environ", {}, clear=True
        ), patch(
            "hippius_sdk.hcfs.HcfsClientConfig"
        ):
            _enable_encryption(client)

        mock_prompt.assert_called_once()
        assert client.encryption_enabled is True


# ---------------------------------------------------------------------------
# HTTP logging — sensitive header masking
# ---------------------------------------------------------------------------


class TestHttpLoggingMasking:
    @pytest.mark.asyncio
    async def test_masks_x_api_key_header(self):
        import logging
        from hippius_sdk.http_utils import _log_request

        request = MagicMock()
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {
            "x-api-key": "super-secret-api-key-value-12345",
            "content-type": "application/json",
        }
        request.content = b""

        with patch("hippius_sdk.http_utils.logger") as mock_logger:
            mock_logger.debug = MagicMock()
            await _log_request(request)

            logged_headers = mock_logger.debug.call_args_list[0][0][3]
            assert logged_headers["x-api-key"] == "super-secret..."
            assert logged_headers["content-type"] == "application/json"

    @pytest.mark.asyncio
    async def test_masks_authorization_header(self):
        from hippius_sdk.http_utils import _log_request

        request = MagicMock()
        request.method = "POST"
        request.url = "https://example.com/api"
        request.headers = {
            "authorization": "Bearer long-token-value-here",
        }
        request.content = b""

        with patch("hippius_sdk.http_utils.logger") as mock_logger:
            mock_logger.debug = MagicMock()
            await _log_request(request)

            logged_headers = mock_logger.debug.call_args_list[0][0][3]
            assert logged_headers["authorization"] == "Bearer long-..."
