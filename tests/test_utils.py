"""
Unit tests for hippius_sdk.utils.format_size.
"""

from hippius_sdk.utils import format_size


class TestFormatSize:
    def test_zero_bytes(self):
        assert format_size(0) == "0 bytes"

    def test_one_byte(self):
        assert format_size(1) == "1 bytes"

    def test_bytes_range(self):
        result = format_size(512)
        assert "bytes" in result

    def test_kilobytes(self):
        result = format_size(1536)
        assert "KB" in result

    def test_megabytes(self):
        result = format_size(2 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = format_size(3 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_large_file(self):
        # 1 TB
        result = format_size(1024 * 1024 * 1024 * 1024)
        assert "GB" in result or "TB" in result

    def test_exact_kb(self):
        result = format_size(1024)
        assert "1.00 KB" in result
