"""
Unit tests for hippius_sdk.http_utils.
"""

from unittest.mock import MagicMock

import httpx
import pytest

from hippius_sdk.errors import HippiusAuthenticationError
from hippius_sdk.http_utils import create_http_client, retry_on_error


class TestCreateHttpClient:
    def test_returns_async_client(self):
        client = create_http_client("https://example.com")
        assert isinstance(client, httpx.AsyncClient)

    def test_base_url_set(self):
        client = create_http_client("https://arion.hippius.com")
        assert str(client.base_url) == "https://arion.hippius.com"

    def test_follow_redirects(self):
        client = create_http_client("https://example.com")
        assert client.follow_redirects is True


class TestRetryOnError:
    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        """Successful call returns immediately, no retry."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.0)
        async def succeeding():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await succeeding()
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_then_succeed(self):
        """Retries on 500, then succeeds."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.0)
        async def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                resp = MagicMock()
                resp.status_code = 500
                resp.text = "Internal Server Error"
                raise httpx.HTTPStatusError("500", request=MagicMock(), response=resp)
            return "recovered"

        result = await flaky()
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_401(self):
        """401 raises HippiusAuthenticationError immediately."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.0)
        async def auth_fail():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 401
            resp.text = "Unauthorized"
            raise httpx.HTTPStatusError("401", request=MagicMock(), response=resp)

        with pytest.raises(HippiusAuthenticationError):
            await auth_fail()
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_no_retry_on_404(self):
        """404 raises immediately, no retry."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.0)
        async def not_found():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 404
            resp.text = "Not Found"
            raise httpx.HTTPStatusError("404", request=MagicMock(), response=resp)

        with pytest.raises(httpx.HTTPStatusError):
            await not_found()
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        """After all retries fail, the last exception is raised."""
        call_count = 0

        @retry_on_error(retries=2, backoff=0.0)
        async def always_fail():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 502
            resp.text = "Bad Gateway"
            raise httpx.HTTPStatusError("502", request=MagicMock(), response=resp)

        with pytest.raises(httpx.HTTPStatusError):
            await always_fail()
        assert call_count == 3  # 1 initial + 2 retries

    @pytest.mark.asyncio
    async def test_no_retry_on_507(self):
        """507 Insufficient Storage is not retried."""
        call_count = 0

        @retry_on_error(retries=3, backoff=0.0)
        async def storage_full():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 507
            resp.text = "Insufficient Storage"
            raise httpx.HTTPStatusError("507", request=MagicMock(), response=resp)

        with pytest.raises(httpx.HTTPStatusError):
            await storage_full()
        assert call_count == 1
