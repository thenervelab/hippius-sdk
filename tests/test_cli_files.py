"""
Unit tests for CLI files and credits handlers.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from hippius_sdk.cli_handlers import handle_credits, handle_files


def _extract_json(text):
    """Extract JSON array from text that may have leading non-JSON lines."""
    idx = text.index("[")
    return json.loads(text[idx:])


def _extract_csv(text):
    """Extract CSV lines, skipping leading non-CSV info lines."""
    lines = text.strip().split("\n")
    csv_lines = []
    for line in lines:
        if csv_lines or "cid" in line:
            csv_lines.append(line)
    return csv_lines


def _make_paginated(results, count=None):
    """Helper to build a paginated API response."""
    if count is None:
        count = len(results)
    return {
        "results": results,
        "count": count,
        "next": None,
        "previous": None,
    }


def _sample_files(n=3):
    """Return n sample file dicts."""
    return [
        {
            "cid": f"QmTestCid{i:04d}abcdef1234567890abcdef",
            "original_name": f"file_{i}.txt",
            "size_bytes": 1024 * (i + 1),
            "status": "pinned",
            "active_replica_count": 2,
            "updated_at": "2026-01-15T10:30:00Z",
        }
        for i in range(n)
    ]


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.api_client = MagicMock()
    client.api_client.list_files_paginated = AsyncMock()
    client.api_client.get_account_balance = AsyncMock()
    return client


# ---- handle_files tests ----


@pytest.mark.asyncio
async def test_files_table_default(mock_client, capsys):
    """Default table mode returns 0 and calls list_files_paginated."""
    files = _sample_files(3)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client)

    assert result == 0
    mock_client.api_client.list_files_paginated.assert_awaited_once()


@pytest.mark.asyncio
async def test_files_json_mode(mock_client, capsys):
    """--format json outputs valid JSON array."""
    files = _sample_files(2)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, output_format="json")
    assert result == 0

    captured = capsys.readouterr()
    parsed = _extract_json(captured.out)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


@pytest.mark.asyncio
async def test_files_csv_mode(mock_client, capsys):
    """--format csv outputs correct CSV headers and rows."""
    files = _sample_files(2)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, output_format="csv")
    assert result == 0

    captured = capsys.readouterr()
    csv_lines = _extract_csv(captured.out)
    assert "cid" in csv_lines[0]
    assert "original_name" in csv_lines[0]
    # Header + 2 data rows
    assert len(csv_lines) == 3


@pytest.mark.asyncio
async def test_files_quiet_mode(mock_client, capsys):
    """-q outputs one CID per line, nothing else."""
    files = _sample_files(3)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, quiet=True)
    assert result == 0

    captured = capsys.readouterr()
    lines = [l for l in captured.out.strip().split("\n") if l]
    assert len(lines) == 3
    for line in lines:
        assert line.startswith("QmTestCid")


@pytest.mark.asyncio
async def test_files_empty(mock_client):
    """Empty results returns 0, no crash."""
    mock_client.api_client.list_files_paginated.return_value = _make_paginated([])

    result = await handle_files(mock_client)
    assert result == 0


@pytest.mark.asyncio
async def test_files_limit(mock_client, capsys):
    """--limit 2 on 5 files shows only 2."""
    files = _sample_files(5)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, output_format="json", limit=2)
    assert result == 0

    captured = capsys.readouterr()
    parsed = _extract_json(captured.out)
    assert len(parsed) == 2


@pytest.mark.asyncio
async def test_files_limit_zero(mock_client, capsys):
    """--limit 0 shows all files."""
    files = _sample_files(5)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, output_format="json", limit=0)
    assert result == 0

    captured = capsys.readouterr()
    parsed = _extract_json(captured.out)
    assert len(parsed) == 5


@pytest.mark.asyncio
async def test_files_no_truncate(mock_client, capsys):
    """--no-truncate passes long CIDs through unmodified."""
    long_cid = "Qm" + "a" * 60
    files = [
        {
            "cid": long_cid,
            "original_name": "long.txt",
            "size_bytes": 100,
            "status": "pinned",
            "active_replica_count": 1,
            "updated_at": "2026-01-01T00:00:00Z",
        }
    ]
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(files)

    result = await handle_files(mock_client, output_format="json", no_truncate=True)
    assert result == 0

    captured = capsys.readouterr()
    parsed = _extract_json(captured.out)
    assert parsed[0]["cid"] == long_cid


@pytest.mark.asyncio
async def test_files_search_passthrough(mock_client):
    """search= param forwarded to API call."""
    mock_client.api_client.list_files_paginated.return_value = _make_paginated([])

    await handle_files(mock_client, search="myfile")

    call_kwargs = mock_client.api_client.list_files_paginated.call_args
    assert call_kwargs.kwargs.get("search") == "myfile" or call_kwargs[1].get("search") == "myfile"


@pytest.mark.asyncio
async def test_files_pagination_footer(mock_client, capsys):
    """Footer shows 'Showing X of Y' when count > shown."""
    files = _sample_files(3)
    mock_client.api_client.list_files_paginated.return_value = _make_paginated(
        files, count=50
    )

    result = await handle_files(mock_client)
    assert result == 0

    captured = capsys.readouterr()
    assert "Showing 3 of 50" in captured.out


# ---- handle_credits tests ----


@pytest.mark.asyncio
async def test_credits_success(mock_client):
    """handle_credits returns 0 and formats balance."""
    mock_client.api_client.get_account_balance.return_value = {
        "balance": 42.50,
    }

    result = await handle_credits(mock_client)
    assert result == 0
    mock_client.api_client.get_account_balance.assert_awaited_once()


@pytest.mark.asyncio
async def test_credits_string_balance(mock_client):
    """Balance as string is handled without error."""
    mock_client.api_client.get_account_balance.return_value = {
        "balance": "99.99",
    }

    result = await handle_credits(mock_client)
    assert result == 0
