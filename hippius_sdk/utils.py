"""
Utility functions for the Hippius SDK.
"""

import os
import math
from typing import Dict, Any, Union, List, Optional


def ensure_directory_exists(directory_path: str) -> None:
    """
    Create a directory if it doesn't exist.

    Args:
        directory_path: Path to the directory to ensure exists
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)


def format_size(size_bytes: int) -> str:
    """
    Format a size in bytes to a human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        str: Human-readable size (e.g., "1.23 MB")
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    if i >= len(size_names):
        i = len(size_names) - 1
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries, with source taking precedence over target.

    Args:
        target: Target dictionary to merge into
        source: Source dictionary to merge from

    Returns:
        Dict[str, Any]: Merged dictionary
    """
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            target[key] = deep_merge(target[key], value)
        else:
            target[key] = value
    return target


def parse_comma_separated(value: Optional[str]) -> List[str]:
    """
    Parse a comma-separated string into a list.

    Args:
        value: Comma-separated string or None

    Returns:
        List[str]: List of stripped values, or empty list if value is None
    """
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def is_valid_url(url: str) -> bool:
    """
    Basic check if a string is a valid URL.

    Args:
        url: URL to check

    Returns:
        bool: True if valid URL, False otherwise
    """
    return url.startswith(("http://", "https://", "ws://", "wss://"))
