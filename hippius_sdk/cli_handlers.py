#!/usr/bin/env python3
"""
Command Line Interface handlers for Hippius SDK.

Re-export facade — actual handler implementations live in sub-modules.
Only create_client() and get_default_address() are defined here.
"""

from typing import Any, Optional

from hippius_sdk import (
    ArionClient,
    get_account_address,
    get_config_value,
)

# Re-export all handlers so cli.py needs zero changes
from hippius_sdk.cli_handlers_file import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_account import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_config import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_address import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_miner import *  # noqa: F401,F403


# Client creation helper function
def create_client(args: Any) -> ArionClient:
    """Create an ArionClient instance from command line arguments."""
    from hippius_sdk.config import (
        get_api_token,
        get_account_address,
        get_active_account,
    )

    # Determine if we need to use password based on the command
    password = None
    api_token_password = None

    # First check if api_token_password is provided
    if hasattr(args, "api_token_password") and args.api_token_password:
        api_token_password = args.api_token_password
    elif hasattr(args, "hippius_key_password") and args.hippius_key_password:
        api_token_password = args.hippius_key_password
    # Otherwise check if old password argument is provided (for backward compatibility)
    elif hasattr(args, "password") and args.password:
        password = args.password
    # Otherwise, decide based on the command
    elif hasattr(args, "command"):
        command = args.command
        needs_password = False

        # Check if this is one of the commands that needs the API token
        if command in [
            "store",
            "download",
            "delete",
            "credits",
            "files",
        ]:
            needs_password = True

        # If this command doesn't need password access, set to empty string to skip prompting
        if not needs_password:
            password = ""
            api_token_password = ""

    # Get account name
    account_name = args.account if hasattr(args, "account") else None

    # Get API token
    api_token = None
    if hasattr(args, "api_token") and args.api_token:
        api_token = args.api_token
    elif hasattr(args, "hippius_key") and args.hippius_key:
        api_token = args.hippius_key
    else:
        api_token = get_api_token(
            password=api_token_password or password,
            account_name=account_name,
        )

    # Get account address
    account_address = get_account_address(account_name)

    # Get Arion URL
    arion_url = get_config_value("arion", "base_url", "https://arion.hippius.com")

    # Initialize client
    client = ArionClient(
        base_url=arion_url,
        api_token=api_token,
        account_address=account_address,
    )

    return client
