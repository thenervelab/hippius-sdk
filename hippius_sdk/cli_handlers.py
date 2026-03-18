#!/usr/bin/env python3
"""
Command Line Interface handlers for Hippius SDK.

Re-export facade — actual handler implementations live in sub-modules.
Only create_client() is defined here.
"""

from typing import Any

import click

from hippius_sdk import (
    ArionClient,
    get_account_address,
    get_config_value,
    load_config,
)

# Re-export all handlers so cli.py needs zero changes
from hippius_sdk.cli_handlers_file import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_account import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_config import *  # noqa: F401,F403
from hippius_sdk.cli_handlers_miner import *  # noqa: F401,F403


# Client creation helper function
def create_client(args: Any) -> ArionClient:
    """Create an ArionClient instance from command line arguments."""
    from hippius_sdk.accounts import (
        get_api_token,
        get_account_address,
        get_active_account,
    )

    # Determine if we need a password based on the command
    password = None

    # First check if password is provided via CLI args
    if hasattr(args, "api_token_password") and args.api_token_password:
        password = args.api_token_password
    elif hasattr(args, "hippius_key_password") and args.hippius_key_password:
        password = args.hippius_key_password
    elif hasattr(args, "password") and args.password:
        password = args.password

    # Determine if this command needs the API token (and therefore a password)
    needs_password = False
    if hasattr(args, "command"):
        if args.command in ["store", "download", "delete", "credits", "files"]:
            needs_password = True

    # Get account name
    account_name = args.account if hasattr(args, "account") else None

    # Get API token
    api_token = None
    if hasattr(args, "api_token") and args.api_token:
        api_token = args.api_token
    elif hasattr(args, "hippius_key") and args.hippius_key:
        api_token = args.hippius_key
    else:
        if needs_password and password is None:
            # Check if the token is actually encrypted before prompting
            config = load_config()
            active = account_name or config.get("accounts", {}).get("active_account")
            account_data = (
                config.get("accounts", {}).get("accounts", {}).get(active, {})
            )
            if account_data.get("api_token_encoded", False):
                password = click.prompt("Encryption password", hide_input=True)

        api_token = get_api_token(
            password=password if needs_password else "",
            account_name=account_name,
        )

    # Get account address
    account_address = get_account_address(account_name)

    # Get Arion URL
    arion_url = get_config_value("arion", "base_url", "https://arion.hippius.com")

    # Initialize client with password passed through the constructor
    return ArionClient(
        base_url=arion_url,
        api_token=api_token,
        account_address=account_address,
        password=password,
    )
