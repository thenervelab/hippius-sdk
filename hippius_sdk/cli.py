#!/usr/bin/env python3
"""
Command Line Interface tools for Hippius SDK.

This module provides CLI tools for working with the Hippius SDK, including
file operations, account management, and miner registration.
"""

import asyncio
import inspect
import logging
import sys
from typing import Callable

from dotenv import load_dotenv

import click

from hippius_sdk import cli_handlers, get_config_value
from hippius_sdk.cli_ui import draw_logo, error
from hippius_sdk.cli_parser import create_parser, get_subparser, parse_arguments

load_dotenv()


def _configure_logging(verbose: bool = False):
    """Configure logging based on CLI config and --verbose flag."""
    if verbose:
        level = "DEBUG"
    else:
        level = get_config_value("cli", "log_level", "warning")

    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("hippius_sdk").setLevel(numeric_level)


def _run(handler: Callable, *args, **kwargs) -> int:
    """Run a handler, dispatching async functions through asyncio.run."""
    if inspect.iscoroutinefunction(handler):
        return asyncio.run(handler(*args, **kwargs))
    return handler(*args, **kwargs)


def _show_subcommand_help(name: str) -> int:
    """Show help for a subcommand."""
    draw_logo()
    from hippius_sdk.cli_ui import print_help_text

    print_help_text(get_subparser(name))
    return 1


# --- Subcommand dispatch tables ---

CONFIG_COMMANDS = {
    "get": lambda args, _: cli_handlers.handle_config_get(args.section, args.key),
    "set": lambda args, _: cli_handlers.handle_config_set(
        args.section, args.key, args.value
    ),
    "list": lambda args, _: cli_handlers.handle_config_list(),
    "reset": lambda args, _: cli_handlers.handle_config_reset(),
}

ACCOUNT_COMMANDS = {
    "list": lambda args, _: cli_handlers.handle_account_list(),
    "login": lambda args, _: cli_handlers.handle_account_login(),
    "switch": lambda args, _: cli_handlers.handle_account_switch(args.account_name),
    "delete": lambda args, _: cli_handlers.handle_account_delete(args.account_name),
    "info": lambda args, _: cli_handlers.handle_account_info(
        args.name if hasattr(args, "name") else None
    ),
    "export": lambda args, client: cli_handlers.handle_account_export(
        client,
        args.name if hasattr(args, "name") else None,
        args.file_path if hasattr(args, "file_path") else None,
    ),
    "import": lambda args, client: cli_handlers.handle_account_import(
        client,
        args.file_path,
        encrypt=args.encrypt if hasattr(args, "encrypt") else False,
    ),
    "init-encryption": lambda args, _: cli_handlers.handle_init_encryption(
        mnemonic=args.mnemonic if hasattr(args, "mnemonic") else None,
    ),
    "show-mnemonic": lambda args, _: cli_handlers.handle_show_mnemonic(),
}


def _handle_account_balance(args, client):
    """Handle account balance with address resolution."""
    account_address = None
    if hasattr(args, "address") and args.address:
        account_address = args.address
    elif hasattr(args, "name") and args.name:
        account_address = cli_handlers.get_account_address(args.name)

    return _run(cli_handlers.handle_account_balance, client, account_address)


MINER_COMMANDS = {
    "register-coldkey": lambda args, client: _run(
        cli_handlers.handle_register_coldkey,
        client,
        args.node_id,
        args.node_priv_hex,
        args.node_type,
        ipfs_config=getattr(args, "ipfs_config", None),
        ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
        ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
        pay_in_credits=getattr(args, "pay_in_credits", False),
        expires_in=getattr(args, "expires_in", 10),
        block_width=getattr(args, "block_width", "u32"),
        nonce_hex=getattr(args, "nonce_hex", None),
        dry_run=getattr(args, "dry_run", False),
    ),
    "register-hotkey": lambda args, client: _run(
        cli_handlers.handle_register_hotkey,
        client,
        args.coldkey,
        args.node_id,
        args.node_priv_hex,
        args.node_type,
        ipfs_config=getattr(args, "ipfs_config", None),
        ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
        ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
        pay_in_credits=getattr(args, "pay_in_credits", False),
        expires_in=getattr(args, "expires_in", 10),
        block_width=getattr(args, "block_width", "u32"),
        nonce_hex=getattr(args, "nonce_hex", None),
        dry_run=getattr(args, "dry_run", False),
    ),
    "verify-node": lambda args, client: _run(
        cli_handlers.handle_verify_node,
        client,
        args.node_id,
        args.node_priv_hex,
        ipfs_config=getattr(args, "ipfs_config", None),
        ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
        ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
        expires_in=getattr(args, "expires_in", 10),
        block_width=getattr(args, "block_width", "u32"),
        nonce_hex=getattr(args, "nonce_hex", None),
        dry_run=getattr(args, "dry_run", False),
    ),
    "verify-coldkey-node": lambda args, client: _run(
        cli_handlers.handle_verify_coldkey_node,
        client,
        args.node_id,
        args.node_priv_hex,
        ipfs_config=getattr(args, "ipfs_config", None),
        ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
        ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
        expires_in=getattr(args, "expires_in", 10),
        block_width=getattr(args, "block_width", "u32"),
        nonce_hex=getattr(args, "nonce_hex", None),
        dry_run=getattr(args, "dry_run", False),
    ),
}

# Top-level commands (simple ones that map directly to handlers)
TOP_COMMANDS = {
    "store": lambda args, client: _run(
        cli_handlers.handle_store, client, args.file_path
    ),
    "download": lambda args, client: _run(
        cli_handlers.handle_download, client, args.file_id, args.output_path
    ),
    "delete": lambda args, client: _run(
        cli_handlers.handle_delete,
        client,
        args.file_id,
        force=args.force if hasattr(args, "force") else False,
    ),
    "credits": lambda args, client: _run(cli_handlers.handle_credits, client),
    "files": lambda args, client: _run(cli_handlers.handle_files, client),
}

# Nested command groups: command -> (action_attr, dispatch_table, help_name)
NESTED_COMMANDS = {
    "config": ("config_action", CONFIG_COMMANDS, "config"),
    "account": ("account_action", ACCOUNT_COMMANDS, "account"),
    "miner": ("miner_action", MINER_COMMANDS, "miner"),
}


def main():
    """Main CLI entry point for hippius command."""
    # Parse arguments
    args = parse_arguments()
    _configure_logging(getattr(args, "verbose", False))

    if not args.command:
        # Display the Hippius logo banner with Rich formatting
        draw_logo()

        from hippius_sdk.cli_ui import print_help_text

        print_help_text(create_parser())
        return

    try:
        # Create client
        client = cli_handlers.create_client(args)

        # Try top-level commands first
        if args.command in TOP_COMMANDS:
            return TOP_COMMANDS[args.command](args, client)

        # Try nested command groups
        if args.command in NESTED_COMMANDS:
            action_attr, dispatch_table, help_name = NESTED_COMMANDS[args.command]
            action = getattr(args, action_attr, None)

            # Special case: account balance needs address resolution
            if args.command == "account" and action == "balance":
                return _handle_account_balance(args, client)

            if action in dispatch_table:
                handler = dispatch_table[action]
                result = handler(args, client)
                # Wrap async results
                if inspect.isawaitable(result):
                    return asyncio.run(result)
                return result

            return _show_subcommand_help(help_name)

        # Command not recognized
        error(f"Unknown command: [bold]{args.command}[/bold]")
        return 1

    except KeyboardInterrupt:
        error("\nOperation cancelled by user")
        return 1
    except Exception as e:
        error(f"{str(e)}")
        if args.verbose:
            import traceback

            click.echo()
            click.secho("Traceback:", fg="red", bold=True)
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
