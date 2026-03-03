#!/usr/bin/env python3
"""
Command Line Interface tools for Hippius SDK.

This module provides CLI tools for working with the Hippius SDK, including
file operations, account management, and miner registration.
"""

import asyncio
import inspect
import os
import sys
from typing import Callable

from dotenv import load_dotenv

import click

from hippius_sdk import cli_handlers
from hippius_sdk.cli_ui import draw_logo, error
from hippius_sdk.cli_parser import create_parser, get_subparser, parse_arguments

load_dotenv()


def main():
    """Main CLI entry point for hippius command."""
    # Parse arguments
    args = parse_arguments()

    if not args.command:
        # Display the Hippius logo banner with Rich formatting
        draw_logo()

        # Use Rich formatting for help text
        from hippius_sdk.cli_ui import print_help_text

        print_help_text(create_parser())

    try:
        # Create client
        client = cli_handlers.create_client(args)

        # Helper function to handle async handlers
        def run_async_handler(handler_func: Callable, *args, **kwargs) -> int:
            # Check if the handler is async
            if inspect.iscoroutinefunction(handler_func):
                # Run the async handler in the event loop
                return asyncio.run(handler_func(*args, **kwargs))
            else:
                # Run the handler directly
                return handler_func(*args, **kwargs)

        # Handle commands
        if args.command == "download":
            return run_async_handler(
                cli_handlers.handle_download,
                client,
                args.file_id,
                args.output_path,
            )

        elif args.command == "store" or args.command == "add":
            return run_async_handler(
                cli_handlers.handle_store,
                client,
                args.file_path,
            )

        elif args.command == "delete":
            return run_async_handler(
                cli_handlers.handle_delete,
                client,
                args.file_id,
                force=args.force if hasattr(args, "force") else False,
            )

        elif args.command == "credits":
            return run_async_handler(
                cli_handlers.handle_credits, client, args.account_address
            )

        elif args.command == "files":
            return run_async_handler(
                cli_handlers.handle_files,
                client,
                args.account_address if hasattr(args, "account_address") else None,
            )

        elif args.command == "config":
            if args.config_action == "get":
                return cli_handlers.handle_config_get(args.section, args.key)
            elif args.config_action == "set":
                return cli_handlers.handle_config_set(
                    args.section, args.key, args.value
                )
            elif args.config_action == "list":
                return cli_handlers.handle_config_list()
            elif args.config_action == "reset":
                return cli_handlers.handle_config_reset()
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                config_parser = get_subparser("config")
                from hippius_sdk.cli_ui import print_help_text

                print_help_text(config_parser)
                return 1

        # Handle the account commands
        elif args.command == "account":
            if args.account_action == "list":
                return cli_handlers.handle_account_list()
            elif args.account_action == "export":
                return cli_handlers.handle_account_export(
                    client,
                    args.name if hasattr(args, "name") else None,
                    args.file_path if hasattr(args, "file_path") else None,
                )
            elif args.account_action == "import" and hasattr(args, "file_path"):
                return cli_handlers.handle_account_import(
                    client,
                    args.file_path,
                    encrypt=args.encrypt if hasattr(args, "encrypt") else False,
                )
            elif args.account_action == "switch" and hasattr(args, "account_name"):
                return cli_handlers.handle_account_switch(args.account_name)
            elif args.account_action == "delete" and hasattr(args, "account_name"):
                return cli_handlers.handle_account_delete(args.account_name)
            elif args.account_action == "login":
                return cli_handlers.handle_account_login()
            elif args.account_action == "info":
                return cli_handlers.handle_account_info(
                    args.name if hasattr(args, "name") else None
                )
            elif args.account_action == "balance":
                # Get account address - prioritize direct address over account name
                account_address = None
                if hasattr(args, "address") and args.address:
                    # If address is directly provided, use it
                    account_address = args.address
                elif hasattr(args, "name") and args.name:
                    # If name is provided, get the address from the account
                    account_address = cli_handlers.get_account_address(args.name)

                return run_async_handler(
                    cli_handlers.handle_account_balance,
                    client,
                    account_address,
                )
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                account_parser = get_subparser("account")
                from hippius_sdk.cli_ui import print_help_text

                print_help_text(account_parser)
                return 1

        # Handle address commands
        elif args.command == "address":
            if args.address_action == "set-default" and hasattr(args, "address"):
                return cli_handlers.handle_default_address_set(args.address)
            elif args.address_action == "get-default":
                return cli_handlers.handle_default_address_get()
            elif args.address_action == "clear-default":
                return cli_handlers.handle_default_address_clear()
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                address_parser = get_subparser("address")
                from hippius_sdk.cli_ui import print_help_text

                print_help_text(address_parser)
                return 1

        # Handle miner commands
        elif args.command == "miner":
            if args.miner_action == "register-coldkey":
                return run_async_handler(
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
                    domain=getattr(args, "domain", "HIPPIUS::REGISTER::v1"),
                    nonce_hex=getattr(args, "nonce_hex", None),
                    dry_run=getattr(args, "dry_run", False),
                )
            elif args.miner_action == "register-hotkey":
                return run_async_handler(
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
                    domain=getattr(args, "domain", "HIPPIUS::REGISTER::v1"),
                    nonce_hex=getattr(args, "nonce_hex", None),
                    dry_run=getattr(args, "dry_run", False),
                )
            elif args.miner_action == "verify-node":
                return run_async_handler(
                    cli_handlers.handle_verify_node,
                    client,
                    args.node_id,
                    args.node_priv_hex,
                    ipfs_config=getattr(args, "ipfs_config", None),
                    ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
                    ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
                    expires_in=getattr(args, "expires_in", 10),
                    block_width=getattr(args, "block_width", "u32"),
                    domain=getattr(args, "domain", "HIPPIUS::REGISTER::v1"),
                    nonce_hex=getattr(args, "nonce_hex", None),
                    dry_run=getattr(args, "dry_run", False),
                )
            elif args.miner_action == "verify-coldkey-node":
                return run_async_handler(
                    cli_handlers.handle_verify_coldkey_node,
                    client,
                    args.node_id,
                    args.node_priv_hex,
                    ipfs_config=getattr(args, "ipfs_config", None),
                    ipfs_priv_b64=getattr(args, "ipfs_priv_b64", None),
                    ipfs_peer_id=getattr(args, "ipfs_peer_id", None),
                    expires_in=getattr(args, "expires_in", 10),
                    block_width=getattr(args, "block_width", "u32"),
                    domain=getattr(args, "domain", "HIPPIUS::REGISTER::v1"),
                    nonce_hex=getattr(args, "nonce_hex", None),
                    dry_run=getattr(args, "dry_run", False),
                )
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                miner_parser = get_subparser("miner")
                from hippius_sdk.cli_ui import print_help_text

                print_help_text(miner_parser)
                return 1

        else:
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
