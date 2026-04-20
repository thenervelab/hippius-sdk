#!/usr/bin/env python3
"""
Command Line Interface tools for Hippius SDK.

This module provides CLI tools for working with the Hippius SDK, including
utilities for encryption key generation, file operations, and marketplace interactions.
"""

import asyncio
import inspect
import os
import sys
from typing import Callable

from dotenv import load_dotenv

import click

from hippius_sdk import cli_handlers, initialize_from_env
from hippius_sdk.cli_assets import draw_logo
from hippius_sdk.cli_parser import create_parser, get_subparser, parse_arguments
from hippius_sdk.cli_rich import error
from hippius_sdk.utils import generate_key

# Import SDK components

load_dotenv()
initialize_from_env()


def generate_encryption_key(copy_to_clipboard=False):
    """Generate an encryption key and display it to the user."""
    # Generate the key
    encoded_key = generate_key()

    # Copy to clipboard if requested
    if copy_to_clipboard:
        try:
            import pyperclip

            pyperclip.copy(encoded_key)
            click.secho("Key copied to clipboard!", fg="green")
        except ImportError:
            click.echo(
                click.style("Warning:", fg="yellow")
                + " Could not copy to clipboard. Install pyperclip with: pip install pyperclip"
            )

    return encoded_key


def key_generation_cli():
    """Standalone CLI tool for encryption key generation with Click formatting."""
    # Display the Hippius logo banner
    draw_logo()
    click.secho("Encryption Key Generator", fg="blue", bold=True)

    try:
        # Generate the key
        encoded_key = generate_encryption_key(copy_to_clipboard=True)

        # Display the key
        click.echo()
        click.secho("Your encryption key:", fg="green", bold=True)
        click.secho(encoded_key, fg="yellow")
        click.echo()
        click.secho("This key has been copied to your clipboard.", dim=True)
        click.secho("Usage instructions:", fg="blue", bold=True)
        click.echo("1. Store this key securely")
        click.echo("2. Use it to encrypt/decrypt files with the Hippius SDK")
        click.secho("3. Never share this key with others", fg="yellow")

        return 0
    except Exception as e:
        error(f"{e}")
        return 1


def main():
    """Main CLI entry point for hippius command."""
    # Parse arguments
    args = parse_arguments()

    if not args.command:
        # Display the Hippius logo banner with Rich formatting
        draw_logo()

        # Use Rich formatting for help text
        from hippius_sdk.cli_rich import print_help_text

        print_help_text(create_parser())

    try:
        # Parse miner IDs if provided
        miner_ids = None
        if args.miner_ids:
            miner_ids = [miner.strip() for miner in args.miner_ids.split(",")]
        elif os.getenv("SUBSTRATE_DEFAULT_MINERS"):
            miner_ids = [
                miner.strip()
                for miner in os.getenv("SUBSTRATE_DEFAULT_MINERS").split(",")
            ]

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

        # Process encrypted flags for common parameters
        encrypt = True if args.encrypt else (False if args.no_encrypt else None)
        decrypt = True if args.decrypt else (False if args.no_decrypt else None)

        # Substrate client has been deprecated - password handling moved to API client

        # Handle commands with the helper function
        if args.command == "download":
            return run_async_handler(
                cli_handlers.handle_download,
                client,
                args.cid,
                args.output_path,
                decrypt=decrypt,
            )

        elif args.command == "exists":
            return run_async_handler(cli_handlers.handle_exists, client, args.cid)

        elif args.command == "cat":
            return run_async_handler(
                cli_handlers.handle_cat,
                client,
                args.cid,
                args.max_size,
                decrypt=decrypt,
            )

        elif args.command == "store" or args.command == "add":
            return run_async_handler(
                cli_handlers.handle_store,
                client,
                args.file_path,
                miner_ids,
                encrypt=encrypt,
                publish=not args.no_publish if hasattr(args, "no_publish") else True,
            )

        elif args.command == "store-dir":
            return run_async_handler(
                cli_handlers.handle_store_dir,
                client,
                args.dir_path,
                miner_ids,
                encrypt=encrypt,
                publish=not args.no_publish if hasattr(args, "no_publish") else True,
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
                show_all_miners=(
                    args.all_miners if hasattr(args, "all_miners") else False
                ),
                file_cid=args.cid if hasattr(args, "cid") else None,
                include_pending=(
                    args.include_pending if hasattr(args, "include_pending") else False
                ),
                search=args.search if hasattr(args, "search") else None,
                ordering=args.ordering if hasattr(args, "ordering") else None,
                page=args.page if hasattr(args, "page") else None,
                output_format=getattr(args, "output_format", "table"),
                quiet=getattr(args, "quiet", False),
                limit=getattr(args, "limit", 25),
                no_truncate=getattr(args, "no_truncate", False),
            )

        elif args.command == "ec-files":
            return run_async_handler(
                cli_handlers.handle_ec_files,
                client,
                args.account_address if hasattr(args, "account_address") else None,
                show_all_miners=(
                    args.all_miners if hasattr(args, "all_miners") else False
                ),
                show_chunks=args.show_chunks if hasattr(args, "show_chunks") else False,
                filter_metadata_cid=args.cid if hasattr(args, "cid") else None,
            )

        elif args.command == "erasure-code":
            return run_async_handler(
                cli_handlers.handle_erasure_code,
                client,
                args.file_path,
                args.k,
                args.m,
                args.chunk_size,
                miner_ids,
                encrypt=args.encrypt if hasattr(args, "encrypt") else None,
                publish=not args.no_publish if hasattr(args, "no_publish") else True,
                verbose=args.verbose,
            )

        elif args.command == "reconstruct":
            return run_async_handler(
                cli_handlers.handle_reconstruct,
                client,
                args.metadata_cid,
                args.output_file,
                verbose=args.verbose,
            )

        elif args.command == "delete":
            return run_async_handler(
                cli_handlers.handle_delete,
                client,
                args.cid,
                force=args.force if hasattr(args, "force") else False,
            )

        elif args.command == "pin":
            return run_async_handler(
                cli_handlers.handle_pin,
                client,
                args.cid,
                publish=not args.no_publish if hasattr(args, "no_publish") else True,
                miner_ids=miner_ids,
            )

        elif args.command == "ec-delete":
            return run_async_handler(
                cli_handlers.handle_ec_delete,
                client,
                args.metadata_cid,
                force=args.force if hasattr(args, "force") else False,
            )

        elif args.command == "keygen":
            # Generate and save an encryption key
            copy_to_clipboard = args.copy if hasattr(args, "copy") else False
            encryption_key = generate_encryption_key(
                copy_to_clipboard=copy_to_clipboard
            )

            # Display the key
            click.echo()
            click.secho("Your encryption key:", fg="green", bold=True)
            click.secho(encryption_key, fg="yellow")

            if hasattr(args, "save") and args.save:
                click.echo()
                click.secho("Saving encryption key to configuration...", bold=True)
                cli_handlers.handle_config_set(
                    "encryption", "encryption_key", encryption_key
                )
                click.echo(
                    click.style("Encryption key saved.", fg="green")
                    + " Files will not be automatically encrypted unless you set encryption.encrypt_by_default to true"
                )
            return 0

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
            elif args.config_action == "import-env":
                initialize_from_env()
                click.echo(
                    "Successfully imported configuration from environment variables"
                )
                return 0
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                config_parser = get_subparser("config")
                from hippius_sdk.cli_rich import print_help_text

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
            elif args.account_action == "login-seed":
                return cli_handlers.handle_account_login_seed()
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
                    try:
                        account_address = cli_handlers.get_account_address(args.name)
                    except Exception as e:
                        error(f"Error getting address for account '{args.name}': {e}")
                        return 1

                return run_async_handler(
                    cli_handlers.handle_account_balance,
                    client,
                    account_address,
                )
            else:
                # Display the Hippius logo banner with Rich formatting
                draw_logo()

                account_parser = get_subparser("account")
                from hippius_sdk.cli_rich import print_help_text

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
                from hippius_sdk.cli_rich import print_help_text

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
                    node_priv_b64=getattr(args, "node_priv_b64", None),
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
                    node_priv_b64=getattr(args, "node_priv_b64", None),
                    pay_in_credits=getattr(args, "pay_in_credits", False),
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
                from hippius_sdk.cli_rich import print_help_text

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


def standalone_key_generation_cli():
    """Standalone CLI tool for generating encryption keys."""
    # Check if help flag is present
    if "--help" in sys.argv or "-h" in sys.argv:
        # Display the logo and help text with nice formatting
        draw_logo()

    # Parse arguments
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate an encryption key for Hippius SDK"
    )
    parser.add_argument(
        "--clipboard",
        "-c",
        action="store_true",
        help="Copy the key to clipboard",
    )
    parser.add_argument(
        "--save", "-s", action="store_true", help="Save the key to configuration"
    )

    args = parser.parse_args()

    # Display encryption key generator title
    click.secho("Encryption Key Generator", fg="blue", bold=True)
    click.echo()

    # Generate and display the key
    key = generate_encryption_key(copy_to_clipboard=args.clipboard)

    # Display the key
    click.echo()
    click.secho("Your encryption key:", bold=True)
    click.secho(key, fg="yellow")

    # Save to config if requested
    if args.save:
        from hippius_sdk import cli_handlers

        cli_handlers.handle_config_set("encryption", "encryption_key", key)
        click.echo()
        click.echo(
            click.style("Encryption key saved to configuration.", fg="green")
            + " Files will not be automatically encrypted unless you set encryption.encrypt_by_default to true."
        )


if __name__ == "__main__":
    sys.exit(main())
