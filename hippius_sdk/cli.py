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

from hippius_sdk import cli_handlers, initialize_from_env
from hippius_sdk.cli_assets import HERO_TITLE
from hippius_sdk.cli_parser import create_parser, get_subparser, parse_arguments
from hippius_sdk.cli_rich import console, error
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
            console.print("[green]Key copied to clipboard![/green]")
        except ImportError:
            console.print(
                "[yellow]Warning:[/yellow] Could not copy to clipboard. Install pyperclip with: [bold]pip install pyperclip[/bold]"
            )

    return encoded_key


def key_generation_cli():
    """Standalone CLI tool for encryption key generation with Rich formatting."""
    # Display the Hippius logo banner with Rich formatting
    console.print(HERO_TITLE, style="bold cyan")
    console.print("[bold]Encryption Key Generator[/bold]", style="blue")

    try:
        # Generate the key
        encoded_key = generate_encryption_key(copy_to_clipboard=True)

        # Display the key with Rich formatting
        console.print("\n[bold green]Your encryption key:[/bold green]")
        console.print(f"[yellow]{encoded_key}[/yellow]")
        console.print("\n[dim]This key has been copied to your clipboard.[/dim]")
        console.print("[bold blue]Usage instructions:[/bold blue]")
        console.print("1. Store this key securely")
        console.print("2. Use it to encrypt/decrypt files with the Hippius SDK")
        console.print("3. [yellow]Never share this key with others[/yellow]")

        return 0
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1


def main():
    """Main CLI entry point for hippius command."""
    # Parse arguments
    args = parse_arguments()

    if not args.command:
        # Display the Hippius logo banner with Rich formatting
        console.print(HERO_TITLE, style="bold cyan")

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

        # For erasure-code specifically, the password may have been requested and cached already
        # We need to preserve it if it was set by handle_erasure_code
        if (
            args.command == "erasure-code"
            and hasattr(client.substrate_client, "_seed_phrase")
            and client.substrate_client._seed_phrase
        ):
            # Password has already been handled by the command handler
            pass

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
            )

        elif args.command == "pinning-status":
            show_contents = (
                not args.no_contents if hasattr(args, "no_contents") else True
            )
            return run_async_handler(
                cli_handlers.handle_pinning_status,
                client,
                args.account_address if hasattr(args, "account_address") else None,
                verbose=args.verbose,
                show_contents=show_contents,
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

            # Display the key with Rich formatting
            console.print("\n[bold green]Your encryption key:[/bold green]")
            console.print(f"[yellow]{encryption_key}[/yellow]")

            if hasattr(args, "save") and args.save:
                console.print(
                    "\n[bold]Saving encryption key to configuration...[/bold]"
                )
                cli_handlers.handle_config_set(
                    "encryption", "encryption_key", encryption_key
                )
                console.print(
                    "[green]Encryption key saved.[/green] Files will not be automatically encrypted unless you set [cyan]encryption.encrypt_by_default[/cyan] to [cyan]true[/cyan]"
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
                print("Successfully imported configuration from environment variables")
                return 0
            else:
                # Display the Hippius logo banner with Rich formatting
                console.print(HERO_TITLE, style="bold cyan")

                config_parser = get_subparser("config")
                from hippius_sdk.cli_rich import print_help_text

                print_help_text(config_parser)
                return 1

        elif args.command == "seed":
            if args.seed_action == "set":
                return cli_handlers.handle_seed_phrase_set(
                    args.seed_phrase,
                    args.encode if hasattr(args, "encode") else False,
                    args.account if hasattr(args, "account") else None,
                )
            elif args.seed_action == "encode":
                return cli_handlers.handle_seed_phrase_encode(
                    args.account if hasattr(args, "account") else None
                )
            elif args.seed_action == "decode":
                return cli_handlers.handle_seed_phrase_decode(
                    args.account if hasattr(args, "account") else None
                )
            elif args.seed_action == "status":
                return cli_handlers.handle_seed_phrase_status(
                    args.account if hasattr(args, "account") else None
                )
            else:
                # Display the Hippius logo banner with Rich formatting
                console.print(HERO_TITLE, style="bold cyan")

                seed_parser = get_subparser("seed")
                from hippius_sdk.cli_rich import print_help_text

                print_help_text(seed_parser)
                return 1

        # Handle the account commands
        elif args.command == "account":
            if args.account_action == "list":
                return cli_handlers.handle_account_list()
            elif args.account_action == "create" and hasattr(args, "name"):
                return cli_handlers.handle_account_create(
                    client,
                    args.name,
                    encrypt=args.encrypt if hasattr(args, "encrypt") else False,
                )
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
                console.print(HERO_TITLE, style="bold cyan")

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
                console.print(HERO_TITLE, style="bold cyan")

                address_parser = get_subparser("address")
                from hippius_sdk.cli_rich import print_help_text

                print_help_text(address_parser)
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

            console.print("\n[bold red]Traceback:[/bold red]")
            traceback.print_exc()
        return 1


def standalone_key_generation_cli():
    """Standalone CLI tool for generating encryption keys."""
    # Check if help flag is present
    if "--help" in sys.argv or "-h" in sys.argv:
        # Display the logo and help text with nice formatting
        console.print(HERO_TITLE, style="bold cyan")

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
    console.print("[bold blue]Encryption Key Generator[/bold blue]\n")

    # Generate and display the key
    key = generate_encryption_key(copy_to_clipboard=args.clipboard)

    # Display the key in a panel with formatting
    console.print("\n[bold]Your encryption key:[/bold]")
    console.print(f"[yellow]{key}[/yellow]", highlight=False)

    # Save to config if requested
    if args.save:
        from hippius_sdk import cli_handlers

        cli_handlers.handle_config_set("encryption", "encryption_key", key)
        console.print(
            "\n[green]Encryption key saved to configuration.[/green] Files will not be automatically encrypted unless you set [bold]encryption.encrypt_by_default[/bold] to [bold]true[/bold]."
        )


if __name__ == "__main__":
    sys.exit(main())
