#!/usr/bin/env python3
"""
Command Line Interface handlers for Hippius SDK.

This module provides handler functions for CLI commands, including
file operations, marketplace interactions, configuration management, etc.
"""
import asyncio
import base64
import getpass
import json
import math
import os
import tempfile
import time
from typing import Any, List, Optional

from hippius_sdk import (
    HippiusClient,
    decrypt_seed_phrase,
    delete_account,
    encrypt_seed_phrase,
    format_size,
    get_account_address,
    get_active_account,
    get_all_config,
    get_config_value,
    list_accounts,
    load_config,
    reset_config,
    save_config,
    set_active_account,
    set_config_value,
    set_seed_phrase,
)
from hippius_sdk.cli_parser import get_default_address
from hippius_sdk.cli_rich import (
    console,
    create_progress,
    error,
    info,
    log,
    print_panel,
    print_table,
    success,
    warning,
)
from hippius_sdk.errors import (
    HippiusAlreadyDeletedError,
    HippiusFailedIPFSUnpin,
    HippiusFailedSubstrateDelete,
    HippiusMetadataError,
)
from hippius_sdk.substrate import FileInput

try:
    import nacl.secret
    import nacl.utils
except ImportError:
    ENCRYPTION_AVAILABLE = False
else:
    ENCRYPTION_AVAILABLE = True


# Client creation helper function
def create_client(args: Any) -> HippiusClient:
    """Create a HippiusClient instance from command line arguments."""
    # Process encryption flags
    encrypt = None
    if hasattr(args, "encrypt") and args.encrypt:
        encrypt = True
    elif hasattr(args, "no_encrypt") and args.no_encrypt:
        encrypt = False

    # Process encryption key if provided
    encryption_key = None
    if hasattr(args, "encryption_key") and args.encryption_key:
        try:
            encryption_key = base64.b64decode(args.encryption_key)
            if hasattr(args, "verbose") and args.verbose:
                print("Using provided encryption key")
        except Exception as e:
            print(f"Warning: Could not decode encryption key: {e}")
            print("Using default encryption key from configuration if available")

    # Get API URL based on local_ipfs flag if the flag exists
    api_url = None
    if hasattr(args, "local_ipfs") and args.local_ipfs:
        api_url = "http://localhost:5001"
    elif hasattr(args, "api_url"):
        api_url = args.api_url
    elif hasattr(args, "ipfs_api"):
        api_url = args.ipfs_api

    # Get gateway URL
    gateway = None
    if hasattr(args, "gateway"):
        gateway = args.gateway
    elif hasattr(args, "ipfs_gateway"):
        gateway = args.ipfs_gateway

    # Get substrate URL
    substrate_url = args.substrate_url if hasattr(args, "substrate_url") else None

    # Determine if we need to use password based on the command
    # Only use password for: store, download, delete, erasure-code (unless --no-publish), reconstruct
    password = None

    # First check if password is provided as an argument
    if hasattr(args, "password") and args.password:
        password = args.password
    # Otherwise, decide based on the command
    elif hasattr(args, "command"):
        command = args.command
        needs_password = False

        # Check if this is one of the commands that needs a password
        if command in [
            "store",
            "store-dir",
            "download",
            "delete",
            "delete-dir",
            "reconstruct",
        ]:
            needs_password = True
        # Special case for erasure-code - only needs password if we're publishing
        elif command == "erasure-code" and not (
            hasattr(args, "no_publish") and args.no_publish
        ):
            needs_password = True

        # If this command doesn't need password access, set to empty string to skip prompting
        if not needs_password:
            # Use empty string to indicate "skip password prompt" to the config system
            password = ""

    # Initialize client with provided parameters
    client = HippiusClient(
        ipfs_gateway=gateway,
        ipfs_api_url=api_url,
        substrate_url=substrate_url,
        substrate_seed_phrase=(
            args.seed_phrase if hasattr(args, "seed_phrase") else None
        ),
        seed_phrase_password=password,
        account_name=args.account if hasattr(args, "account") else None,
        encrypt_by_default=encrypt,
        encryption_key=encryption_key,
    )

    return client


#
# IPFS File Operation Handlers
#


async def handle_download(
    client: HippiusClient, cid: str, output_path: str, decrypt: Optional[bool] = None
) -> int:
    """Handle the download command"""
    info(f"Downloading [bold cyan]{cid}[/bold cyan] to [bold]{output_path}[/bold]...")

    # Use the enhanced download method which returns formatted information
    result = await client.download_file(cid, output_path, decrypt=decrypt)

    # Create a success panel with download information
    details = [
        f"Download successful in [bold green]{result['elapsed_seconds']}[/bold green] seconds!",
        f"Saved to: [bold]{result['output_path']}[/bold]",
        f"Size: [bold cyan]{result['size_bytes']:,}[/bold cyan] bytes ([bold cyan]{result['size_formatted']}[/bold cyan])",
    ]

    # Add details about content type
    if result.get("is_directory", False):
        details.append("[bold green]Content type: Directory[/bold green]")
    else:
        details.append("[bold blue]Content type: File[/bold blue]")

    if result.get("decrypted"):
        details.append("[bold yellow]File was decrypted during download[/bold yellow]")

    print_panel("\n".join(details), title="Download Complete")

    return 0


async def handle_exists(client: HippiusClient, cid: str) -> int:
    """Handle the exists command"""
    info(f"Checking if CID [bold cyan]{cid}[/bold cyan] exists on IPFS...")
    result = await client.exists(cid)

    # Use the formatted CID from the result
    formatted_cid = result["formatted_cid"]
    exists = result["exists"]

    if exists:
        success(f"CID [bold cyan]{formatted_cid}[/bold cyan] exists on IPFS")

        if result.get("gateway_url"):
            log(f"Gateway URL: [link]{result['gateway_url']}[/link]")

            # Display download command in a panel
            command = f"[bold green underline]hippius download {formatted_cid} <output_path>[/bold green underline]"
            print_panel(command, title="Download Command")
    else:
        error(f"CID [bold cyan]{formatted_cid}[/bold cyan] does not exist on IPFS")

    return 0


async def handle_cat(
    client: HippiusClient, cid: str, max_size: int, decrypt: Optional[bool] = None
) -> int:
    """Handle the cat command"""
    info(f"Displaying content of CID [bold cyan]{cid}[/bold cyan]...")
    with tempfile.NamedTemporaryFile() as temp:
        temp_path = temp.name
        download_result = await client.download_file(cid, temp_path, decrypt=decrypt)
        file_size = os.path.getsize(temp_path)

        # Read content based on max size
        with open(temp_path, "rb") as f:
            content = f.read(max_size)

        # Try to display as text, fall back to binary info
        try:
            decoded = content.decode("utf-8")
            log(
                f"\nContent (first [bold]{min(max_size, file_size):,}[/bold] bytes):",
                style="blue",
            )
            console.print("--------------------------------------------", style="dim")
            console.print(decoded)
            console.print("--------------------------------------------", style="dim")
        except UnicodeDecodeError:
            log("\nBinary content (showing size information only):", style="yellow")
            log(
                f"Total size: [bold cyan]{file_size:,}[/bold cyan] bytes ([bold cyan]{download_result['size_formatted']}[/bold cyan])"
            )
            log("Content type appears to be binary", style="yellow")

        notes = []
        if file_size > max_size:
            notes.append(
                f"Content truncated. Total file size: [bold]{file_size:,}[/bold] bytes"
            )
            notes.append(
                f"Use '[bold]hippius download {cid} <output_path>[/bold]' to download the entire file"
            )

        if download_result.get("decrypted"):
            notes.append(
                "[bold yellow]File was decrypted during download[/bold yellow]"
            )

        if notes:
            print_panel("\n".join(notes), title="Notes")


async def handle_store(
    client: HippiusClient,
    file_path: str,
    miner_ids: Optional[List[str]] = None,
    encrypt: Optional[bool] = None,
    publish: bool = True,
) -> int:
    """Handle the store command (upload file to IPFS and store on Substrate)"""
    if not os.path.exists(file_path):
        error(f"File [bold]{file_path}[/bold] does not exist")
        return 1

    if not os.path.isfile(file_path):
        error(f"[bold]{file_path}[/bold] is not a file")
        return 1

    # If publishing is enabled, ensure we have a valid substrate client by accessing it
    # This will trigger password prompts if needed right at the beginning
    if publish and hasattr(client, "substrate_client") and client.substrate_client:
        try:
            # Force keypair initialization - this will prompt for password if needed
            _ = client.substrate_client._ensure_keypair()
        except Exception as e:
            warning(f"Failed to initialize blockchain client: {str(e)}")
            warning("Will continue with upload but blockchain publishing may fail")

    # Get file size for display
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    # Format size for display
    if file_size >= 1024 * 1024:
        size_formatted = f"{file_size / (1024 * 1024):.2f} MB"
    else:
        size_formatted = f"{file_size / 1024:.2f} KB"

    # Upload information panel
    upload_info = [
        f"File: [bold]{file_name}[/bold]",
        f"Size: [bold cyan]{size_formatted}[/bold cyan] ({file_size:,} bytes)",
    ]

    # Add encryption status
    if encrypt is True:
        upload_info.append("[bold green]Encryption: Enabled[/bold green]")
    elif encrypt is False:
        upload_info.append("[bold red]Encryption: Disabled[/bold red]")
    else:
        upload_info.append(
            "[bold yellow]Encryption: Using default setting[/bold yellow]"
        )

    # Add publishing status
    if not publish:
        upload_info.append(
            "[bold yellow]Publishing: Disabled (local upload only)[/bold yellow]"
        )
        log(
            "\nUpload will be local only - not publishing to blockchain or pinning to IPFS"
        )
    else:
        upload_info.append(
            "[bold green]Publishing: Enabled (publishing to blockchain)[/bold green]"
        )

    # Parse miner IDs if provided
    miner_id_list = None
    if miner_ids:
        miner_id_list = [m.strip() for m in miner_ids if m.strip()]
        upload_info.append(
            f"Targeting [bold]{len(miner_id_list)}[/bold] miners for storage"
        )

    # Display upload information panel
    print_panel("\n".join(upload_info), title="Upload Operation")

    # Create progress for the upload process
    with create_progress() as progress:
        # Add a task for the upload
        task = progress.add_task("[cyan]Uploading...", total=100)

        # We can't track actual progress from the client.store_file method yet,
        # so we'll update the progress periodically
        start_time = time.time()

        # Create a task to update the progress while waiting for the upload
        async def update_progress():
            while not progress.finished:
                # Since we don't have actual progress data, we'll use time as a proxy
                # The progress will move faster at first, then slow down
                elapsed = time.time() - start_time
                # Use a logarithmic function to simulate progress
                # This is just an estimation and not actual progress
                pct = min(95, 100 * (1 - 1 / (1 + elapsed / 10)))
                progress.update(task, completed=pct)
                await asyncio.sleep(0.1)

        # Start the progress updater task
        updater = asyncio.create_task(update_progress())

        try:
            # Use the upload_file method to get the CID
            result = await client.upload_file(
                file_path=file_path,
                encrypt=encrypt,
            )

            # If publishing is enabled, store on blockchain
            if publish and result.get("cid"):
                try:
                    # Pin and publish the file globally
                    # First pin in IPFS (essential step for publishing)
                    await client.ipfs_client.pin(result["cid"])

                    # Then publish globally to make available across network
                    publish_result = await client.ipfs_client.publish_global(
                        result["cid"]
                    )

                    log(
                        "\n[green]File has been pinned to IPFS and published to the network[/green]"
                    )

                    # Add gateway URL to the result for use in output
                    if "cid" in result:
                        result[
                            "gateway_url"
                        ] = f"{client.ipfs_client.gateway}/ipfs/{result['cid']}"

                    # Store on blockchain - miners are optional
                    # Create a file input for blockchain storage
                    file_input = FileInput(file_hash=result["cid"], file_name=file_name)

                    # Submit storage request
                    tx_hash = await client.substrate_client.storage_request(
                        files=[file_input], miner_ids=miner_id_list
                    )

                    # Add transaction hash to result
                    result["transaction_hash"] = tx_hash

                    # Add a note about the pinning status command
                    log(
                        "\n[bold yellow]Note:[/bold yellow] The pinning-status command will show a different CID (metadata) rather than the direct file CID."
                    )
                except Exception as e:
                    warning(f"Failed to publish file globally: {str(e)}")

            progress.update(task, completed=100)
            updater.cancel()

            elapsed_time = time.time() - start_time

            # Success panel with results
            success_info = [
                f"Upload completed in [bold green]{elapsed_time:.2f}[/bold green] seconds!",
                f"IPFS CID: [bold cyan]{result['cid']}[/bold cyan]",
            ]

            # Always add the gateway URL
            gateway_url = result.get("gateway_url")
            if not gateway_url and "cid" in result:
                gateway_url = f"{client.ipfs_client.gateway}/ipfs/{result['cid']}"

            if gateway_url:
                success_info.append(f"Gateway URL: [link]{gateway_url}[/link]")

            if result.get("encrypted"):
                success_info.append(
                    "[bold yellow]File was encrypted during upload[/bold yellow]"
                )

            if not publish:
                success_info.append(
                    "[bold yellow]File was uploaded locally only (not published to blockchain)[/bold yellow]"
                )

            print_panel("\n".join(success_info), title="Upload Successful")

            # If we stored in the marketplace
            if "transaction_hash" in result:
                log(
                    f"\nStored in marketplace. Transaction hash: [bold]{result['transaction_hash']}[/bold]"
                )

            # Display download command in a panel
            command = f"[bold green underline]hippius download {result['cid']} <output_path>[/bold green underline]"
            print_panel(command, title="Download Command")

            return 0

        except Exception as e:
            # Cancel the updater task in case of error
            updater.cancel()
            error(f"Upload failed: {str(e)}")


async def handle_store_dir(
    client: HippiusClient,
    dir_path: str,
    miner_ids: Optional[List[str]] = None,
    encrypt: Optional[bool] = None,
    publish: bool = True,
) -> int:
    """Handle the store directory command"""
    if not os.path.exists(dir_path):
        error(f"Directory [bold]{dir_path}[/bold] does not exist")
        return 1

    if not os.path.isdir(dir_path):
        error(f"[bold]{dir_path}[/bold] is not a directory")
        return 1

    # If publishing is enabled, ensure we have a valid substrate client by accessing it
    # This will trigger password prompts if needed right at the beginning
    if publish and hasattr(client, "substrate_client") and client.substrate_client:
        try:
            # Force keypair initialization - this will prompt for password if needed
            _ = client.substrate_client._ensure_keypair()
        except Exception as e:
            warning(f"Failed to initialize blockchain client: {str(e)}")
            warning("Will continue with upload but blockchain publishing may fail")

    # Upload information panel
    upload_info = [f"Directory: [bold]{dir_path}[/bold]"]

    # Add encryption status
    if encrypt is True:
        upload_info.append("[bold green]Encryption: Enabled[/bold green]")
    elif encrypt is False:
        upload_info.append("[bold red]Encryption: Disabled[/bold red]")
    else:
        upload_info.append(
            "[bold yellow]Encryption: Using default setting[/bold yellow]"
        )

    # Parse miner IDs if provided
    miner_id_list = None
    if miner_ids:
        miner_id_list = [m.strip() for m in miner_ids if m.strip()]
        upload_info.append(
            f"Targeting [bold]{len(miner_id_list)}[/bold] miners for storage"
        )

    # Display upload information panel
    print_panel("\n".join(upload_info), title="Directory Upload Operation")

    # Create progress for the directory upload process
    with create_progress() as progress:
        # Add a task for the directory upload
        task = progress.add_task("[cyan]Uploading directory...", total=100)

        # We can't track actual progress from the client.store_directory method yet,
        # so we'll update the progress periodically
        start_time = time.time()

        # Create a task to update the progress while waiting for the upload
        async def update_progress():
            while not progress.finished:
                # Since we don't have actual progress data, we'll use time as a proxy
                # The progress will move faster at first, then slow down
                elapsed = time.time() - start_time
                # Use a logarithmic function to simulate progress
                # This is just an estimation and not actual progress
                pct = min(95, 100 * (1 - 1 / (1 + elapsed / 10)))
                progress.update(task, completed=pct)
                await asyncio.sleep(0.1)

        # Start the progress updater task
        updater = asyncio.create_task(update_progress())

        try:
            # Upload info message based on publish flag
            if not publish:
                upload_info.append(
                    "[bold yellow]Publishing: Disabled (local upload only)[/bold yellow]"
                )
                log(
                    "\nUpload will be local only - not publishing to blockchain or pinning to IPFS"
                )
            else:
                upload_info.append(
                    "[bold green]Publishing: Enabled (publishing to blockchain)[/bold green]"
                )

            # Display updated upload information panel
            print_panel("\n".join(upload_info), title="Directory Upload Operation")

            # Use the store_directory method
            result = await client.ipfs_client.upload_directory(
                dir_path=dir_path,
                encrypt=encrypt,
            )

            # Skip publishing to blockchain if publish is False
            if not publish:
                # Remove any blockchain-related data from result to ensure we don't try to use it
                if "transaction_hash" in result:
                    del result["transaction_hash"]
            else:
                # If we want to publish, make sure files are pinned globally
                try:
                    # Add gateway URL to the result for use in output
                    if "cid" in result:
                        result[
                            "gateway_url"
                        ] = f"{client.ipfs_client.gateway}/ipfs/{result['cid']}"

                    # Pin and publish the directory root CID globally
                    # First pin in IPFS (essential step for publishing)
                    await client.ipfs_client.pin(result["cid"])

                    # Then publish globally to make available across network
                    await client.ipfs_client.publish_global(result["cid"])

                    log(
                        "\n[green]Directory has been pinned to IPFS and published to the network[/green]"
                    )

                    # Also pin and publish individual files if available
                    for file_info in result.get("files", []):
                        if "cid" in file_info:
                            try:
                                # Pin each file to ensure availability
                                await client.ipfs_client.pin(file_info["cid"])

                                # Then publish globally
                                await client.ipfs_client.publish_global(
                                    file_info["cid"]
                                )
                            except Exception as e:
                                warning(
                                    f"Failed to publish file {file_info['name']} globally: {str(e)}"
                                )

                    # Store on blockchain if client is available - miners are optional
                    if hasattr(client, "substrate_client") and client.substrate_client:
                        # Create a file input for blockchain storage
                        file_input = FileInput(
                            file_hash=result["cid"],
                            file_name=os.path.basename(dir_path),
                        )

                        # This will prompt for a password if needed
                        tx_hash = await client.substrate_client.storage_request(
                            files=[file_input], miner_ids=miner_id_list
                        )

                        # Add transaction hash to result
                        result["transaction_hash"] = tx_hash

                        # Add a note about the pinning status command
                        log(
                            "\n[bold yellow]Note:[/bold yellow] The pinning-status command will show a different CID (metadata) rather than the direct directory CID."
                        )

                except Exception as e:
                    warning(f"Failed to publish directory globally: {str(e)}")

            # Complete the progress
            progress.update(task, completed=100)
            # Cancel the updater task
            updater.cancel()

            elapsed_time = time.time() - start_time

            # Success panel with results
            success_info = [
                f"Upload completed in [bold green]{elapsed_time:.2f}[/bold green] seconds!",
                f"Directory CID: [bold cyan]{result['cid']}[/bold cyan]",
            ]

            # Always add the gateway URL
            gateway_url = result.get("gateway_url")
            if not gateway_url and "cid" in result:
                gateway_url = f"{client.ipfs_client.gateway}/ipfs/{result['cid']}"

            if gateway_url:
                success_info.append(f"Gateway URL: [link]{gateway_url}[/link]")

            # Add encryption and publish status to success info
            if result.get("encrypted"):
                success_info.append(
                    "[bold yellow]Directory was encrypted during upload[/bold yellow]"
                )

            if not publish:
                success_info.append(
                    "[bold yellow]Directory was uploaded locally only (not published to blockchain)[/bold yellow]"
                )

            print_panel("\n".join(success_info), title="Directory Upload Successful")

            # Display uploaded files in a table
            if "files" in result:
                table_data = []
                for i, file_info in enumerate(result["files"], 1):
                    table_data.append(
                        {
                            "Index": str(i),
                            "Filename": file_info["name"],
                            "CID": file_info["cid"],
                        }
                    )

                print_table(
                    f"Uploaded {len(result['files'])} Files",
                    table_data,
                    ["Index", "Filename", "CID"],
                )

            # If publishing is enabled and we stored in the marketplace
            if publish:
                # We only include transaction hash stuff if we actually created a blockchain transaction
                if "transaction_hash" in result:
                    log(
                        f"\nStored in marketplace. Transaction hash: [bold]{result['transaction_hash']}[/bold]"
                    )
                else:
                    # If publish is true but no transaction hash, just indicate files were published to IPFS
                    log("\n[green]Directory was published to IPFS network.[/green]")
            elif not publish:
                log(
                    "\n[yellow]Files were uploaded locally only. No blockchain publication or IPFS pinning.[/yellow]"
                )

            return 0

        except Exception as e:
            # Cancel the updater task in case of error
            updater.cancel()
            error(f"Directory upload failed: {str(e)}")
            return 1


async def handle_credits(
    client: HippiusClient, account_address: Optional[str] = None
) -> int:
    """Handle the credits command"""
    info("Checking free credits for the account...")
    try:
        # Get the account address we're querying
        if account_address is None:
            # If no address provided, first try to get from keypair (if available)
            if (
                hasattr(client.substrate_client, "_keypair")
                and client.substrate_client._keypair is not None
            ):
                account_address = client.substrate_client._keypair.ss58_address
            else:
                # Get the active account name and its address
                from hippius_sdk.config import get_account_address, get_active_account

                active_account = get_active_account()
                if active_account:
                    active_address = get_account_address(active_account)
                    if active_address:
                        account_address = active_address
                    else:
                        error(
                            f"Active account '{active_account}' does not have a valid address."
                        )
                        warning(
                            "Please provide an account address with '--account_address'"
                        )
                        return 1
                else:
                    error(
                        "No account address provided, no active account set, and client has no keypair."
                    )
                    warning(
                        "Please provide an account address with '--account_address' or set an active account with:"
                    )
                    log(
                        "  [bold green underline]hippius account switch <account_name>[/bold green underline]"
                    )
                    return 1

        credits = await client.substrate_client.get_free_credits(account_address)

        # Create a panel with credit information
        credit_info = [
            f"Free credits: [bold green]{credits:.6f}[/bold green]",
            f"Raw value: [dim]{int(credits * 1_000_000_000_000_000_000):,}[/dim]",
            f"Account address: [bold cyan]{account_address}[/bold cyan]",
        ]

        print_panel("\n".join(credit_info), title="Account Credits")

    except Exception as e:
        error(f"Error checking credits: {e}")
        return 1

    return 0


async def handle_files(
    client: HippiusClient,
    account_address: Optional[str] = None,
    show_all_miners: bool = False,
    file_cid: str = None,
) -> int:
    """Handle the files command"""
    # Get the account address we're querying
    if account_address is None:
        # If no address provided, try these options in order:
        # 1. Keypair from the client (if available)
        # 2. Address from active account
        # 3. Default address from config

        # Option 1: Try keypair from client
        if (
            hasattr(client.substrate_client, "_keypair")
            and client.substrate_client._keypair is not None
        ):
            account_address = client.substrate_client._keypair.ss58_address
        else:
            # Option 2: Try to get address from active account
            active_account = get_active_account()
            if active_account:
                account_address = get_account_address(active_account)

            # Option 3: If still not found, try default address
            if not account_address:
                default_address = get_default_address()
                if default_address:
                    account_address = default_address

            # If we still don't have an address, show error
            if not account_address:
                has_default = get_default_address() is not None
                error("No account address provided, and client has no keypair.")

                if has_default:
                    warning(
                        "Please provide an account address with '--account_address' or the default address may be invalid."
                    )
                else:
                    info(
                        "Please provide an account address with '--account_address' or set a default with:"
                    )
                    log(
                        "  [bold green underline]hippius address set-default <your_account_address>[/bold green underline]"
                    )
                return 1

    # Get files from the marketplace
    info(f"Getting files for account: [bold]{account_address}[/bold]")
    files = await client.substrate_client.get_user_files(account_address)

    if not files:
        info("No files found for this account")
        return 0

    # Display summary
    success(f"Found [bold]{len(files)}[/bold] files")

    # Display file information
    for i, file in enumerate(files, 1):
        # Extract file details
        cid = file["cid"]

        if file_cid and file_cid != cid:
            continue

        size_formatted = file["size_formatted"]
        size_raw = file["file_size"]
        file_name = file["file_name"]
        file_hash = file["file_hash"]
        selected_validator = file["selected_validator"]

        # Create a panel for each file
        file_info = [
            f"CID: [bold cyan]{cid}[/bold cyan]",
            f"Size: [bold]{size_raw}[/bold] bytes ([bold cyan]{size_formatted}[/bold cyan])",
            f"File name: [bold]{file_name}[/bold]",
            f"File hash: {file_hash}",
            f"Selected validator: {selected_validator}",
        ]

        # Show miners if requested
        if show_all_miners and "miner_ids" in file:
            miners = file.get("miner_ids", [])
            if miners:
                file_info.append(f"Stored on [bold]{len(miners)}[/bold] miners:")
                miners_list = []
                for j, miner in enumerate(miners, 1):
                    miners_list.append(f"  {j}. {miner}")
                file_info.append("\n".join(miners_list))
            else:
                file_info.append("No miners assigned yet")

        print_panel("\n".join(file_info), title=f"File #{i}: {file_name}")


async def handle_pinning_status(
    client: HippiusClient,
    account_address: Optional[str] = None,
    verbose: bool = False,
    show_contents: bool = True,
) -> int:
    """Handle the pinning-status command"""
    try:
        info("Checking pinning status of files...")

        # Use the get_pinning_status method from the substrate client
        pins = client.substrate_client.get_pinning_status(account_address)

        if not pins:
            log("No active pins found")
            return 0

        log(f"\nFound {len(pins)} pinning requests:")

        for i, pin in enumerate(pins, 1):
            try:
                # Get the CID from the pin data
                cid = pin.get("cid")

                # Display pin information
                log(f"\n{i}. Metadata CID: [bold]{cid}[/bold]")
                log(f"   File Name: {pin['file_name']}")
                status = "Assigned" if pin["is_assigned"] else "Pending"
                log(f"   Status: {status}")
                log(f"   Created At Block: {pin['created_at']}")
                log(f"   Last Charged At Block: {pin['last_charged_at']}")
                log(f"   Owner: {pin['owner']}")
                log(f"   Total Replicas: {pin['total_replicas']}")
                log(f"   Selected Validator: {pin['selected_validator']}")
                miners = pin["miner_ids"]
                if miners:
                    log(f"   Miners: {', '.join(miners[:3])}")
                    if len(miners) > 3:
                        log(f"   ... and {len(miners) - 3} more")
                else:
                    log("   Miners: None assigned yet")

                # Show content info if requested
                if show_contents:
                    # Add gateway URL
                    gateway_url = f"{client.ipfs_client.gateway}/ipfs/{cid}"
                    log(f"   Gateway URL: {gateway_url}")

                    # Try to decode the metadata file to get the original file CID
                    try:
                        # Fetch the content
                        cat_result = await client.ipfs_client.cat(cid)

                        # Try to parse as JSON
                        try:
                            # Decode JSON from content
                            metadata_json = json.loads(
                                cat_result["content"].decode("utf-8")
                            )

                            # This should be an array with one or more file entries
                            if (
                                isinstance(metadata_json, list)
                                and len(metadata_json) > 0
                            ):
                                log(f"\n   [bold cyan]Contained files:[/bold cyan]")
                                for idx, file_entry in enumerate(metadata_json, 1):
                                    if isinstance(file_entry, dict):
                                        original_cid = file_entry.get("cid")
                                        original_name = file_entry.get("filename")
                                        if original_cid:
                                            log(
                                                f"   {idx}. Original CID: [bold green]{original_cid}[/bold green]"
                                            )
                                            if original_name:
                                                log(f"      Name: {original_name}")
                                            log(
                                                f"      Gateway URL: {client.ipfs_client.gateway}/ipfs/{original_cid}"
                                            )
                        except json.JSONDecodeError:
                            if verbose:
                                log(
                                    "   [yellow]Could not parse metadata as JSON[/yellow]"
                                )
                    except Exception as e:
                        if verbose:
                            warning(f"   Error getting original file CIDs: {e}")
            except Exception as e:
                warning(f"Error processing pin {i}: {e}")
                if verbose:
                    log(f"Raw pin data: {pin}")

        return 0

    except Exception as e:
        error(f"Error checking pinning status: {str(e)}")
        return 1


async def handle_ec_files(
    client: HippiusClient,
    account_address: Optional[str] = None,
    show_all_miners: bool = False,
    show_chunks: bool = False,
    filter_metadata_cid: str = None,
) -> int:
    """Handle the ec-files command"""
    if account_address is None:
        # If no address provided, first try to get from keypair (if available)
        if (
            hasattr(client.substrate_client, "_keypair")
            and client.substrate_client._keypair is not None
        ):
            account_address = client.substrate_client._keypair.ss58_address
        else:
            # Use the active account address instead of default address
            from hippius_sdk.config import get_account_address, get_active_account

            active_account = get_active_account()
            if active_account:
                account_address = get_account_address(active_account)

            if not account_address:
                error("No account address provided and client has no keypair.")
                info(
                    "Please provide an account address with '--account_address' or set an active account with:"
                )
                log(
                    "  [bold green underline]hippius account switch <account_name>[/bold green underline]"
                )
                return 1

    info(f"Getting erasure-coded files for account: [bold]{account_address}[/bold]")

    # Get all files from the marketplace
    files = await client.substrate_client.get_user_files(account_address)

    # Separate metadata files and chunks
    ec_metadata_files = []
    chunk_files = []

    for file in files:
        if file["file_name"].endswith(".ec_metadata"):
            ec_metadata_files.append(file)
        elif file["file_name"].endswith(".ec"):
            chunk_files.append(file)

    if not ec_metadata_files:
        info("No erasure-coded files found for this account")
        return 0

    # Display summary
    success(f"Found [bold]{len(ec_metadata_files)}[/bold] erasure-coded files")
    if chunk_files:
        log(f"Found [bold]{len(chunk_files)}[/bold] chunk files")

    # Store metadata CIDs for reconstruction command at the end
    metadata_cids = []

    # Process each metadata file
    for i, metadata_file in enumerate(ec_metadata_files, 1):
        metadata_cid = metadata_file["cid"]

        if filter_metadata_cid and metadata_cid != filter_metadata_cid:
            continue

        metadata_file_name = metadata_file["file_name"]
        metadata_size = metadata_file["file_size"]
        metadata_size_formatted = metadata_file["size_formatted"]

        # Store metadata CID for reconstruction command
        metadata_cids.append(metadata_cid)

        # Basic file info panel (always show this)
        file_info = [
            f"Metadata filename: [bold]{metadata_file_name}[/bold]",
            f"Metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
            f"Metadata size: [bold]{metadata_size}[/bold] bytes ([bold cyan]{metadata_size_formatted}[/bold cyan])",
            f"Selected validator: {metadata_file['selected_validator']}",
        ]

        # Add miners info if available and requested - with consistent formatting
        if show_all_miners and metadata_file["miner_ids"]:
            miners = metadata_file["miner_ids"]
            file_info.append(f"Metadata stored on [bold]{len(miners)}[/bold] miners:")
            miners_list = []
            for j, miner in enumerate(miners, 1):
                miners_list.append(f"  {j}. {miner}")
            file_info.append("\n".join(miners_list))

        # If show_chunks is enabled, download the metadata file and get chunk information
        if show_chunks:
            with tempfile.NamedTemporaryFile() as temp:
                temp_path = temp.name

                await client.download_file(metadata_cid, temp_path)

                # Open and parse the metadata file
                with open(temp_path, "r") as f:
                    metadata_content = json.load(f)

                # Extract the original file information
                original_file = metadata_content["original_file"]
                original_file_name = original_file["name"]
                original_file_size = original_file["size"]

                # Extract the erasure coding parameters
                erasure_coding = metadata_content["erasure_coding"]
                file_id = erasure_coding["file_id"]
                k = erasure_coding["k"]
                m = erasure_coding["m"]
                chunk_size = erasure_coding["chunk_size"]
                encrypted = erasure_coding["encrypted"]

                # Extract the chunks information
                chunks_info = metadata_content["chunks"]

                # Update file_info with detailed metadata information
                file_info = [
                    f"Original file: [bold]{original_file_name}[/bold]",
                    f"Size: [bold]{original_file_size}[/bold] bytes ([bold cyan]{format_size(original_file_size)}[/bold cyan])",
                    f"File hash: {original_file['hash']}",
                    f"Metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
                    f"File ID: [bold yellow]{file_id}[/bold yellow]",
                    f"Erasure coding: k=[bold]{k}[/bold], m=[bold]{m}[/bold] (need {k} of {m} chunks to reconstruct)",
                    f"Chunk size: [bold]{format_size(chunk_size)}[/bold]",
                    f"Encrypted: [bold]{'Yes' if encrypted else 'No'}[/bold]",
                    f"Total chunks from metadata: [bold]{len(chunks_info)}[/bold]",
                ]

                # Match chunks from the blockchain with the metadata by CID
                matching_chunks = []
                chunk_cids_in_metadata = []

                # Create a mapping of CIDs from metadata
                for chunk in chunks_info:
                    # Extract CID (handle both string and dict formats)
                    chunk_cid = chunk["cid"]
                    if isinstance(chunk_cid, dict) and "cid" in chunk_cid:
                        chunk_cid = chunk_cid["cid"]
                    chunk_cids_in_metadata.append(chunk_cid)

                # Find matching chunks
                for chunk_file in chunk_files:
                    if (
                        chunk_file["cid"] in chunk_cids_in_metadata
                        or file_id in chunk_file["file_name"]
                    ):
                        matching_chunks.append(chunk_file)

                # Add information about matched chunks
                if matching_chunks:
                    file_info.append(
                        f"Found [bold]{len(matching_chunks)}/{len(chunks_info)}[/bold] chunks in blockchain"
                    )

                    # Calculate if we have enough chunks for reconstruction
                    chunks_needed = k
                    if len(matching_chunks) >= chunks_needed:
                        file_info.append(
                            "[bold green]✓ Enough chunks available for reconstruction[/bold green]"
                        )
                    else:
                        file_info.append(
                            "[bold red]✗ Not enough chunks available for reconstruction[/bold red]"
                        )
                else:
                    file_info.append(
                        "[bold yellow]No associated chunks found in blockchain[/bold yellow]"
                    )

                # Display the panel with all file information
                print_panel(
                    "\n".join(file_info), title=f"File #{i}: {original_file_name}"
                )

                # Display the chunks in a table if we found any
                if matching_chunks:
                    # Limit the number of chunks displayed
                    MAX_DISPLAYED_CHUNKS = 25
                    chunk_table = []

                    # Sort chunks by original_chunk_idx and share_idx for better display
                    def chunk_sort_key(chunk):
                        chunk_name = chunk["file_name"]
                        chunk_parts = []
                        if "_chunk_" in chunk_name:
                            chunk_parts = (
                                chunk_name.split("_chunk_")[1].split(".")[0].split("_")
                            )

                        original_chunk_idx = (
                            int(chunk_parts[0])
                            if len(chunk_parts) > 0 and chunk_parts[0].isdigit()
                            else 0
                        )
                        share_idx = (
                            int(chunk_parts[1])
                            if len(chunk_parts) > 1 and chunk_parts[1].isdigit()
                            else 0
                        )
                        return (original_chunk_idx, share_idx)

                    sorted_chunks = sorted(matching_chunks, key=chunk_sort_key)
                    displayed_chunks = sorted_chunks[:MAX_DISPLAYED_CHUNKS]

                    for j, chunk in enumerate(displayed_chunks, 1):
                        # Extract information from the chunk filename
                        chunk_name = chunk["file_name"]
                        chunk_parts = []

                        # Try to extract original_chunk_idx and share_idx
                        if "_chunk_" in chunk_name:
                            chunk_parts = (
                                chunk_name.split("_chunk_")[1].split(".")[0].split("_")
                            )

                        original_chunk_idx = (
                            chunk_parts[0] if len(chunk_parts) > 0 else "?"
                        )
                        share_idx = chunk_parts[1] if len(chunk_parts) > 1 else "?"

                        chunk_table.append(
                            {
                                "Index": str(j),
                                "Name": chunk_name,
                                "Original": original_chunk_idx,
                                "Share": share_idx,
                                "Size": chunk["size_formatted"],
                                "CID": chunk["cid"][:10] + "..." + chunk["cid"][-6:]
                                if len(chunk["cid"]) > 20
                                else chunk["cid"],
                            }
                        )

                    # Print chunk table without title, using dim (grey) styling
                    print_table(
                        "",  # Empty title
                        chunk_table,
                        ["Index", "Name", "Original", "Share", "Size", "CID"],
                        style="dim",  # Use dim (grey) styling for chunk tables
                    )

                    # If there are more chunks than the display limit, show a compact note in dim text
                    if len(matching_chunks) > MAX_DISPLAYED_CHUNKS:
                        log(
                            f"[dim](Showing {MAX_DISPLAYED_CHUNKS} of {len(matching_chunks)} chunks. Use 'hippius ipfs download {metadata_cid}' to view all.)[/dim]"
                        )

        else:
            # If show_chunks is disabled, just display the basic file information
            print_panel("\n".join(file_info), title=f"File #{i}: {metadata_file_name}")

    # Show a generic reconstruction command at the end
    if metadata_cids:
        # Include a real example with the first metadata CID
        example_cid = metadata_cids[0] if metadata_cids else "<METADATA_CID>"
        print_panel(
            f"[bold green underline]hippius reconstruct <METADATA_CID> <OUTPUT_FILENAME>[/bold green underline]\n\nExample:\n[bold green underline]hippius reconstruct {example_cid} reconstructed_file.bin[/bold green underline]",
            title="Reconstruction Command",
        )

    return 0


async def handle_erasure_code(
    client: HippiusClient,
    file_path: str,
    k: int,
    m: int,
    chunk_size: int,
    miner_ids: Optional[List[str]] = None,
    encrypt: Optional[bool] = None,
    publish: bool = True,
    verbose: bool = False,
) -> int:
    """Handle the erasure-code command"""
    if not os.path.exists(file_path):
        error(f"File [bold]{file_path}[/bold] does not exist")
        return 1

    if not os.path.isfile(file_path):
        error(f"[bold]{file_path}[/bold] is not a file")
        return 1

    # Check if zfec is installed
    try:
        import zfec
    except ImportError:
        error("zfec is required for erasure coding")
        log(
            "Install it with: [bold green underline]pip install zfec[/bold green underline]"
        )
        log(
            "Then update your environment: [bold green underline]poetry add zfec[/bold green underline]"
        )
        return 1

    # Request password early if we're going to publish to the blockchain
    if publish and client.substrate_client._seed_phrase is None:
        # First check if we have an encrypted seed phrase that will require a password
        config = load_config()
        account_name = client.substrate_client._account_name or get_active_account()

        if account_name and account_name in config["substrate"].get("accounts", {}):
            account_data = config["substrate"]["accounts"][account_name]
            is_encoded = account_data.get("seed_phrase_encoded", False)

            if is_encoded:
                warning("Wallet password will be required for publishing to blockchain")
                password = getpass.getpass(
                    "Enter password to decrypt seed phrase: \n\n"
                )

                # Store the password in client for later use
                client.substrate_client._seed_phrase_password = password

                # Pre-authenticate to ensure the password is correct
                try:
                    seed_phrase = decrypt_seed_phrase(password, account_name)
                    if not seed_phrase:
                        error("Failed to decrypt seed phrase. Incorrect password?")
                        return 1
                    client.substrate_client._seed_phrase = seed_phrase
                except Exception as e:
                    error(f"Error decrypting seed phrase: {e}")
                    return 1

    # Get file size
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    # Convert chunk size from MB to bytes if needed
    if chunk_size < 1024:  # Assume it's in MB if small
        chunk_size = chunk_size * 1024 * 1024

    # Calculate potential chunks
    potential_chunks = file_size / chunk_size
    if potential_chunks < k:
        warning("File is too small for the requested parameters.")

        # Calculate new chunk size to get exactly k chunks
        new_chunk_size = file_size / k

        new_chunk_size = int(new_chunk_size)
        new_chunk_size = max(1, new_chunk_size)

        # Create a panel with parameter adjustment information
        adjustment_info = [
            f"Original parameters: k=[bold]{k}[/bold], m=[bold]{m}[/bold], chunk size=[bold]{chunk_size / 1024 / 1024:.2f} MB[/bold]",
            f"Would create only [bold red]{potential_chunks:.2f}[/bold red] chunks, which is less than k=[bold]{k}[/bold]",
            f"Automatically adjusting chunk size to [bold green]{new_chunk_size / 1024 / 1024:.6f} MB[/bold green] to create at least {k} chunks",
        ]
        print_panel("\n".join(adjustment_info), title="Parameter Adjustment")

        chunk_size = new_chunk_size

    # Calculate total number of chunks that will be created
    total_original_chunks = max(1, int(math.ceil(file_size / chunk_size)))
    total_encoded_chunks = total_original_chunks * m
    estimated_size_per_chunk = min(chunk_size, file_size / total_original_chunks)

    # Create parameter information panel
    param_info = [
        f"File: [bold]{file_name}[/bold] ([bold cyan]{file_size / 1024 / 1024:.2f} MB[/bold cyan])",
        f"Parameters: k=[bold]{k}[/bold], m=[bold]{m}[/bold] (need {k} of {m} chunks to reconstruct)",
        f"Chunk size: [bold cyan]{chunk_size / 1024 / 1024:.6f} MB[/bold cyan]",
        f"Total chunks to be created: [bold yellow]{total_encoded_chunks}[/bold yellow] ({total_original_chunks} original chunks × {m} encoded chunks each)",
        f"Estimated storage required: [bold magenta]{(total_encoded_chunks * estimated_size_per_chunk) / (1024 * 1024):.2f} MB[/bold magenta]",
    ]

    # Add encryption status
    if encrypt:
        param_info.append("[bold green]Encryption: Enabled[/bold green]")
    else:
        param_info.append("[bold yellow]Encryption: Disabled[/bold yellow]")

    # Add publish status
    if publish:
        param_info.append(
            "[bold blue]Publishing: Enabled[/bold blue] (will store on blockchain)"
        )
    else:
        param_info.append(
            "[bold cyan]Publishing: Disabled[/bold cyan] (local only, no password needed)"
        )

    # Parse miner IDs if provided
    miner_id_list = None
    if miner_ids:
        miner_id_list = [m.strip() for m in miner_ids if m.strip()]
        param_info.append(
            f"Targeting [bold]{len(miner_id_list)}[/bold] miners for storage"
        )

    # Display parameter information panel
    print_panel("\n".join(param_info), title="Erasure Coding Operation")

    start_time = time.time()

    # Create progress for the erasure coding operation
    with create_progress() as progress:
        # Add tasks for the different stages
        processing_task = progress.add_task(
            "[cyan]Processing file...", total=100, visible=False
        )
        encoding_task = progress.add_task(
            "[green]Encoding chunks...", total=100, visible=False
        )
        upload_task = progress.add_task(
            "[blue]Uploading chunks...", total=100, visible=False
        )

        # Progress callback function to update the appropriate task
        def update_progress_bar(stage, current, total):
            pct = min(100, int(current / total * 100))

            if stage == "processing":
                progress.update(processing_task, completed=pct)
                if pct >= 100 and not progress.tasks[encoding_task].visible:
                    progress.update(encoding_task, visible=True)

            elif stage == "encoding":
                progress.update(encoding_task, completed=pct)
                if pct >= 100 and not progress.tasks[upload_task].visible:
                    progress.update(upload_task, visible=True)

            elif stage == "upload":
                progress.update(upload_task, completed=pct)

        # As a fallback, create a task to update the general progress if no callbacks are received
        async def update_general_progress():
            while not progress.finished:
                elapsed = time.time() - start_time
                # If we haven't shown the encoding task yet, update the processing task
                if not progress.tasks[encoding_task].visible:
                    pct = min(95, 100 * (1 - 1 / (1 + elapsed / 5)))
                    progress.update(processing_task, completed=pct)
                    if pct > 90:
                        progress.update(encoding_task, visible=True)
                # If we haven't shown the upload task yet, update the encoding task
                elif not progress.tasks[upload_task].visible and elapsed > 3:
                    pct = min(95, 100 * (1 - 1 / (1 + (elapsed - 3) / 5)))
                    progress.update(encoding_task, completed=pct)
                    if pct > 90:
                        progress.update(upload_task, visible=True)

                await asyncio.sleep(0.1)

        # Start the fallback progress updater task
        updater = asyncio.create_task(update_general_progress())

        try:
            # Use the store_erasure_coded_file method directly from HippiusClient
            result = await client.store_erasure_coded_file(
                file_path=file_path,
                k=k,
                m=m,
                chunk_size=chunk_size,
                encrypt=encrypt,
                miner_ids=miner_id_list,
                max_retries=3,
                verbose=verbose,
                progress_callback=update_progress_bar,
                publish=publish,
            )

            # Complete all progress tasks
            progress.update(processing_task, completed=100)
            progress.update(encoding_task, completed=100, visible=True)
            progress.update(upload_task, completed=100, visible=True)
            # Cancel the updater task
            updater.cancel()

            # Store the original result before potentially overwriting it with publish result
            storage_result = result.copy()
            metadata_cid = storage_result.get("metadata_cid", "unknown")

            # If publish flag is set, publish to the global IPFS network
            if publish:
                if metadata_cid != "unknown":
                    info("Publishing to global IPFS network...")
                try:
                    # Publish the metadata to the global IPFS network
                    publish_result = await client.ipfs_client.publish_global(
                        metadata_cid
                    )
                    if publish_result.get("published", False):
                        success("Successfully published to global IPFS network")
                        log(
                            f"Access URL: [link]{client.ipfs_client.gateway}/ipfs/{metadata_cid}[/link]"
                        )
                    else:
                        warning(
                            f"{publish_result.get('message', 'Failed to publish to global network')}"
                        )
                except Exception as e:
                    warning(f"Failed to publish to global IPFS network: {str(e)}")

            elapsed_time = time.time() - start_time

            # Display metadata
            metadata = storage_result.get("metadata", {})
            total_files_stored = storage_result.get("total_files_stored", 0)

            original_file = metadata.get("original_file", {})
            erasure_coding = metadata.get("erasure_coding", {})

            # Create a summary panel with the erasure coding results
            summary_lines = [
                f"Completed in [bold green]{elapsed_time:.2f}[/bold green] seconds!"
            ]

            # If metadata_cid is known but metadata is empty, try to get file info from result directly
            if metadata_cid != "unknown" and not original_file:
                file_name = os.path.basename(file_path)
                file_size = (
                    os.path.getsize(file_path) if os.path.exists(file_path) else 0
                )

                # Use direct values from input parameters when metadata is not available
                summary_lines.extend(
                    [
                        f"Original file: [bold]{file_name}[/bold] ([bold cyan]{file_size / 1024 / 1024:.2f} MB[/bold cyan])",
                        f"Parameters: k=[bold]{k}[/bold], m=[bold]{m}[/bold]",
                        f"Total files stored in marketplace: [bold]{total_files_stored}[/bold]",
                        f"Metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
                    ]
                )

                # Add publish status if applicable
                if publish:
                    summary_lines.extend(
                        [
                            "Published to global IPFS: [bold green]Yes[/bold green]",
                            f"Global access URL: [link]{client.ipfs_client.gateway}/ipfs/{metadata_cid}[/link]",
                        ]
                    )
            else:
                summary_lines.extend(
                    [
                        f"Original file: [bold]{original_file.get('name')}[/bold] ([bold cyan]{original_file.get('size', 0) / 1024 / 1024:.2f} MB[/bold cyan])",
                        f"File ID: [bold]{erasure_coding.get('file_id')}[/bold]",
                        f"Parameters: k=[bold]{erasure_coding.get('k')}[/bold], m=[bold]{erasure_coding.get('m')}[/bold]",
                        f"Total chunks: [bold]{len(metadata.get('chunks', []))}[/bold]",
                        f"Total files stored in marketplace: [bold]{total_files_stored}[/bold]",
                        f"Metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
                    ]
                )

                # Add publish status if applicable
                if publish:
                    summary_lines.extend(
                        [
                            "Published to global IPFS: [bold green]Yes[/bold green]",
                            f"Global access URL: [link]{client.ipfs_client.gateway}/ipfs/{metadata_cid}[/link]",
                        ]
                    )

            # If we stored in the marketplace
            if "transaction_hash" in result:
                summary_lines.append(
                    f"Transaction hash: [bold]{result['transaction_hash']}[/bold]"
                )

            # Display the summary panel
            print_panel("\n".join(summary_lines), title="Erasure Coding Summary")

            # Get file name, either from metadata or directly from file path
            output_filename = original_file.get("name")
            if not output_filename:
                output_filename = os.path.basename(file_path)

            # Create reconstruction instructions panel
            reconstruction_lines = [
                "You will need:",
                f"  1. The metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
                f"  2. Access to at least [bold]{k}[/bold] chunks for each original chunk",
                "",
                "Reconstruction command:",
                f"[bold green underline]hippius reconstruct {metadata_cid} reconstructed_{output_filename}[/bold green underline]",
            ]

            print_panel(
                "\n".join(reconstruction_lines), title="Reconstruction Instructions"
            )

            return 0

        except Exception as e:
            # Cancel the updater task in case of error
            updater.cancel()
            error(f"Erasure coding failed: {str(e)}")

            # Provide helpful advice based on the error
            if "Wrong length" in str(e) and "input blocks" in str(e):
                # Create an advice panel for small file errors
                advice_lines = [
                    "This error typically occurs with very small files.",
                    "",
                    "Suggestions:",
                    "  1. Try using a smaller chunk size: [bold]--chunk-size 4096[/bold]",
                    "  2. Try using a smaller k value: [bold]--k 2[/bold]",
                    "  3. For very small files, consider using regular storage instead of erasure coding.",
                ]
                print_panel("\n".join(advice_lines), title="Troubleshooting")


async def handle_reconstruct(
    client: HippiusClient, metadata_cid: str, output_file: str, verbose: bool = False
) -> int:
    """Handle the reconstruct command"""
    # Create initial parameters panel
    param_info = [
        f"Metadata CID: [bold cyan]{metadata_cid}[/bold cyan]",
        f"Output file: [bold]{output_file}[/bold]",
    ]

    if verbose:
        param_info.append(
            "[bold yellow]Verbose mode enabled[/bold yellow] - will show detailed progress"
        )

    print_panel("\n".join(param_info), title="Reconstruction Operation")

    start_time = time.time()

    # Create progress for the reconstruction operation
    with create_progress() as progress:
        # Add a task for the reconstruction process
        download_task = progress.add_task("[cyan]Downloading metadata...", total=100)
        reconstruct_task = progress.add_task(
            "[green]Reconstructing file...", total=100, visible=False
        )

        # Create a task to update the progress while waiting for the operation
        async def update_progress():
            # Phase 1: Downloading metadata and chunks (first 40% of process)
            # Assume an approximate timing: phase1 = 5 seconds, phase2 = 10 seconds
            phase1_duration = 5
            total_duration = 15  # Estimation for both phases

            while not progress.finished:
                elapsed = time.time() - start_time

                # Phase 1: Downloading metadata and chunks (0-40%)
                if elapsed <= phase1_duration:
                    # Calculate progress for phase 1 (0-100%)
                    download_pct = min(100, elapsed / phase1_duration * 100)
                    progress.update(download_task, completed=download_pct)

                    # Make reconstruction task visible when metadata download starts progressing
                    if (
                        download_pct > 30
                        and not progress.tasks[reconstruct_task].visible
                    ):
                        progress.update(reconstruct_task, completed=0, visible=True)
                else:
                    # Ensure download task shows complete
                    progress.update(download_task, completed=100)

                    # Phase 2: Reconstructing (0-100%)
                    remaining_time = total_duration - phase1_duration
                    phase2_elapsed = elapsed - phase1_duration
                    if phase2_elapsed >= 0:
                        # Calculate progress for phase 2 (0-100%)
                        reconstruct_pct = min(95, phase2_elapsed / remaining_time * 100)
                        progress.update(
                            reconstruct_task, completed=reconstruct_pct, visible=True
                        )

                await asyncio.sleep(0.1)

        # Start the progress updater task
        updater = asyncio.create_task(update_progress())

        try:
            # Use the reconstruct_erasure_coded_file method
            result = await client.reconstruct_from_erasure_code(
                metadata_cid=metadata_cid, output_file=output_file, verbose=verbose
            )

            # Complete all progress tasks
            progress.update(download_task, completed=100)
            progress.update(reconstruct_task, completed=100)
            # Cancel the updater task
            updater.cancel()

            elapsed_time = time.time() - start_time

            # Display reconstruction results
            output_path = result.get("output_path", output_file)
            file_size = result.get("size_bytes", 0)
            size_formatted = format_size(file_size)

            # Create success panel
            success_info = [
                f"Reconstruction completed in [bold green]{elapsed_time:.2f}[/bold green] seconds!",
                f"Saved to: [bold]{output_path}[/bold]",
                f"Size: [bold cyan]{file_size:,}[/bold cyan] bytes ([bold cyan]{size_formatted}[/bold cyan])",
            ]

            if result.get("decrypted"):
                success_info.append(
                    "[bold yellow]File was decrypted during reconstruction[/bold yellow]"
                )

            print_panel("\n".join(success_info), title="Reconstruction Successful")

            return 0

        except Exception as e:
            # Cancel the updater task in case of error
            updater.cancel()
            error(f"Reconstruction failed: {str(e)}")

            if "No metadata found for CID" in str(e):
                advice_lines = [
                    "The metadata CID could not be found. Please check:",
                    "  1. The CID is correct",
                    "  2. The IPFS gateway is accessible",
                    "  3. If the file was published to the global IPFS network",
                ]
                print_panel("\n".join(advice_lines), title="Troubleshooting")

            elif "Failed to download chunk" in str(e):
                advice_lines = [
                    "Failed to download enough chunks for reconstruction. Please check:",
                    "  1. Your connection to the IPFS network",
                    "  2. If enough chunks are available (need at least k chunks)",
                    "  3. If the chunks are still pinned in the network",
                ]
                print_panel("\n".join(advice_lines), title="Troubleshooting")

            return 1


async def handle_delete(client: HippiusClient, cid: str, force: bool = False) -> int:
    """Handle the delete command for files or directories"""
    info(f"Preparing to delete content with CID: [bold cyan]{cid}[/bold cyan]")

    # First check if this is a directory
    try:
        exists_result = await client.exists(cid)
        if not exists_result["exists"]:
            error(f"CID [bold cyan]{cid}[/bold cyan] not found on IPFS")
            return 1
    except Exception as e:
        warning(f"Error checking if CID exists: {e}")

    if not force:
        warning("This will cancel storage and remove the content from the marketplace.")
        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm != "y":
            log("Deletion cancelled", style="yellow")
            return 0

    # Show spinner during deletion
    with console.status("[cyan]Deleting content...[/cyan]", spinner="dots") as status:
        result = await client.delete_file(cid)

    # Display results
    is_directory = result.get("is_directory", False)
    child_files = result.get("child_files", [])

    if is_directory:
        # Directory deletion
        details = [
            f"Successfully deleted directory: [bold cyan]{cid}[/bold cyan]",
            f"Child files unpinned: [bold]{len(child_files)}[/bold]",
        ]

        # If there are child files, show them in a table
        if child_files:
            table_data = []
            for i, file in enumerate(
                child_files[:10], 1
            ):  # Limit to first 10 files if many
                table_data.append(
                    {
                        "Index": str(i),
                        "Filename": file.get("name", "unknown"),
                        "CID": file.get("cid", "unknown"),
                    }
                )

            if len(child_files) > 10:
                table_data.append(
                    {
                        "Index": "...",
                        "Filename": f"({len(child_files) - 10} more files)",
                        "CID": "...",
                    }
                )

            print_table(
                "Unpinned Child Files", table_data, ["Index", "Filename", "CID"]
            )
    else:
        # Regular file deletion
        details = [f"Successfully deleted file: [bold cyan]{cid}[/bold cyan]"]

    if "duration_seconds" in result.get("timing", {}):
        details.append(
            f"Deletion completed in [bold green]{result['timing']['duration_seconds']:.2f}[/bold green] seconds"
        )

    print_panel("\n".join(details), title="Deletion Complete")

    # Create an informative panel with notes
    notes = [
        "1. The content is now unpinned from the marketplace",
        "2. The CID may still resolve temporarily until garbage collection occurs",
        "3. If the content was published to the global IPFS network, it may still be",
        "   available through other nodes that pinned it",
    ]

    print_panel("\n".join(notes), title="Important Notes")

    return 0


async def handle_pin(
    client: HippiusClient, cid: str, publish: bool = True, miner_ids=None
) -> int:
    """Handle the pin command to pin a CID to IPFS and optionally publish to blockchain"""
    from rich.panel import Panel

    # First check if this CID exists
    try:
        exists_result = await client.exists(cid)
        if not exists_result["exists"]:
            error(f"CID [bold cyan]{cid}[/bold cyan] not found on IPFS")
            return 1
    except Exception as e:
        warning(f"Error checking if CID exists: {e}")
        return 1

    # Create operation title based on publish flag
    if publish:
        info(
            f"Preparing to pin and publish content with CID: [bold cyan]{cid}[/bold cyan]"
        )
        operation_title = "Pin & Publish Operation"
    else:
        info(f"Preparing to pin content with CID: [bold cyan]{cid}[/bold cyan]")
        operation_title = "Pin Operation"

    # Display operation details
    operation_details = [
        f"CID: [bold cyan]{cid}[/bold cyan]",
        f"Publishing to blockchain: {'Enabled' if publish else 'Disabled'}",
    ]
    print_panel("\n".join(operation_details), title=operation_title)

    # Need to authenticate if publishing to blockchain
    if publish:
        try:
            # Ensure we have a keypair for substrate operations
            _ = client.substrate_client._ensure_keypair()
        except Exception as e:
            warning(f"Failed to initialize blockchain client: {str(e)}")
            warning("Will continue with pinning but blockchain publishing may fail")

    # Show spinner during pinning
    with console.status(
        "[cyan]Pinning content to IPFS...[/cyan]", spinner="dots"
    ) as status:
        try:
            # Pin the content to IPFS
            pin_result = await client.ipfs_client.pin(cid)

            if not pin_result.get("success", False):
                error(
                    f"Failed to pin content: {pin_result.get('message', 'Unknown error')}"
                )
                return 1

            # If publishing to blockchain, do that now
            if publish:
                status.update("[cyan]Publishing content to blockchain...[/cyan]")

                # Create a FileInput object for the substrate client
                from hippius_sdk.substrate import FileInput

                file_input = FileInput(file_hash=cid, file_name=f"pinned_{cid}")

                # Submit the storage request
                tx_hash = await client.substrate_client.storage_request(
                    files=[file_input], miner_ids=miner_ids
                )

                # Create result panel with blockchain details
                gateway_url = f"{client.ipfs_client.gateway}/ipfs/{cid}"
                panel_details = [
                    f"Successfully pinned and published: [bold cyan]{cid}[/bold cyan]",
                    f"Gateway URL: [bold cyan]{gateway_url}[/bold cyan]",
                    f"Transaction hash: [bold green]{tx_hash}[/bold green]",
                    "\nThis content is now:",
                    "1. Pinned to your IPFS node",
                    "2. Published to the IPFS network",
                    "3. Stored on the Hippius blockchain",
                ]
                console.print(
                    Panel(
                        "\n".join(panel_details),
                        title="Operation Complete",
                        border_style="green",
                    )
                )
            else:
                # Just pinning, no blockchain publishing
                gateway_url = f"{client.ipfs_client.gateway}/ipfs/{cid}"
                panel_details = [
                    f"Successfully pinned: [bold cyan]{cid}[/bold cyan]",
                    f"Gateway URL: [bold cyan]{gateway_url}[/bold cyan]",
                    "\nThis content is now pinned to your IPFS node.",
                    "It will remain available as long as your node is running.",
                ]
                console.print(
                    Panel(
                        "\n".join(panel_details),
                        title="Pinning Complete",
                        border_style="green",
                    )
                )

            return 0
        except Exception as e:
            error(f"Error during operation: {e}")
            return 1


async def handle_ec_delete(
    client: HippiusClient, metadata_cid: str, force: bool = False
) -> int:
    """Handle the erasure-code delete command"""

    # Create a stylish header with the CID
    info(f"Preparing to delete erasure-coded file with metadata CID:")
    print_panel(f"[bold cyan]{metadata_cid}[/bold cyan]", title="Metadata CID")

    # Confirm the deletion if not forced
    if not force:
        warning_text = [
            "This will cancel the storage of this file on the Hippius blockchain.",
            "The file metadata will be removed from blockchain storage tracking.",
            "[dim]Note: Only the metadata CID will be canceled; contents may remain on IPFS.[/dim]",
        ]
        print_panel("\n".join(warning_text), title="Warning")

        confirm = input("Continue with deletion? (y/n): ").strip().lower()
        if confirm != "y":
            log("Deletion cancelled", style="yellow")
            return 0

    try:
        # First, pre-authenticate the client to get any password prompts out of the way
        # This accesses the substrate client to trigger authentication
        if not client.substrate_client._keypair:
            client.substrate_client._ensure_keypair()

        # Now we can show the spinner after any password prompts
        info("Deleting erasure-coded file from marketplace...")

        # Create a more detailed spinner with phases
        with console.status(
            "[cyan]Processing file metadata and chunks...[/cyan]", spinner="dots"
        ) as status:
            try:
                # Use the specialized delete method that now throws specific exceptions
                await client.delete_ec_file(metadata_cid)

                # If we get here, deletion was successful
                deletion_success = True
                already_deleted = False

            except HippiusAlreadyDeletedError:
                # Special case - already deleted
                deletion_success = False
                already_deleted = True

            except HippiusFailedSubstrateDelete as e:
                # Blockchain deletion failed
                error(f"Blockchain storage cancellation failed: {e}")
                return 1

            except HippiusFailedIPFSUnpin as e:
                # IPFS unpinning failed, but blockchain deletion succeeded
                warning(
                    f"Note: Some IPFS operations failed, but blockchain storage was successfully canceled"
                )
                # Consider this a success for the user since the more important blockchain part worked
                deletion_success = True
                already_deleted = False

            except HippiusMetadataError as e:
                # Metadata parsing failed, but we can still continue
                warning(
                    f"Note: Metadata file was corrupted, but blockchain storage was successfully canceled"
                )
                # Consider this a success for the user since the blockchain part worked
                deletion_success = True
                already_deleted = False

            except Exception as e:
                # Handle any unexpected errors
                error(f"Unexpected error: {e}")
                return 1

        # Show the result
        if deletion_success:
            # Create a success panel
            success_panel = [
                "[bold green]✓[/bold green] Metadata CID canceled from blockchain storage",
                f"[dim]This file is no longer tracked for storage payments[/dim]",
                "",
                "[dim]To purge file data completely:[/dim]",
                "• Individual chunks may still exist on IPFS and nodes",
                "• For complete deletion, all chunks should be unpinned manually",
            ]
            print_panel(
                "\n".join(success_panel), title="Storage Cancellation Successful"
            )
            return 0
        elif already_deleted:
            # Create a panel for the already deleted case
            already_panel = [
                "[bold yellow]![/bold yellow] This file has already been deleted from storage",
                "[dim]The CID was not found in the blockchain storage registry[/dim]",
                "",
                "This is expected if:",
                "• You previously deleted this file",
                "• The file was deleted by another process",
                "• The file was never stored in the first place",
            ]
            print_panel("\n".join(already_panel), title="Already Deleted")
            # Return 0 since this is not an error condition
            return 0
        else:
            # Create an error panel for all other failures
            error_panel = [
                "[bold red]×[/bold red] File not found in blockchain storage",
                "[dim]The metadata CID was not found in the blockchain storage registry[/dim]",
                "",
                "Possible reasons:",
                "• The CID may be incorrect",
                "• You may not be the owner of this file",
            ]
            print_panel("\n".join(error_panel), title="Storage Cancellation Failed")
            return 1
    except Exception as e:
        error(f"Error deleting erasure-coded file: {e}")
        return 1


#
# Configuration Handlers
#


def handle_config_get(section: str, key: str) -> int:
    """Handle the config get command"""
    try:
        value = get_config_value(section, key)
        log(
            f"[bold cyan]{section}[/bold cyan].[bold green]{key}[/bold green] = [bold]{value}[/bold]"
        )
        return 0
    except Exception as e:
        error(f"Error getting configuration value: {e}")
        return 1


def handle_config_set(section: str, key: str, value: str) -> int:
    """Handle the config set command"""
    try:
        # Convert string "true"/"false" to boolean if applicable
        if value.lower() == "true":
            value = True
        elif value.lower() == "false":
            value = False

        # Set the configuration value
        set_config_value(section, key, value)
        success(
            f"Set [bold cyan]{section}[/bold cyan].[bold green]{key}[/bold green] = [bold]{value}[/bold]"
        )
        return 0
    except Exception as e:
        error(f"Error setting configuration value: {e}")
        return 1


def handle_config_list() -> int:
    """Handle the config list command"""
    try:
        config = get_all_config()

        # Format the configuration as a multi-line string
        config_lines = ["Current configuration:"]

        for section, values in config.items():
            config_lines.append(f"\n[bold cyan]{section}[/bold cyan]")
            for key, value in values.items():
                config_lines.append(
                    f"  [bold green]{key}[/bold green] = [bold]{value}[/bold]"
                )

        # Print as a panel
        print_panel("\n".join(config_lines), title="Configuration")

        return 0
    except Exception as e:
        error(f"Error listing configuration: {e}")
        return 1


def handle_config_reset() -> int:
    """Handle the config reset command"""
    try:
        reset_config()
        success("Configuration reset to default values")
        return 0
    except Exception as e:
        error(f"Error resetting configuration: {e}")
        return 1


#
# Seed Phrase Handlers
#


def handle_seed_phrase_set(
    seed_phrase: str, encode: bool = False, account_name: Optional[str] = None
) -> int:
    """Handle the seed set command"""
    try:
        # Validate the seed phrase
        if not seed_phrase or len(seed_phrase.split()) not in [12, 24]:
            error("Seed phrase must be 12 or 24 words")
            return 1

        # If account name is provided, create a new account
        if account_name:
            info(f"Setting seed phrase for account: [bold]{account_name}[/bold]")
        else:
            info("Setting default seed phrase")

        # Encrypt if requested
        password = None
        if encode:
            log("\nYou've chosen to encrypt this seed phrase.", style="yellow")
            password = getpass.getpass("Enter a password for encryption: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                error("Passwords do not match")
                return 1

            if not password:
                error("Password cannot be empty for encryption")
                return 1

        # Set the seed phrase
        set_seed_phrase(seed_phrase, password, account_name)

        # Gather information for the success panel
        status_info = []

        # Display success message
        if encode:
            status_info.append(
                "[bold green]Seed phrase set and encrypted successfully[/bold green]"
            )
        else:
            status_info.append("[bold green]Seed phrase set successfully[/bold green]")
            status_info.append(
                "\n[bold yellow]Warning:[/bold yellow] Seed phrase is stored in plaintext. Consider encrypting it with:"
            )
            status_info.append(
                f"  [bold]hippius seed encode{' --account ' + account_name if account_name else ''}[/bold]"
            )

        # If this is a new account, show the address
        try:
            address = get_account_address(account_name)
            status_info.append(f"\nAccount address: [bold cyan]{address}[/bold cyan]")
        except:
            pass

        print_panel("\n".join(status_info), title="Seed Phrase Status")

        return 0
    except Exception as e:
        error(f"Error setting seed phrase: {e}")
        return 1


def handle_seed_phrase_encode(account_name: Optional[str] = None) -> int:
    """Handle the seed encode command"""
    try:
        # Check if account exists and get its encryption status
        config = load_config()
        accounts = config.get("substrate", {}).get("accounts", {})

        # If account name not specified, use active account
        if not account_name:
            account_name = config.get("substrate", {}).get("active_account")
            if not account_name:
                error("No account specified and no active account")
                return 1

        # Check if the account exists
        if account_name not in accounts:
            error(f"Account '{account_name}' not found")
            return 1

        # Get account details
        account = accounts.get(account_name, {})
        is_encrypted = account.get("seed_phrase_encoded", False)
        seed_phrase = account.get("seed_phrase")

        # Check if we have a seed phrase
        if not seed_phrase:
            error(f"Account '{account_name}' doesn't have a seed phrase")
            info(
                f"Set a seed phrase first with: [bold green underline]hippius seed set <seed_phrase> --account {account_name}[/bold green underline]"
            )
            return 1

        # Check if the seed phrase is already encrypted
        if is_encrypted:
            info("Seed phrase is already encrypted")
            confirm = (
                input("Do you want to re-encrypt it with a new password? (y/n): ")
                .strip()
                .lower()
            )
            if confirm != "y":
                info("Encryption cancelled")
                return 0

            # Need to decrypt with old password first
            old_password = getpass.getpass("Enter your current password to decrypt: ")
            decrypted_seed_phrase = decrypt_seed_phrase(old_password, account_name)

            if not decrypted_seed_phrase:
                error("Unable to decrypt the seed phrase. Incorrect password?")
                return 1

            # Now we have the decrypted seed phrase
            seed_phrase = decrypted_seed_phrase

        # Get new password for encryption
        info("\nYou are about to encrypt your seed phrase.")
        password = getpass.getpass("Enter a password for encryption: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            error("Passwords do not match")
            return 1

        if not password:
            error("Password cannot be empty for encryption")
            return 1

        # Now encrypt the seed phrase - key fix here passing correct parameters
        success = encrypt_seed_phrase(seed_phrase, password, account_name)

        # Security: Clear the plaintext seed phrase from memory
        # This is a best-effort approach, as Python's garbage collection may still keep copies
        seed_phrase = None

        if success:
            # Create success panel with encryption information
            encryption_info = [
                f"Account: [bold]{account_name}[/bold]",
                "[bold green]Seed phrase encrypted successfully[/bold green]",
                "",
                "You will need to provide this password when using the account for:",
                "  - Pinning files to IPFS",
                "  - Erasure coding with publishing",
                "  - Any other blockchain operations",
                "",
                "[bold yellow underline]Security note:[/bold yellow underline] The original unencrypted seed phrase is NOT stored in the config.",
            ]

            # Try to get the address for display
            try:
                address = get_account_address(account_name)
                if address:
                    encryption_info.append("")
                    encryption_info.append(
                        f"Account address: [bold cyan]{address}[/bold cyan]"
                    )
            except Exception:
                pass

            print_panel("\n".join(encryption_info), title="Encryption Successful")
            return 0
        else:
            error("Failed to encrypt seed phrase")
            return 1

    except Exception as e:
        error(f"Error encrypting seed phrase: {e}")
        return 1


def handle_seed_phrase_decode(account_name: Optional[str] = None) -> int:
    """Handle the seed decode command - temporarily decrypts and displays the seed phrase"""
    try:
        # Check if seed phrase exists and is encrypted
        config = load_config()
        accounts = config.get("substrate", {}).get("accounts", {})

        if account_name:
            account = accounts.get(account_name, {})
            is_encrypted = account.get("seed_phrase_encoded", False)
        else:
            # Get active account
            active_account = config.get("substrate", {}).get("active_account")
            if active_account and active_account in accounts:
                is_encrypted = accounts[active_account].get(
                    "seed_phrase_encoded", False
                )
            else:
                # Legacy mode
                is_encrypted = config.get("substrate", {}).get(
                    "seed_phrase_encoded", False
                )

        if not is_encrypted:
            info("Seed phrase is not encrypted")
            return 0

        # Get password for decryption
        password = getpass.getpass("Enter your password to decrypt the seed phrase: ")

        if not password:
            error("Password cannot be empty")
            return 1

        # Try to decrypt the seed phrase
        try:
            seed_phrase = decrypt_seed_phrase(password, account_name)

            if seed_phrase:
                # Create info panel for the decrypted seed phrase
                seed_info = [
                    f"Decrypted seed phrase: [bold yellow]{seed_phrase}[/bold yellow]",
                    "",
                    "[bold green underline]NOTE: This is a temporary decryption only. Your seed phrase remains encrypted in the config.[/bold green underline]",
                    "",
                    "[bold red underline]SECURITY WARNING:[/bold red underline]",
                    "- Your seed phrase gives full access to your account funds",
                    "- Never share it with anyone or store it in an insecure location",
                    "- Be aware that displaying it on screen could expose it to screen capture",
                    "- Consider clearing your terminal history after this operation",
                ]

                print_panel("\n".join(seed_info), title="Seed Phrase Decoded")

                # Security: Clear the plaintext seed phrase from memory
                # This is a best-effort approach, as Python's garbage collection may still keep copies
                seed_phrase = None

                return 0
            else:
                error("Failed to decrypt seed phrase")
                return 1

        except Exception as e:
            error(f"Error decrypting seed phrase: {e}")

            if "decryption failed" in str(e).lower():
                warning("Incorrect password")

            return 1

    except Exception as e:
        error(f"{e}")
        return 1


def handle_seed_phrase_status(account_name: Optional[str] = None) -> int:
    """Handle the seed status command"""
    try:
        # Load configuration
        config = load_config()

        if account_name:
            print(f"Checking seed phrase status for account: {account_name}")

            # Check if account exists
            accounts = config.get("substrate", {}).get("accounts", {})
            if account_name not in accounts:
                print(f"Account '{account_name}' not found")
                return 1

            account = accounts[account_name]
            has_seed = "seed_phrase" in account
            is_encrypted = account.get("seed_phrase_encoded", False)
            is_active = account_name == get_active_account()

            print("\nAccount Status:")
            print(f"  Account Name: {account_name}")
            print(f"  Has Seed Phrase: {'Yes' if has_seed else 'No'}")
            print(f"  Encrypted: {'Yes' if is_encrypted else 'No'}")
            print(f"  Active: {'Yes' if is_active else 'No'}")

            if has_seed:
                try:
                    # Try to get the address (will use cached if available)
                    address = get_account_address(account_name)
                    print(f"  Address: {address}")
                except Exception as e:
                    if is_encrypted:
                        print("  Address: Encrypted (password required to view)")
                    else:
                        print(f"  Address: Unable to derive (Error: {e})")

        else:
            print("Checking active account seed phrase status")

            # Get the active account
            active_account = get_active_account()
            if active_account:
                accounts = config.get("substrate", {}).get("accounts", {})
                if active_account in accounts:
                    account = accounts[active_account]
                    has_seed = "seed_phrase" in account
                    is_encrypted = account.get("seed_phrase_encoded", False)

                    print(f"\nActive Account: {active_account}")
                    print(f"  Has Seed Phrase: {'Yes' if has_seed else 'No'}")
                    print(f"  Encrypted: {'Yes' if is_encrypted else 'No'}")

                    if has_seed:
                        try:
                            # Try to get the address (will use cached if available)
                            address = get_account_address(active_account)
                            print(f"  Address: {address}")
                        except Exception as e:
                            if is_encrypted:
                                print(
                                    "  Address: Encrypted (password required to view)"
                                )
                            else:
                                print(f"  Address: Unable to derive (Error: {e})")
                else:
                    print(
                        f"\nActive account '{active_account}' not found in configuration"
                    )
            else:
                print("\nNo active account set")

        return 0

    except Exception as e:
        print(f"Error checking seed phrase status: {e}")
        return 1


#
# Account Management Handlers
#


def handle_account_info(account_name: Optional[str] = None) -> int:
    """Handle the account info command - displays detailed information about an account"""
    try:
        # Load configuration
        config = load_config()

        # If account name not specified, use active account
        if not account_name:
            account_name = config.get("substrate", {}).get("active_account")
            if not account_name:
                error("No account specified and no active account")
                return 1

        # Check if account exists
        accounts = config.get("substrate", {}).get("accounts", {})
        if account_name not in accounts:
            error(f"Account '{account_name}' not found")
            return 1

        # Get account details
        account = accounts[account_name]
        has_seed = "seed_phrase" in account
        is_encrypted = account.get("seed_phrase_encoded", False)
        is_active = account_name == get_active_account()
        ss58_address = account.get("ss58_address", "")

        # Account information panel with rich formatting
        account_info = [
            f"Account Name: [bold]{account_name}[/bold]",
            f"Active: [bold cyan]{'Yes' if is_active else 'No'}[/bold cyan]",
            f"Has Seed Phrase: [bold]{'Yes' if has_seed else 'No'}[/bold]",
            f"Encryption: [bold {'green' if is_encrypted else 'yellow'}]{'Encrypted' if is_encrypted else 'Unencrypted'}[/bold {'green' if is_encrypted else 'yellow'}]",
        ]

        if ss58_address:
            account_info.append(f"SS58 Address: [bold cyan]{ss58_address}[/bold cyan]")
        elif has_seed:
            if is_encrypted:
                account_info.append(
                    "[dim]Address: Encrypted (password required to view)[/dim]"
                )
            else:
                try:
                    # Try to get the address
                    address = get_account_address(account_name)
                    account_info.append(
                        f"SS58 Address: [bold cyan]{address}[/bold cyan]"
                    )
                except Exception as e:
                    account_info.append(
                        f"[yellow]Unable to derive address: {e}[/yellow]"
                    )

        # Add suggestions based on account status
        account_info.append("")
        if is_active:
            account_info.append("[bold green]This is your active account[/bold green]")
        else:
            account_info.append(
                f"[dim]To use this account: [bold green underline]hippius account switch {account_name}[/bold green underline][/dim]"
            )

        if has_seed and not is_encrypted:
            account_info.append(
                f"[bold yellow underline]WARNING:[/bold yellow underline] Seed phrase is not encrypted"
            )
            account_info.append(
                f"[dim]To encrypt: [bold green underline]hippius account encode --name {account_name}[/bold green underline][/dim]"
            )

        # Print the panel with rich formatting
        print_panel(
            "\n".join(account_info), title=f"Account Information: {account_name}"
        )

        return 0

    except Exception as e:
        error(f"Error getting account info: {e}")
        return 1


def handle_account_create(
    client: HippiusClient, name: str, encrypt: bool = False
) -> int:
    """Handle the account create command"""
    try:
        # Check if account already exists
        accounts = list_accounts()
        if name in accounts:
            print(f"Error: Account '{name}' already exists")
            return 1

        print(f"Creating new account: {name}")

        # Import Keypair at the beginning to ensure it's available
        from substrateinterface import Keypair

        # Generate a new keypair (seed phrase)
        seed_phrase = client.substrate_client.generate_seed_phrase()

        if not seed_phrase:
            print("Error: Failed to generate seed phrase")
            return 1

        # Process encryption
        password = None
        if encrypt:
            print("\nYou've chosen to encrypt this seed phrase.")
            password = getpass.getpass("Enter a password for encryption: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                print("Error: Passwords do not match")
                return 1

            if not password:
                print("Error: Password cannot be empty for encryption")
                return 1

        # Set the seed phrase for the new account
        # First load the config to directly edit it
        config = load_config()

        # Ensure accounts structure exists
        if "accounts" not in config["substrate"]:
            config["substrate"]["accounts"] = {}

        # Create keypair directly from seed phrase
        keypair = Keypair.create_from_mnemonic(seed_phrase)
        address = keypair.ss58_address

        # Add the new account
        config["substrate"]["accounts"][name] = {
            "seed_phrase": seed_phrase,
            "seed_phrase_encoded": False,
            "seed_phrase_salt": None,
            "ss58_address": address,
        }

        # Set as active account
        config["substrate"]["active_account"] = name

        # Save the config
        save_config(config)

        # Print account information using rich formatting
        account_info = [
            f"Account: [bold]{name}[/bold]",
            f"Address: [bold cyan]{address}[/bold cyan]",
            f"Seed phrase: [bold yellow]{seed_phrase}[/bold yellow]",
            "",
            "[bold red underline]IMPORTANT:[/bold red underline] Keep your seed phrase safe. It's the only way to recover your account!",
        ]

        # Add encryption status
        if encrypt:
            account_info.append("")
            account_info.append(
                "[bold green]Your seed phrase is encrypted.[/bold green]"
            )
            account_info.append(
                "You'll need to provide the password whenever using this account."
            )
        else:
            account_info.append("")
            account_info.append(
                "[bold yellow underline]WARNING:[/bold yellow underline] Your seed phrase is stored unencrypted."
            )
            account_info.append(
                f"[bold green underline]Consider encrypting it with: hippius account encode --name {name}[/bold green underline]"
            )

        account_info.append("")
        account_info.append(
            "This account is now active. Use it with: [bold]hippius <command>[/bold]"
        )

        # Print the panel with rich formatting
        print_panel("\n".join(account_info), title="Account Created Successfully")

        return 0

    except Exception as e:
        error(f"Error creating account: {e}")
        return 1


def handle_account_export(
    client: HippiusClient, name: Optional[str] = None, file_path: Optional[str] = None
) -> int:
    """Handle the account export command"""
    try:
        # Determine account to export
        account_name = name or get_active_account()

        if not account_name:
            print("Error: No account specified and no active account found")
            print("Use --name to specify an account to export")
            return 1

        print(f"Exporting account: {account_name}")

        # Default file path if not provided
        if not file_path:
            file_path = f"{account_name}_hippius_account.json"

        # Export the account
        config = load_config()
        accounts = config.get("substrate", {}).get("accounts", {})

        if account_name not in accounts:
            print(f"Error: Account '{account_name}' not found")
            return 1

        # Get the account data
        account_data = accounts[account_name]

        # Create export data
        export_data = {
            "name": account_name,
            "encrypted": account_data.get("encrypted", False),
            "seed_phrase": account_data.get("seed_phrase", ""),
            "address": account_data.get("address", ""),
        }

        # Save to file
        with open(file_path, "w") as f:
            json.dump(export_data, f, indent=2)

        print(f"Account exported to: {file_path}")

        # Security warning
        if not export_data.get("encrypted"):
            print("\nWARNING: This export file contains an unencrypted seed phrase.")
            print("Keep this file secure and never share it with anyone.")

        return 0

    except Exception as e:
        print(f"Error exporting account: {e}")
        return 1


def handle_account_import(
    client: HippiusClient, file_path: str, encrypt: bool = False
) -> int:
    """Handle the account import command"""
    try:
        # Verify file exists
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found")
            return 1

        print(f"Importing account from: {file_path}")

        # Read and parse the file
        try:
            with open(file_path, "r") as f:
                import_data = json.load(f)

            # Validate data
            if not isinstance(import_data, dict):
                print("Error: Invalid account file format")
                return 1

            account_name = import_data.get("name")
            seed_phrase = import_data.get("seed_phrase")
            is_encrypted = import_data.get("encrypted", False)

            if not account_name:
                print("Error: Missing account name in import file")
                return 1

            if not seed_phrase:
                print("Error: Missing seed phrase in import file")
                return 1

        except Exception as e:
            print(f"Error reading account file: {e}")
            return 1

        # Check if account already exists
        accounts = list_accounts()
        if account_name in accounts:
            print(f"Warning: Account '{account_name}' already exists")
            overwrite = input("Overwrite existing account? (y/n): ").strip().lower()
            if overwrite != "y":
                print("Import cancelled")
                return 0

        # Handle encryption
        password = None

        # If importing encrypted account
        if is_encrypted:
            print("\nThis account has an encrypted seed phrase.")
            if encrypt:
                # Re-encrypt with new password
                print("You've chosen to re-encrypt this account.")
                old_password = getpass.getpass("Enter the original password: ")

                # Try to decrypt first
                try:
                    # Create temporary decryption box
                    if ENCRYPTION_AVAILABLE:
                        # Derive key from password
                        import hashlib

                        import nacl.secret
                        import nacl.utils
                        from nacl.exceptions import CryptoError

                        key = hashlib.sha256(old_password.encode()).digest()
                        box = nacl.secret.SecretBox(key)

                        # Try decryption
                        try:
                            # Split the nonce and ciphertext
                            data = base64.b64decode(seed_phrase)
                            nonce = data[: box.NONCE_SIZE]
                            ciphertext = data[box.NONCE_SIZE :]

                            # Decrypt
                            decrypted = box.decrypt(ciphertext, nonce)
                            seed_phrase = decrypted.decode("utf-8")

                            # Now get new password for re-encryption
                            new_password = getpass.getpass(
                                "Enter new password for encryption: "
                            )
                            confirm = getpass.getpass("Confirm new password: ")

                            if new_password != confirm:
                                print("Error: Passwords do not match")
                                return 1

                            password = new_password

                        except CryptoError:
                            print("Error: Incorrect password for encrypted seed phrase")
                            return 1
                    else:
                        print("Error: PyNaCl is required for encryption/decryption.")
                        print("Install it with: pip install pynacl")
                        return 1
                except Exception as e:
                    print(f"Error decrypting seed phrase: {e}")
                    return 1
            else:
                # Keep existing encryption
                print("Importing with existing encryption.")
                print("You'll need the original password to use this account.")
        elif encrypt:
            # Encrypt an unencrypted import
            print("\nYou've chosen to encrypt this account during import.")
            password = getpass.getpass("Enter a password for encryption: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                print("Error: Passwords do not match")
                return 1

            if not password:
                print("Error: Password cannot be empty for encryption")
                return 1

        # Import the account
        set_seed_phrase(seed_phrase, password, account_name)

        # Set as active account
        set_active_account(account_name)

        print(f"\nSuccessfully imported account: {account_name}")
        print("This account is now active.")

        # If address is provided in import data, show it
        if "address" in import_data and import_data["address"]:
            print(f"Address: {import_data['address']}")
        else:
            # Try to get address
            try:
                address = get_account_address(account_name)
                print(f"Address: {address}")
            except:
                if is_encrypted or encrypt:
                    print("Address: Encrypted (password required to view)")
                else:
                    print("Address: Unable to derive")

        return 0

    except Exception as e:
        print(f"Error importing account: {e}")
        return 1


def handle_account_list() -> int:
    """Handle the account list command"""
    try:
        accounts = list_accounts()
        active_account = get_active_account()

        if not accounts:
            log("No accounts found", style="yellow")
            return 0

        info(f"Found [bold]{len(accounts)}[/bold] accounts:")

        # Load config to get more details
        config = load_config()
        account_config = config.get("substrate", {}).get("accounts", {})

        # Create data for a table
        account_data_list = []
        for i, account_name in enumerate(accounts, 1):
            account_data = account_config.get(account_name, {})

            is_active = account_name == active_account
            has_seed = "seed_phrase" in account_data
            is_encrypted = account_data.get("seed_phrase_encoded", False)

            # Get address
            address = account_data.get("ss58_address", "")

            # Add to table data
            row = {
                "Index": str(i),
                "Name": account_name,
                "Status": "[bold green]Active[/bold green]" if is_active else "",
                "Encrypted": "[yellow]Yes[/yellow]" if is_encrypted else "No",
                "Address": address if address else "",
                "Has seed": has_seed,
            }
            account_data_list.append(row)

        # Display accounts in a table
        print_table(
            title="Accounts",
            data=account_data_list,
            columns=["Index", "Name", "Status", "Encrypted", "Address", "Has seed"],
        )

        # Show active account status
        if active_account:
            success(f"Active account: [bold]{active_account}[/bold]")
        else:
            warning("No active account selected")

        # Instructions
        help_text = [
            "To switch accounts: [bold green underline]hippius account switch <account_name>[/bold green underline]",
            "To create a new account: [bold green underline]hippius account create --name <account_name>[/bold green underline]",
        ]
        print_panel("\n".join(help_text), title="Account Management")

        return 0

    except Exception as e:
        error(f"Error listing accounts: {e}")
        return 1


def handle_account_switch(account_name: str) -> int:
    """Handle the account switch command"""
    try:
        # Check if account exists
        accounts = list_accounts()
        if account_name not in accounts:
            print(f"Error: Account '{account_name}' not found")
            print("Available accounts:")
            for account in accounts:
                print(f"  {account}")
            return 1

        # Set as active account
        set_active_account(account_name)

        print(f"Switched to account: {account_name}")

        # Show account address if possible
        try:
            address = get_account_address(account_name)
            print(f"Address: {address}")
        except Exception as e:
            # Check if encrypted
            config = load_config()
            account_config = (
                config.get("substrate", {}).get("accounts", {}).get(account_name, {})
            )

            if account_config.get("encrypted", False):
                print("Address: Encrypted (password required to view)")
            else:
                print(f"Note: Unable to display address ({str(e)})")

        return 0

    except Exception as e:
        print(f"Error switching account: {e}")
        return 1


def handle_account_login() -> int:
    """Handle the account login command - prompts for account details and creates an account"""
    try:
        # Display the login banner
        from hippius_sdk.cli_assets import LOGIN_ASSET

        console.print(LOGIN_ASSET, style="bold cyan")
        console.print(
            "\n[bold blue]Welcome to Hippius![/bold blue] Let's set up your account.\n"
        )

        # Create a style for prompts
        prompt_style = "bold green"
        input_style = "bold cyan"

        # Prompt for account name with nice formatting
        console.print(
            "[bold]Step 1:[/bold] Choose a name for your account", style=prompt_style
        )
        console.print(
            "This name will be used to identify your account in the Hippius system.",
            style="dim",
        )
        console.print("Account name:", style=input_style, end=" ")
        name = input().strip()

        if not name:
            error("[bold red]Account name cannot be empty[/bold red]")
            return 1

        # Check if account already exists
        accounts = list_accounts()
        if name in accounts:
            warning(f"Account '[bold]{name}[/bold]' already exists")
            console.print(
                "Do you want to overwrite it? (y/n):", style=input_style, end=" "
            )
            confirm = input().strip().lower()
            if confirm != "y":
                info("Login cancelled")
                return 0

        # Prompt for seed phrase with detailed explanation
        console.print(
            "\n[bold]Step 2:[/bold] Enter your seed phrase", style=prompt_style
        )
        console.print(
            "Your seed phrase gives access to your blockchain account and funds.",
            style="dim",
        )
        console.print(
            "[yellow]Important:[/yellow] Must be 12 or 24 words separated by spaces.",
            style="dim",
        )
        console.print("Seed phrase:", style=input_style, end=" ")
        seed_phrase = input().strip()

        # Validate the seed phrase
        if not seed_phrase or len(seed_phrase.split()) not in [12, 24]:
            error(
                "[bold red]Invalid seed phrase[/bold red] - must be 12 or 24 words separated by spaces"
            )
            return 1

        # Prompt for encryption with security explanation
        console.print("\n[bold]Step 3:[/bold] Secure your account", style=prompt_style)
        console.print(
            "Encrypting your seed phrase adds an extra layer of security.", style="dim"
        )
        console.print(
            "[bold yellow]Strongly recommended[/bold yellow] to protect your account.",
            style="dim",
        )
        console.print(
            "Encrypt seed phrase? [bold green](Y/n)[/bold green]:",
            style=input_style,
            end=" ",
        )
        encrypt_input = input().strip().lower()
        encrypt = encrypt_input == "y" or encrypt_input == "" or encrypt_input == "yes"

        # Set up encryption if requested
        password = None
        if encrypt:
            console.print(
                "\n[bold]Step 4:[/bold] Set encryption password", style=prompt_style
            )
            console.print(
                "This password will be required whenever you use your account for blockchain operations.",
                style="dim",
            )

            password = getpass.getpass("Enter a password: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                error("[bold red]Passwords do not match[/bold red]")
                return 1

            if not password:
                error("[bold red]Password cannot be empty for encryption[/bold red]")
                return 1

        # Initialize address variable
        address = None

        # Create and store the account
        with console.status("[cyan]Setting up your account...[/cyan]", spinner="dots"):
            # First, directly modify the config to ensure account is created
            config = load_config()

            # Ensure accounts structure exists
            if "substrate" not in config:
                config["substrate"] = {}
            if "accounts" not in config["substrate"]:
                config["substrate"]["accounts"] = {}

            # Create keypair and get address from seed phrase
            from substrateinterface import Keypair

            keypair = Keypair.create_from_mnemonic(seed_phrase)
            address = keypair.ss58_address

            # Add the new account
            config["substrate"]["accounts"][name] = {
                "seed_phrase": seed_phrase,
                "seed_phrase_encoded": False,
                "seed_phrase_salt": None,
                "ss58_address": address,
            }

            # Set as active account
            config["substrate"]["active_account"] = name

            # Save the config first
            save_config(config)

            # Now encrypt if requested
            if encrypt:
                encrypt_seed_phrase(seed_phrase, password, name)

            time.sleep(0.5)  # Small delay for visual feedback

        # Success panel with account information
        account_info = [
            f"[bold]Account Name:[/bold] [bold magenta]{name}[/bold magenta]",
            f"[bold]Blockchain Address:[/bold] [bold cyan]{address}[/bold cyan]",
            "",
            "[bold green]✓ Login successful![/bold green]",
            "[bold green]✓ Account set as active[/bold green]",
        ]

        if encrypt:
            account_info.append("[bold green]✓ Seed phrase encrypted[/bold green]")
            account_info.append("")
            account_info.append(
                "[dim]You'll need your password when using this account for blockchain operations.[/dim]"
            )
        else:
            account_info.append(
                "[bold yellow]⚠ Seed phrase not encrypted[/bold yellow]"
            )
            account_info.append("")
            account_info.append(
                "[dim]For better security, consider encrypting your seed phrase:[/dim]"
            )
            account_info.append(
                f"[dim]  [bold green underline]hippius account encode --name {name}[/bold green underline][/dim]"
            )

        # Add next steps
        account_info.append("")
        account_info.append("[bold blue]Next steps:[/bold blue]")
        account_info.append(
            "• [bold green underline]hippius credits[/bold green underline] - Check your account balance"
        )
        account_info.append(
            "• [bold green underline]hippius files[/bold green underline] - View your stored files"
        )
        account_info.append(
            "• [bold green underline]hippius store <file>[/bold green underline] - Upload a file to IPFS"
        )

        print_panel(
            "\n".join(account_info), title="[bold green]Account Ready[/bold green]"
        )
        return 0

    except Exception as e:
        error(f"[bold red]Error logging in:[/bold red] {e}")
        return 1


def handle_account_delete(account_name: str) -> int:
    """Handle the account delete command"""
    try:
        # Check if account exists
        accounts = list_accounts()
        if account_name not in accounts:
            print(f"Error: Account '{account_name}' not found")
            return 1

        # Confirm deletion
        print(f"Warning: You are about to delete account '{account_name}'")
        print("This action cannot be undone unless you have exported the account.")
        confirm = input("Delete this account? (y/n): ").strip().lower()

        if confirm != "y":
            print("Deletion cancelled")
            return 0

        # Delete the account
        delete_account(account_name)

        print(f"Account '{account_name}' deleted successfully")

        # If this was the active account, notify user
        active_account = get_active_account()
        if active_account == account_name:
            print("This was the active account. No account is currently active.")

            # If there are other accounts, suggest one
            remaining_accounts = list_accounts()
            if remaining_accounts:
                print(
                    f"You can switch to another account with: hippius account switch {remaining_accounts[0]}"
                )

        return 0

    except Exception as e:
        print(f"Error deleting account: {e}")
        return 1


async def handle_account_balance(
    client: HippiusClient, account_address: Optional[str] = None
) -> int:
    """Handle the account balance command"""
    info("Checking account balance...")
    # Get the account address we're querying
    if account_address is None:
        # If no address provided, first try to get from keypair (if available)
        if (
            hasattr(client.substrate_client, "_keypair")
            and client.substrate_client._keypair is not None
        ):
            account_address = client.substrate_client._keypair.ss58_address
        else:
            # Get the active account name and its address
            from hippius_sdk.config import get_account_address, get_active_account

            active_account = get_active_account()
            if active_account:
                active_address = get_account_address(active_account)
                if active_address:
                    account_address = active_address
                else:
                    error(
                        f"Active account '{active_account}' does not have a valid address."
                    )
                    warning(
                        "Please provide an account address with '--account_address'"
                    )
                    return 1
            else:
                error(
                    "No account address provided, no active account set, and client has no keypair."
                )
                warning(
                    "Please provide an account address with '--account_address' or set an active account with:"
                )
                log(
                    "  [bold green underline]hippius account switch <account_name>[/bold green underline]"
                )
                return 1

    # Get the account balance
    balance = await client.substrate_client.get_account_balance(account_address)

    # Create a panel with balance information
    balance_info = [
        f"Account address: [bold cyan]{account_address}[/bold cyan]",
        f"Free balance: [bold green]{balance['free']:.6f}[/bold green]",
        f"Reserved balance: [bold yellow]{balance['reserved']:.6f}[/bold yellow]",
        f"Frozen balance: [bold blue]{balance['frozen']:.6f}[/bold blue]",
        f"Total balance: [bold]{balance['total']:.6f}[/bold]",
    ]

    # Add the raw values in a more subtle format
    balance_info.append("\n[dim]Raw values:[/dim]")
    balance_info.append(f"[dim]Free: {balance['raw']['free']:,}[/dim]")
    balance_info.append(f"[dim]Reserved: {balance['raw']['reserved']:,}[/dim]")
    balance_info.append(f"[dim]Frozen: {balance['raw']['frozen']:,}[/dim]")

    print_panel("\n".join(balance_info), title="Account Balance")


#
# Default Address Handlers
#


def handle_default_address_set(address: str) -> int:
    """Handle the address set-default command"""
    try:
        # Validate address format
        if not address.startswith("5"):
            warning("The address does not appear to be a valid Substrate address")
            log("Substrate addresses typically start with '5'", style="yellow")
            confirm = input("Continue anyway? (y/n): ").strip().lower()
            if confirm != "y":
                return 1

        # Update config
        config = load_config()

        if "substrate" not in config:
            config["substrate"] = {}

        config["substrate"]["default_address"] = address

        # Save config
        save_config(config)

        # Create success information
        details = [
            f"Default address set to: [bold cyan]{address}[/bold cyan]",
            "\nThis address will be used for read-only operations when no account is specified.",
        ]

        print_panel("\n".join(details), title="Default Address Updated")

        return 0

    except Exception as e:
        error(f"Error setting default address: {e}")
        return 1


def handle_default_address_get() -> int:
    """Handle the address get-default command"""
    try:
        address = get_default_address()

        if address:
            info(f"Default address: [bold cyan]{address}[/bold cyan]")
        else:
            warning("No default address set")
            log(
                "You can set one with: [bold]hippius address set-default <address>[/bold]"
            )

        return 0

    except Exception as e:
        error(f"Error getting default address: {e}")
        return 1


def handle_default_address_clear() -> int:
    """Handle the address clear-default command"""
    try:
        config = load_config()

        if "substrate" in config and "default_address" in config["substrate"]:
            del config["substrate"]["default_address"]
            save_config(config)
            success("Default address cleared")
        else:
            log("No default address was set", style="yellow")

        return 0

    except Exception as e:
        error(f"Error clearing default address: {e}")
        return 1
