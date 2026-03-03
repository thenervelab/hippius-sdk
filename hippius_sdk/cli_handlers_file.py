"""CLI handlers for file operations: store, download, delete, files, credits."""

import asyncio
import os
import time
from typing import Optional

import click

from hippius_sdk import (
    ArionClient,
    format_size,
    get_config_value,
)
from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.cli_ui import (
    _console,
    create_progress,
    error,
    info,
    log,
    print_panel,
    warning,
)


async def handle_store(
    client: ArionClient,
    file_path: str,
) -> int:
    """Handle the store command (upload file to Hippius storage)"""
    if not os.path.exists(file_path):
        error(f"File [bold]{file_path}[/bold] does not exist")
        return 1

    if not os.path.isfile(file_path):
        error(f"[bold]{file_path}[/bold] is not a file")
        return 1

    # Get file size for display
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    size_formatted = format_size(file_size)

    # Upload information panel
    upload_info = [
        f"File: [bold]{file_name}[/bold]",
        f"Size: [bold cyan]{size_formatted}[/bold cyan] ({file_size:,} bytes)",
    ]

    # Display upload information panel
    print_panel("\n".join(upload_info), title="Upload Operation")

    # Create progress for the upload process
    with create_progress() as progress:
        # Add a task for the upload
        task = progress.add_task("[cyan]Uploading...", total=100)

        start_time = time.time()

        # Create a task to update the progress while waiting for the upload
        async def update_progress():
            while not progress.finished:
                elapsed = time.time() - start_time
                # Use a logarithmic function to simulate progress
                pct = min(95, 100 * (1 - 1 / (1 + elapsed / 10)))
                progress.update(task, completed=pct)
                await asyncio.sleep(0.1)

        # Start the progress updater task
        updater = asyncio.create_task(update_progress())

        # Upload the file
        result = await client.upload_file(file_path=file_path)

        progress.update(task, completed=100)
        updater.cancel()

        elapsed_time = time.time() - start_time

        # Success panel with results
        success_info = [
            f"Upload completed in [bold green]{elapsed_time:.2f}[/bold green] seconds!",
            f"File ID: [bold cyan]{result['file_id']}[/bold cyan]",
            f"Size: [bold cyan]{result['size_formatted']}[/bold cyan]",
        ]

        print_panel("\n".join(success_info), title="Upload Successful")

        # Display download command
        command = f"[bold green underline]hippius download {result['file_id']} <output_path>[/bold green underline]"
        print_panel(command, title="Download Command")

        return 0


async def handle_download(
    client: ArionClient,
    file_id: str,
    output_path: str,
) -> int:
    """Handle the download command"""
    info(
        f"Downloading [bold cyan]{file_id}[/bold cyan] to [bold]{output_path}[/bold]..."
    )

    start_time = time.time()
    result = await client.download_file(file_id, output_path)
    elapsed_time = time.time() - start_time

    # Create a success panel with download information
    details = [
        f"Download successful in [bold green]{elapsed_time:.2f}[/bold green] seconds!",
        f"Saved to: [bold]{result['output_path']}[/bold]",
        f"Size: [bold cyan]{result['size_bytes']:,}[/bold cyan] bytes ([bold cyan]{result['size_formatted']}[/bold cyan])",
    ]

    print_panel("\n".join(details), title="Download Complete")

    return 0


async def handle_delete(client: ArionClient, file_id: str, force: bool = False) -> int:
    """Handle the delete command"""
    info(f"Preparing to delete file: [bold cyan]{file_id}[/bold cyan]")

    if not force:
        warning("This will permanently delete the file from storage.")
        if not click.confirm("Continue?", default=False):
            log("Deletion cancelled", style="yellow")
            return 0

    # Show spinner during deletion
    with _console.status("[cyan]Deleting file...[/cyan]", spinner="dots"):
        result = await client.delete_file(file_id)

    # Display results
    details = [
        f"Successfully deleted file: [bold cyan]{file_id}[/bold cyan]",
        f"Status: [bold green]{result['status']}[/bold green]",
    ]

    print_panel("\n".join(details), title="Deletion Complete")

    return 0


async def handle_credits(
    client: ArionClient, account_address: Optional[str] = None
) -> int:
    """Handle the credits command"""
    info("Checking credits for the authenticated account...")

    # Reuse the already-decrypted token from ArionClient (avoids double password prompt)
    api_token = client._api_token
    if not api_token:
        error("No API token available. Please login first with: hippius account login")
        return 1

    api_url = get_config_value("arion", "api_url", "https://api.hippius.com/api")
    api_client = HippiusApiClient(api_url=api_url, api_token=api_token)

    balance_data = await api_client.get_account_balance()
    await api_client.close()

    credits = balance_data.get("balance", 0)
    # Convert to float if it's a string
    if isinstance(credits, str):
        credits = float(credits)

    # Create a panel with credit information
    credit_info = [
        f"Credit balance: [bold green]{credits:.2f} USD[/bold green]",
    ]

    # Add account info if available in response
    if "account" in balance_data:
        credit_info.append(f"Account: [bold cyan]{balance_data['account']}[/bold cyan]")

    print_panel("\n".join(credit_info), title="Account Credits")

    return 0


async def handle_files(
    client: ArionClient,
    account_address: Optional[str] = None,
) -> int:
    """Handle the files command"""
    info("File listing is coming soon.")
    info("Arion list endpoint is not yet available.")
    return 0
