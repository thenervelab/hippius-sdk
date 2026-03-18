"""CLI handlers for account management."""

import asyncio
import json
import os
import time
from typing import Optional

import click
from substrateinterface import SubstrateInterface

from hcfs_client import Drive

from hippius_sdk import (
    ArionClient,
    delete_account,
    encrypt_api_token,
    get_account_address,
    get_active_account,
    get_config_value,
    list_accounts,
    load_config,
    save_config,
    set_active_account,
)
from hippius_sdk.api_client import HippiusApiClient
from hippius_sdk.crypto import decrypt_hcfs_mnemonic
from hippius_sdk.errors import HippiusAuthenticationError
from hippius_sdk.hcfs import get_drive_dir, HCFS_METADATA_SUBDIR
from hippius_sdk.cli_ui import (
    BRAND_COLOR,
    _console,
    draw_key_value,
    draw_logo,
    draw_step,
    draw_success_box,
    error,
    info,
    log,
    print_panel,
    print_table,
    success,
    warning,
)


def _display_recovery_phrase(phrase: str):
    """Display a recovery phrase with warnings."""
    warning("IMPORTANT: Write down your recovery phrase and store it safely!")
    warning(
        "You will need it to recover your encryption keys if you lose your password."
    )
    click.echo()
    click.secho("Recovery Phrase (24 words):", fg="yellow", bold=True)
    click.echo()
    click.echo(phrase)
    click.echo()
    click.secho("This phrase will NOT be shown again.", fg="red", bold=True)


def handle_account_info(account_name: Optional[str] = None) -> int:
    """Handle the account info command - displays detailed information about an account"""
    # Load configuration
    config = load_config()

    # If account name not specified, use active account
    if not account_name:
        account_name = config.get("accounts", {}).get("active_account")
        if not account_name:
            error("No account specified and no active account")
            return 1

    # Check if account exists
    accounts = config.get("accounts", {}).get("accounts", {})
    if account_name not in accounts:
        error(f"Account '{account_name}' not found")
        return 1

    # Get account details
    account = accounts[account_name]
    is_encrypted = account.get("api_token_encoded", False)
    is_active = account_name == get_active_account()

    # Get API token and truncate for display
    api_token = account.get("api_token", "")
    if api_token:
        if is_encrypted:
            api_key_display = "[encrypted]"
        elif len(api_token) > 6:
            api_key_display = f"{api_token[:3]}...{api_token[-3:]}"
        else:
            api_key_display = api_token
    else:
        api_key_display = "[dim]Not set[/dim]"

    # Get account address
    account_address = account.get("account_address", "[dim]Not set[/dim]")

    # Account information panel
    account_info = [
        f"Account Name: [bold]{account_name}[/bold]",
        f"Active: [bold cyan]{'Yes' if is_active else 'No'}[/bold cyan]",
        f"API Token: [bold]{api_key_display}[/bold]",
        f"Account Address: [bold cyan]{account_address}[/bold cyan]",
        f"Encryption: [bold {'green' if is_encrypted else 'yellow'}]{'Encrypted' if is_encrypted else 'Unencrypted'}[/bold {'green' if is_encrypted else 'yellow'}]",
    ]

    # Check for seed phrase (miner accounts)
    has_seed = bool(account.get("seed_phrase"))
    if has_seed:
        account_info.append(
            "[bold blue]Seed Phrase: Available (for miner operations)[/bold blue]"
        )

    # Add suggestions based on account status
    account_info.append("")
    if is_active:
        account_info.append("[bold green]This is your active account[/bold green]")
    else:
        account_info.append(
            f"[dim]To use this account: [bold green underline]hippius account switch {account_name}[/bold green underline][/dim]"
        )

    if not is_encrypted and api_token:
        account_info.append(
            "[bold yellow underline]WARNING:[/bold yellow underline] API token is not encrypted"
        )
        account_info.append(
            "[dim]Consider encrypting your token for better security[/dim]"
        )

    # Print the panel
    print_panel("\n".join(account_info), title=f"Account Information: {account_name}")

    return 0


def handle_account_export(
    client: ArionClient, name: Optional[str] = None, file_path: Optional[str] = None
) -> int:
    """Handle the account export command"""
    # Determine account to export
    account_name = name or get_active_account()

    if not account_name:
        error("No account specified and no active account found")
        click.echo("Use --name to specify an account to export")
        return 1

    info(f"Exporting account: [bold]{account_name}[/bold]")

    # Default file path if not provided
    if not file_path:
        file_path = f"{account_name}_hippius_account.json"

    # Export the account
    config = load_config()
    accounts = config.get("accounts", {}).get("accounts", {})

    if account_name not in accounts:
        error(f"Account '{account_name}' not found")
        return 1

    # Get the account data
    account_data = accounts[account_name]

    # Create export data
    export_data = {
        "name": account_name,
        "api_token": account_data.get("api_token", ""),
        "api_token_encoded": account_data.get("api_token_encoded", False),
        "account_address": account_data.get("account_address", ""),
    }

    # Only include encrypted data if needed
    if export_data["api_token_encoded"]:
        export_data["api_token_salt"] = account_data.get("api_token_salt")

    # Save to file
    with open(file_path, "w") as f:
        json.dump(export_data, f, indent=2)

    info(f"Account exported to: [bold cyan]{file_path}[/bold cyan]")

    # Security warning
    if not export_data.get("api_token_encoded"):
        click.echo()
        warning("This export file contains an unencrypted API token.")
        click.echo("Keep this file secure and never share it with anyone.")

    return 0


def handle_account_import(
    client: ArionClient, file_path: str, encrypt: bool = False
) -> int:
    """Handle the account import command"""
    # Verify file exists
    if not os.path.exists(file_path):
        error(f"File {file_path} not found")
        return 1

    info(f"Importing account from: [bold]{file_path}[/bold]")

    # Read and parse the file
    with open(file_path, "r") as f:
        import_data = json.load(f)

    # Validate data
    if not isinstance(import_data, dict):
        error("Invalid account file format")
        return 1

    account_name = import_data.get("name")
    api_token = import_data.get("api_token") or import_data.get("hippius_key")
    api_token_encoded = import_data.get(
        "api_token_encoded", import_data.get("hippius_key_encoded", False)
    )
    api_token_salt = import_data.get(
        "api_token_salt", import_data.get("hippius_key_salt")
    )
    account_address = import_data.get("account_address", "")

    if not account_name:
        error("Missing account name in import file")
        return 1

    if not api_token:
        error("Missing API token in import file")
        return 1

    # Check if account already exists
    accounts = list_accounts()
    if account_name in accounts:
        warning(f"Account '{account_name}' already exists")
        if not click.confirm("Overwrite existing account?", default=False):
            info("Import cancelled")
            return 0

    # Load config and add account
    config = load_config()

    # Import the account
    config["accounts"]["accounts"][account_name] = {
        "api_token": api_token,
        "api_token_encoded": api_token_encoded,
        "api_token_salt": api_token_salt,
        "account_address": account_address,
    }

    # Set as active account
    config["accounts"]["active_account"] = account_name
    save_config(config)

    info(f"\nSuccessfully imported account: [bold]{account_name}[/bold]")
    info("This account is now active.")

    return 0


def handle_account_list() -> int:
    """Handle the account list command"""
    accounts = list_accounts()
    active_account = get_active_account()

    if not accounts:
        log("No accounts found", style="yellow")
        return 0

    info(f"Found [bold]{len(accounts)}[/bold] accounts:")

    # Load config to get more details
    config = load_config()
    account_config = config.get("accounts", {}).get("accounts", {})

    # Create data for a table
    account_data_list = []
    for i, account_name in enumerate(accounts, 1):
        account_data = account_config.get(account_name, {})

        is_active = account_name == active_account
        is_encrypted = account_data.get("api_token_encoded", False)
        account_address = account_data.get("account_address", "")

        # Truncate address for display
        if account_address and len(account_address) > 12:
            addr_display = f"{account_address[:6]}...{account_address[-4:]}"
        else:
            addr_display = account_address or "N/A"

        # Add to table data
        row = {
            "Index": str(i),
            "Name": account_name,
            "Status": "[bold green]Active[/bold green]" if is_active else "",
            "Encrypted": "[yellow]Yes[/yellow]" if is_encrypted else "No",
            "Address": addr_display,
        }
        account_data_list.append(row)

    # Display accounts in a table
    print_table(
        title="Accounts",
        data=account_data_list,
        columns=["Index", "Name", "Status", "Encrypted", "Address"],
    )

    # Show active account status
    if active_account:
        success(f"Active account: [bold]{active_account}[/bold]")
    else:
        warning("No active account selected")

    # Instructions
    help_text = [
        "To switch accounts: [bold green underline]hippius account switch <account_name>[/bold green underline]",
        "To create a new account: [bold green underline]hippius account login[/bold green underline]",
    ]
    print_panel("\n".join(help_text), title="Account Management")

    return 0


def handle_account_switch(account_name: str) -> int:
    """Handle the account switch command"""
    # Check if account exists
    accounts = list_accounts()
    if account_name not in accounts:
        error(f"Account '{account_name}' not found")
        click.echo("Available accounts:")
        for account in accounts:
            click.echo(f"  {account}")
        return 1

    # Set as active account
    set_active_account(account_name)

    success(f"Switched to account: {account_name}")

    # Show account address if possible
    address = get_account_address(account_name)
    if address:
        draw_key_value("Address", address)

    return 0


def handle_account_login() -> int:
    """Handle the account login command - prompts for API token and validates it"""
    # Display the login banner
    draw_logo()
    click.echo()
    click.echo(
        click.style("Welcome to Hippius!", fg=BRAND_COLOR, bold=True)
        + " Let's set up your account."
    )
    click.echo()

    # Step 1: Account name
    draw_step(1, "Choose a name for your account")
    click.secho(
        "This name will be used to identify your account in the Hippius system.",
        dim=True,
    )
    name = click.prompt(click.style("Account name", fg="cyan", bold=True)).strip()

    if not name:
        error("Account name cannot be empty")
        return 1

    # Check if account already exists
    accounts = list_accounts()
    if name in accounts:
        warning(f"Account '{name}' already exists")
        if not click.confirm("Do you want to overwrite it?", default=False):
            info("Login cancelled")
            return 0

    # Step 2: API Token
    click.echo()
    draw_step(2, "Enter your Hippius API Token")
    click.secho("Your API token authenticates you with the Hippius platform.", dim=True)
    click.secho(
        "You can find this at https://console.hippius.com/dashboard/settings",
        dim=True,
    )
    api_token = click.prompt(click.style("API Token", fg="cyan", bold=True)).strip()

    if not api_token:
        error("API Token cannot be empty")
        return 1

    # Step 3: Validate the token
    click.echo()
    draw_step(3, "Validating your API token")

    account_address = None
    with _console.status("[cyan]Validating token...[/cyan]", spinner="dots"):
        api_url = get_config_value("arion", "api_url", "https://api.hippius.com/api")

        async def _validate():
            async with HippiusApiClient(api_url=api_url) as client:
                return await client.validate_token(api_token)

        try:
            token_result = asyncio.run(_validate())
        except HippiusAuthenticationError:
            error("Token validation failed: invalid or expired token")
            return 1

        account_address = token_result.substrate_address

    success(f"Token is valid! Account address: {account_address}")

    # Step 4: Encryption password (mandatory)
    click.echo()
    draw_step(4, "Set your encryption password")
    click.secho(
        "This password encrypts your API token and initializes file encryption.",
        dim=True,
    )
    click.secho(
        "You'll need it whenever you use your account for operations.",
        dim=True,
    )
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    if not password:
        error("Password cannot be empty")
        return 1

    # Step 5: Create account, encrypt token, and initialize per-account HCFS Drive
    click.echo()
    draw_step(5, "Setting up account and file encryption")

    recovery_phrase = None
    with _console.status("[cyan]Setting up your account...[/cyan]", spinner="dots"):
        config = load_config()

        # Store account data
        config["accounts"]["accounts"][name] = {
            "api_token": api_token,
            "api_token_encoded": False,
            "api_token_salt": None,
            "account_address": account_address,
        }

        # Set as active account
        config["accounts"]["active_account"] = name

        # Save the config first
        save_config(config)

        # Encrypt the API token
        encrypt_api_token(api_token, password, name)

        # Initialize per-account HCFS Drive
        drive_dir = get_drive_dir(name)
        os.makedirs(drive_dir, exist_ok=True)
        drive = Drive(drive_dir)
        if not drive.is_initialized():
            recovery_phrase = drive.init(password)

        time.sleep(0.5)  # Small delay for visual feedback

    # Display recovery phrase if newly generated
    if recovery_phrase:
        click.echo()
        _display_recovery_phrase(recovery_phrase)
    else:
        click.echo()
        info("File encryption already initialized for this account.")

    # Success box with account information
    result_lines = [
        f"Account Name: {name}",
        f"Account Address: {account_address}",
        "",
        "Login successful!",
        "Account set as active",
        "API token encrypted",
        "File encryption initialized",
    ]

    draw_success_box(result_lines)

    click.echo()
    click.secho(
        "You'll need your password when using this account for operations.",
        dim=True,
    )

    # Next steps
    click.echo()
    click.secho("Next steps:", fg=BRAND_COLOR, bold=True)
    click.echo("  hippius credits       - Check your account balance")
    click.echo("  hippius store <file>  - Upload a file to storage")
    click.echo("  hippius files         - View your stored files")

    return 0


def handle_account_delete(account_name: str) -> int:
    """Handle the account delete command"""
    # Check if account exists
    accounts = list_accounts()
    if account_name not in accounts:
        error(f"Account '{account_name}' not found")
        return 1

    # Confirm deletion
    warning(f"You are about to delete account '{account_name}'")
    click.echo("This action cannot be undone unless you have exported the account.")
    if not click.confirm("Delete this account?", default=False):
        click.echo("Deletion cancelled")
        return 0

    # Delete the account
    delete_account(account_name)

    success(f"Account '{account_name}' deleted successfully")

    # If this was the active account, notify user
    active_account = get_active_account()
    if active_account == account_name:
        warning("This was the active account. No account is currently active.")

        # If there are other accounts, suggest one
        remaining_accounts = list_accounts()
        if remaining_accounts:
            first_name = next(iter(remaining_accounts))
            click.echo(
                f"You can switch to another account with: hippius account switch {first_name}"
            )

    return 0


def handle_init_encryption(mnemonic: Optional[str] = None) -> int:
    """Handle the account init-encryption command — initialize HCFS file encryption."""

    account_name = get_active_account()
    if not account_name:
        error("No active account. Run: hippius account login")
        return 1

    info("Initializing HCFS file encryption...")

    drive_dir = get_drive_dir(account_name)
    os.makedirs(drive_dir, exist_ok=True)
    drive = Drive(drive_dir)
    if drive.is_initialized():
        warning("Encryption is already initialized.")
        if not click.confirm(
            "Re-initialize? This will overwrite the existing keys.", default=False
        ):
            info("Cancelled.")
            return 0

    # Prompt for password
    click.echo()
    draw_step(1, "Set encryption password")
    click.secho(
        "This password will be required to encrypt and decrypt your files.",
        dim=True,
    )
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    if not password:
        error("Password cannot be empty")
        return 1

    # Initialize
    click.echo()
    draw_step(2, "Generating encryption keys")

    with _console.status("[cyan]Initializing...[/cyan]", spinner="dots"):
        phrase = drive.init(password, mnemonic)

    # Display the mnemonic for backup
    if not mnemonic:
        click.echo()
        _display_recovery_phrase(phrase)
    else:
        success("Encryption initialized with provided recovery phrase.")

    click.echo()
    success("File encryption is now enabled!")
    click.secho(
        "Your files will be encrypted client-side before uploading.",
        dim=True,
    )

    return 0


def handle_show_mnemonic() -> int:
    """Handle the account show-mnemonic command — display saved recovery phrase."""

    account_name = get_active_account()
    if not account_name:
        error("No active account. Run: hippius account login")
        return 1

    drive_dir = get_drive_dir(account_name)
    drive = Drive(drive_dir)
    if not drive.is_initialized():
        error("Encryption is not initialized. Run: hippius account login")
        return 1

    password = click.prompt("Encryption password", hide_input=True)

    mnemonic_path = os.path.join(drive_dir, HCFS_METADATA_SUBDIR, "enc_mnemonic.json")
    if not os.path.exists(mnemonic_path):
        error("Encrypted mnemonic not found.")
        return 1

    # Decrypt mnemonic using PBKDF2 + AES-GCM (matching Rust hcfs-client scheme)
    with open(mnemonic_path, "r") as f:
        enc_data = json.load(f)

    mnemonic_str = decrypt_hcfs_mnemonic(enc_data, password)

    click.echo()
    click.secho("Recovery Phrase (24 words):", fg="yellow", bold=True)
    click.echo()
    click.echo(mnemonic_str)
    click.echo()
    warning("Keep this phrase safe — it can recover your encryption keys.")

    return 0


async def handle_account_balance(
    client: ArionClient, account_address: Optional[str] = None
) -> int:
    """Handle the account balance command - shows credit balance (API) or blockchain balance (Substrate)"""
    info("Checking account balance...")

    # Reuse the already-decrypted token from ArionClient (avoids double password prompt)
    api_token = client._api_token

    if api_token:
        api_url = get_config_value("arion", "api_url", "https://api.hippius.com/api")
        api_client = HippiusApiClient(api_url=api_url, api_token=api_token)

        balance_data = await api_client.get_account_balance()
        await api_client.close()

        credits = balance_data.get("balance", 0)
        credits = float(credits)

        # Create a panel with balance information
        balance_info = [
            f"Credit balance: [bold green]{credits:.2f} USD[/bold green]",
        ]

        # Add account info if available in response
        if "account" in balance_data:
            balance_info.append(
                f"Account: [bold cyan]{balance_data['account']}[/bold cyan]"
            )

        print_panel("\n".join(balance_info), title="Account Balance (API)")
        return 0

    # If no API token, try Substrate blockchain balance
    log("[dim]No API token available, checking blockchain balance instead...[/dim]")

    # Get the account address we're querying
    if account_address is None:
        from hippius_sdk.accounts import get_account_address as cfg_get_account_address

        active_account = get_active_account()
        if active_account:
            active_address = cfg_get_account_address(active_account)
            if active_address:
                account_address = active_address
            else:
                error(
                    f"Active account '{active_account}' does not have a valid address."
                )
                warning(
                    "Please provide an account address with '--address' or set up an account with:"
                )
                log(
                    "  [bold green underline]hippius account login[/bold green underline]"
                )
                return 1
        else:
            error("No account address available.")
            warning("Please either:")
            log(
                "  1. Set up an API token account: [bold green underline]hippius account login[/bold green underline]"
            )
            log(
                "  2. Provide an address: [bold green underline]hippius account balance --address <address>[/bold green underline]"
            )
            return 1

    # Try to get blockchain balance via Substrate
    substrate_url = get_config_value("substrate", "url", "wss://rpc.hippius.network")
    substrate = SubstrateInterface(url=substrate_url)

    # Get account info
    result = substrate.query("System", "Account", [account_address])

    if result:
        data = result.value["data"]
        decimals = substrate.properties.get("tokenDecimals", 18)
        unit = 10**decimals

        free = data["free"] / unit
        reserved = data["reserved"] / unit
        frozen = data.get("frozen", data.get("miscFrozen", 0)) / unit
        total = free + reserved

        # Create a panel with balance information
        balance_info = [
            f"Account address: [bold cyan]{account_address}[/bold cyan]",
            f"Free balance: [bold green]{free:.6f}[/bold green]",
            f"Reserved balance: [bold yellow]{reserved:.6f}[/bold yellow]",
            f"Frozen balance: [bold blue]{frozen:.6f}[/bold blue]",
            f"Total balance: [bold]{total:.6f}[/bold]",
        ]

        # Add the raw values in a more subtle format
        balance_info.append("\n[dim]Raw values:[/dim]")
        balance_info.append(f"[dim]Free: {data['free']:,}[/dim]")
        balance_info.append(f"[dim]Reserved: {data['reserved']:,}[/dim]")
        balance_info.append(f"[dim]Frozen: {frozen * unit:,.0f}[/dim]")

        print_panel("\n".join(balance_info), title="Account Balance (Blockchain)")
        return 0
    else:
        error(f"Could not fetch balance for address: {account_address}")
        return 1
