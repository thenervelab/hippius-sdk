"""CLI handlers for default address management."""

from typing import Optional

import click

from hippius_sdk import (
    load_config,
    save_config,
)
from hippius_sdk.cli_ui import (
    log,
    print_panel,
    success,
    warning,
)


def get_default_address() -> Optional[str]:
    """Get the default address for read-only operations"""
    config = load_config()
    return config.get("substrate", {}).get("default_address")


def handle_default_address_set(address: str) -> int:
    """Handle the address set-default command"""
    # Validate address format
    if not address.startswith("5"):
        warning("The address does not appear to be a valid Substrate address")
        log("Substrate addresses typically start with '5'", style="yellow")
        if not click.confirm("Continue anyway?", default=False):
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


def handle_default_address_get() -> int:
    """Handle the address get-default command"""
    address = get_default_address()

    if address:
        log(f"Default address: [bold cyan]{address}[/bold cyan]")
    else:
        warning("No default address set")
        log(
            "You can set one with: [bold]hippius address set-default <address>[/bold]"
        )

    return 0


def handle_default_address_clear() -> int:
    """Handle the address clear-default command"""
    config = load_config()

    if "substrate" in config and "default_address" in config["substrate"]:
        del config["substrate"]["default_address"]
        save_config(config)
        success("Default address cleared")
    else:
        log("No default address was set", style="yellow")

    return 0
