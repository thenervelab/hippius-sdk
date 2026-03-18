"""CLI handlers for configuration management."""

from hippius_sdk import (
    get_all_config,
    get_config_value,
    reset_config,
    set_config_value,
)
from hippius_sdk.cli_ui import (
    log,
    print_panel,
    success,
)


def handle_config_get(section: str, key: str) -> int:
    """Handle the config get command"""
    value = get_config_value(section, key)
    log(
        f"[bold cyan]{section}[/bold cyan].[bold green]{key}[/bold green] = [bold]{value}[/bold]"
    )
    return 0


def handle_config_set(section: str, key: str, value: str) -> int:
    """Handle the config set command"""
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


def handle_config_list() -> int:
    """Handle the config list command"""
    config = get_all_config()

    # Format the configuration as a multi-line string
    config_lines = ["Current configuration:"]

    for section, values in config.items():
        config_lines.append(f"\n[bold cyan]{section}[/bold cyan]")
        if isinstance(values, dict):
            for key, value in values.items():
                config_lines.append(
                    f"  [bold green]{key}[/bold green] = [bold]{value}[/bold]"
                )
        else:
            config_lines.append(f"  [bold]{values}[/bold]")

    # Print as a panel
    print_panel("\n".join(config_lines), title="Configuration")

    return 0


def handle_config_reset() -> int:
    """Handle the config reset command"""
    reset_config()
    success("Configuration reset to default values")
    return 0
