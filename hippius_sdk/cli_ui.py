"""
Unified UI components for the Hippius SDK CLI.

Merges the former cli_rich.py (Rich-based output) and cli_assets.py
(ASCII art, box-drawing helpers) into a single module.
"""

import argparse
import io
import os
import re
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

# Brand color RGB
BRAND_COLOR = (49, 103, 221)

# Rich console — kept for tables, progress bars, and status spinners only
_console = Console()


# --- ASCII art constants ---

HERO_TITLE = r"""
 /$$   /$$ /$$$$$$ /$$$$$$$  /$$$$$$$  /$$$$$$ /$$   /$$  /$$$$$$
| $$  | $$|_  $$_/| $$__  $$| $$__  $$|_  $$_/| $$  | $$ /$$__  $$
| $$  | $$  | $$  | $$  \ $$| $$  \ $$  | $$  | $$  | $$| $$  \__/
| $$$$$$$$  | $$  | $$$$$$$/| $$$$$$$/  | $$  | $$  | $$|  $$$$$$
| $$__  $$  | $$  | $$____/ | $$____/   | $$  | $$  | $$ \____  $$
| $$  | $$  | $$  | $$      | $$        | $$  | $$  | $$ /$$  \ $$
| $$  | $$ /$$$$$$| $$      | $$       /$$$$$$|  $$$$$$/|  $$$$$$/
|__/  |__/|______/|__/      |__/      |______/ \______/  \______/
"""

# --- Low-level helpers ---


def _strip_rich_markup(text: str) -> str:
    """Strip Rich markup tags like [bold cyan]...[/bold cyan] from a string."""
    return re.sub(r"\[/?[^\]]+\]", "", text)


# --- Logging functions (Click-based) ---


def log(message: str, style: Optional[str] = None) -> None:
    """Log a message to the console with optional styling.

    Args:
        message: The message to log
        style: Optional style to apply to the message
    """
    cleaned = _strip_rich_markup(message)
    if style == "dim":
        click.secho(cleaned, dim=True)
    elif style == "bold":
        click.secho(cleaned, bold=True)
    elif style:
        click.echo(cleaned)
    else:
        click.echo(cleaned)


def info(message: str) -> None:
    """Log an info message to the console.

    Args:
        message: The info message to log
    """
    cleaned = _strip_rich_markup(message)
    click.echo(click.style("INFO:", fg=BRAND_COLOR, bold=True) + " " + cleaned)


def success(message: str) -> None:
    """Log a success message to the console.

    Args:
        message: The success message to log
    """
    cleaned = _strip_rich_markup(message)
    click.echo(click.style("SUCCESS:", fg="green", bold=True) + " " + cleaned)


def warning(message: str) -> None:
    """Log a warning message to the console.

    Args:
        message: The warning message to log
    """
    cleaned = _strip_rich_markup(message)
    click.echo(click.style("WARNING:", fg="yellow", bold=True) + " " + cleaned)


def error(message: str) -> None:
    """Log an error message to the console.

    Args:
        message: The error message to log
    """
    cleaned = _strip_rich_markup(message)
    click.echo(click.style("ERROR:", fg="red", bold=True) + " " + cleaned, err=True)


# --- Rich-based output (tables, panels, progress) ---


def print_table(
    title: str,
    data: List[Dict[str, Any]],
    columns: List[str],
    style: Optional[str] = None,
) -> None:
    """Print a table of data.

    Args:
        title: The title of the table
        data: List of dictionaries containing the data
        columns: List of column names to include
        style: Optional style to apply to the table
    """
    # Create table with optional style and expanded width
    table = Table(title=title, style=style, expand=True, show_edge=True)

    # Add columns
    for column in columns:
        table.add_column(column)

    # Add rows, applying style to each cell if provided
    for row in data:
        values = [str(row.get(column, "")) for column in columns]
        if style:
            # Apply style to each cell value if a style is provided
            styled_values = [f"[{style}]{value}[/{style}]" for value in values]
            table.add_row(*styled_values)
        else:
            table.add_row(*values)

    # Print the table
    _console.print(table)


def print_panel(content: str, title: Optional[str] = None) -> None:
    """Print content in a panel.

    Args:
        content: The content to display in the panel
        title: Optional title for the panel
    """
    _console.print(Panel(content, title=title))


def create_progress() -> Progress:
    """Create a Rich progress bar for tracking operations.

    Returns:
        A Rich Progress instance configured for the Hippius CLI
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=_console,
    )


# --- Argparse help (Rich-styled) ---


def print_help_text(parser: "argparse.ArgumentParser"):
    """Print help text with Click formatting.

    Args:
        parser: The argparse parser to display help for
    """
    # Get the help text from the parser
    buffer = io.StringIO()
    parser.print_help(buffer)
    help_text = buffer.getvalue()

    # Split the help text into sections
    sections = help_text.split("\n\n")

    # Process and print each section with appropriate styling
    for i, section in enumerate(sections):
        if i == 0:  # Usage section
            lines = section.split("\n")
            title = lines[0]
            usage = "\n".join(lines[1:]) if len(lines) > 1 else ""
            click.secho(title, fg=BRAND_COLOR, bold=True)
            if usage:
                click.secho(usage, fg="yellow")
        elif "positional arguments:" in section:
            lines = section.split("\n")
            title = lines[0]
            args_text = "\n".join(lines[1:])
            click.echo()
            click.secho(title, fg="green", bold=True)
            click.echo(args_text)
        elif "options:" in section:
            lines = section.split("\n")
            title = lines[0]
            opts = "\n".join(lines[1:])
            click.echo()
            click.secho(title, fg="green", bold=True)
            click.echo(opts)
        elif "examples:" in section:
            lines = section.split("\n")
            title = lines[0]
            examples = "\n".join(lines[1:])
            click.echo()
            click.secho(title, fg="magenta", bold=True)
            click.secho(examples, fg="cyan")
        else:
            click.echo()
            click.echo(section)


class RichHelpAction(argparse.Action):
    """Custom help action that displays the Hippius logo and uses Rich formatting."""

    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        # Display the Hippius logo banner when help is requested
        draw_logo()

        # Use our print_help_text function instead of the default formatter
        print_help_text(parser)
        parser.exit()


# --- Draw helpers (box-drawing, ASCII art) ---


def draw_logo(logo_text=None):
    """Display the HERO_TITLE logo in brand color.

    Args:
        logo_text: Optional custom logo text (defaults to HERO_TITLE)
    """
    text = logo_text or HERO_TITLE
    click.secho(text, fg=BRAND_COLOR, bold=True)


def draw_panel(content, title=None, border_color=None):
    """Draw a box-drawing panel around content.

    Args:
        content: String content (may be multi-line)
        title: Optional title shown in the top border
        border_color: Optional RGB tuple or click color name for the border
    """
    color = border_color or BRAND_COLOR
    lines = content.split("\n")
    width = max((len(line) for line in lines), default=0)
    # Account for title length
    if title:
        width = max(width, len(title) + 4)
    width = max(width, 20)
    inner_width = width + 2  # 1 space padding on each side

    # Top border
    if title:
        padding = inner_width - len(title) - 2
        left_pad = padding // 2
        right_pad = padding - left_pad
        top = "┌" + "─" * left_pad + " " + title + " " + "─" * right_pad + "┐"
    else:
        top = "┌" + "─" * inner_width + "┐"

    click.secho(top, fg=color)

    # Content lines
    for line in lines:
        padded = " " + line.ljust(width) + " "
        click.echo(click.style("│", fg=color) + padded + click.style("│", fg=color))

    # Bottom border
    bottom = "└" + "─" * inner_width + "┘"
    click.secho(bottom, fg=color)


def draw_banner(text, color=None):
    """Display a styled banner line.

    Args:
        text: Banner text
        color: Optional RGB tuple or click color name
    """
    click.secho(text, fg=color or BRAND_COLOR, bold=True)


def draw_divider(char="─", width=None, color=None):
    """Draw a horizontal divider line.

    Args:
        char: Character to repeat (default: ─)
        width: Width of the divider (default: terminal width)
        color: Optional RGB tuple or click color name
    """
    if width is None:
        width = os.get_terminal_size(fallback=(80, 24)).columns
    click.secho(char * width, fg=color or BRAND_COLOR, dim=True)


def draw_step(step_number, title, description=None):
    """Display a wizard step indicator.

    Args:
        step_number: Step number (int)
        title: Step title
        description: Optional step description
    """
    marker = click.style(f"  Step {step_number}:", fg=BRAND_COLOR, bold=True)
    click.echo(marker + " " + click.style(title, bold=True))
    if description:
        click.secho(f"           {description}", dim=True)


def draw_success_box(lines):
    """Draw a green-bordered panel for success messages.

    Args:
        lines: List of strings or a single string
    """
    if isinstance(lines, str):
        lines = lines.split("\n")
    draw_panel("\n".join(lines), title="Success", border_color="green")


def draw_key_value(key, value, key_color=None):
    """Display a key-value pair with styled key.

    Args:
        key: The label
        value: The value
        key_color: Optional RGB tuple or click color name for the key
    """
    styled_key = click.style(f"{key}:", fg=key_color or BRAND_COLOR, bold=True)
    click.echo(f"  {styled_key} {value}")
