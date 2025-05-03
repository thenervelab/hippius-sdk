"""Rich UI components for the Hippius SDK CLI."""

import argparse
import sys
from typing import Any, Dict, List, Optional, Union

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
from rich.text import Text

# Create a global console instance
console = Console()


def log(message: str, style: Optional[str] = None) -> None:
    """Log a message to the console with optional styling.

    Args:
        message: The message to log
        style: Optional style to apply to the message
    """
    console.print(message, style=style)


def info(message: str) -> None:
    """Log an info message to the console.

    Args:
        message: The info message to log
    """
    console.print(f"[blue]INFO:[/blue] {message}")


def success(message: str) -> None:
    """Log a success message to the console.

    Args:
        message: The success message to log
    """
    console.print(f"[green]SUCCESS:[/green] {message}")


def warning(message: str) -> None:
    """Log a warning message to the console.

    Args:
        message: The warning message to log
    """
    console.print(f"[yellow]WARNING:[/yellow] {message}")


def error(message: str) -> None:
    """Log an error message to the console.

    Args:
        message: The error message to log
    """
    console.print(f"[bold red]ERROR:[/bold red] {message}")


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
    console.print(table)


def print_panel(content: str, title: Optional[str] = None) -> None:
    """Print content in a panel.

    Args:
        content: The content to display in the panel
        title: Optional title for the panel
    """
    console.print(Panel(content, title=title))


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
        console=console,
    )


def print_help_text(parser: "argparse.ArgumentParser"):
    """Print help text with Rich formatting.

    Args:
        parser: The argparse parser to display help for
    """
    # Get the help text from the parser
    import io

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
            console.print(f"[bold cyan]{title}[/bold cyan]")
            if usage:
                console.print(f"[yellow]{usage}[/yellow]")
        elif "positional arguments:" in section:
            lines = section.split("\n")
            title = lines[0]
            args = "\n".join(lines[1:])
            console.print(f"\n[bold green]{title}[/bold green]")
            console.print(args)
        elif "options:" in section:
            lines = section.split("\n")
            title = lines[0]
            opts = "\n".join(lines[1:])
            console.print(f"\n[bold green]{title}[/bold green]")
            console.print(opts)
        elif "examples:" in section:
            lines = section.split("\n")
            title = lines[0]
            examples = "\n".join(lines[1:])
            console.print(f"\n[bold magenta]{title}[/bold magenta]")
            console.print(f"[cyan]{examples}[/cyan]")
        else:
            console.print(f"\n{section}")


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
        from hippius_sdk.cli_assets import HERO_TITLE

        console.print(HERO_TITLE, style="bold cyan")

        # Use our print_help_text function instead of the default formatter
        print_help_text(parser)
        parser.exit()


class ProgressTracker:
    """Helper class for tracking progress in async operations with Rich progress bars."""

    def __init__(self, description: str, total: int):
        """Initialize a progress tracker.

        Args:
            description: Description for the progress bar
            total: Total number of items to process
        """
        self.progress = create_progress()
        self.task_id = None
        self.description = description
        self.total = total
        self.completed = 0

    def __enter__(self):
        """Context manager entry that initializes the progress bar."""
        self.progress.__enter__()
        self.task_id = self.progress.add_task(self.description, total=self.total)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit that properly closes the progress bar."""
        self.progress.__exit__(exc_type, exc_val, exc_tb)

    def update(self, advance: int = 1):
        """Update the progress bar.

        Args:
            advance: Number of steps to advance by (default: 1)
        """
        self.completed += advance
        self.progress.update(self.task_id, completed=self.completed)

    def set_description(self, description: str):
        """Update the progress bar description.

        Args:
            description: New description text
        """
        self.progress.update(self.task_id, description=description)

    def finish(self):
        """Mark the progress as complete."""
        self.progress.update(self.task_id, completed=self.total)
