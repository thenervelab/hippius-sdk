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
LOGIN_ASSET = r"""
┬ ┬┬┌─┐┌─┐┬┬ ┬┌─┐
├─┤│├─┘├─┘││ │└─┐
┴ ┴┴┴  ┴  ┴└─┘└─┘
"""

import click
import os

# Brand color RGB tuple
BRAND_COLOR = (49, 103, 221)


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
