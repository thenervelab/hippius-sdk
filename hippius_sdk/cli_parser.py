#!/usr/bin/env python3
"""
Command Line Interface argument parser for Hippius SDK.

This module provides the argument parsing functionality for the Hippius CLI,
defining all available commands, subcommands, and their respective arguments.
"""

import argparse

from hippius_sdk import get_config_value


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the CLI."""
    # Import custom help action that shows the logo
    from hippius_sdk.cli_ui import RichHelpAction

    # Set up the argument parser
    parser = argparse.ArgumentParser(
        description="Hippius SDK Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # Disable the default help action
        epilog="""
examples:
  # Store a file
  hippius store example.txt

  # Download a file
  hippius download <file_id> output.txt

  # Delete a file
  hippius delete <file_id>

  # View your available credits
  hippius credits

  # View your stored files
  hippius files

  # Account login
  hippius account login

  # Miner registration
  hippius miner register-coldkey --node-id <id> --node-priv-hex <hex> --node-type StorageMiner
""",
    )

    # Add our custom help option
    parser.add_argument(
        "-h", "--help", action=RichHelpAction, help="Show this help message and exit"
    )

    from hippius_sdk import __version__

    parser.add_argument(
        "--version",
        action="version",
        version=f"{__version__} (Hippius Python SDK)",
    )

    # Optional arguments for all commands
    parser.add_argument(
        "--substrate-url",
        default=get_config_value("substrate", "url", "wss://rpc.hippius.network"),
        help="Substrate node WebSocket URL (default: from config or wss://rpc.hippius.network)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=get_config_value("cli", "verbose", False),
        help="Enable verbose debug output",
    )
    parser.add_argument(
        "--hippius-key",
        help="API token for authentication (uses config if not specified)",
    )
    parser.add_argument(
        "--hippius-key-password",
        help="Password to decrypt the API token if needed (will prompt if required and not provided)",
    )
    parser.add_argument(
        "--account",
        help="Account name to use (uses active account if not specified)",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Add all command parsers
    add_file_commands(subparsers)
    add_market_commands(subparsers)
    add_config_commands(subparsers)
    add_account_commands(subparsers)
    add_miner_commands(subparsers)

    return parser


def add_file_commands(subparsers):
    """Add file operation commands to the parser."""
    # Store command
    store_parser = subparsers.add_parser(
        "store", help="Upload a file to Hippius storage"
    )
    store_parser.add_argument("file_path", help="Path of file to upload")

    # Download command
    download_parser = subparsers.add_parser(
        "download", help="Download a file from Hippius storage"
    )
    download_parser.add_argument("file_id", help="File ID to download")
    download_parser.add_argument("output_path", help="Path to save downloaded file")

    # Delete command
    delete_parser = subparsers.add_parser(
        "delete", help="Delete a file from Hippius storage"
    )
    delete_parser.add_argument("file_id", help="File ID to delete")
    delete_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Skip confirmation prompt",
    )


def add_market_commands(subparsers):
    """Add marketplace/billing commands to the parser."""
    # Credits command
    subparsers.add_parser("credits", help="Check your account credit balance")

    # Files command
    subparsers.add_parser("files", help="List stored files (coming soon)")


def add_config_commands(subparsers):
    """Add configuration commands to the parser."""
    config_parser = subparsers.add_parser(
        "config", help="Manage Hippius SDK configuration"
    )

    config_subparsers = config_parser.add_subparsers(
        dest="config_action", help="Configuration commands"
    )

    # Config get
    config_get = config_subparsers.add_parser("get", help="Get a configuration value")
    config_get.add_argument("section", help="Configuration section")
    config_get.add_argument("key", help="Configuration key")

    # Config set
    config_set = config_subparsers.add_parser("set", help="Set a configuration value")
    config_set.add_argument("section", help="Configuration section")
    config_set.add_argument("key", help="Configuration key")
    config_set.add_argument("value", help="Configuration value")

    # Config list
    config_subparsers.add_parser("list", help="List all configuration values")

    # Config reset
    config_subparsers.add_parser("reset", help="Reset configuration to defaults")


def add_account_commands(subparsers):
    """Add account management commands to the parser."""
    account_parser = subparsers.add_parser("account", help="Manage Hippius accounts")

    account_subparsers = account_parser.add_subparsers(
        dest="account_action", help="Account commands"
    )

    # Account login
    account_subparsers.add_parser("login", help="Log in with an API token")

    # Account list
    account_subparsers.add_parser("list", help="List all accounts")

    # Account switch
    switch_parser = account_subparsers.add_parser(
        "switch", help="Switch active account"
    )
    switch_parser.add_argument("account_name", help="Account name to switch to")

    # Account delete
    delete_parser = account_subparsers.add_parser("delete", help="Delete an account")
    delete_parser.add_argument("account_name", help="Account name to delete")

    # Account info
    info_parser = account_subparsers.add_parser("info", help="Show account information")
    info_parser.add_argument(
        "--name",
        help="Account name (uses active account if not specified)",
    )

    # Account balance
    balance_parser = account_subparsers.add_parser(
        "balance", help="Check account balance"
    )
    balance_parser.add_argument(
        "--name",
        help="Account name (uses active account if not specified)",
    )
    balance_parser.add_argument(
        "--address",
        help="Account address to check balance for",
    )

    # Account export
    export_parser = account_subparsers.add_parser(
        "export", help="Export an account to a file"
    )
    export_parser.add_argument(
        "--name",
        help="Account name to export (uses active account if not specified)",
    )
    export_parser.add_argument(
        "--file-path",
        help="File path to save the export (default: <name>_hippius_account.json)",
    )

    # Account import
    import_parser = account_subparsers.add_parser(
        "import", help="Import an account from a file"
    )
    import_parser.add_argument("file_path", help="Path to account file to import")
    import_parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the imported credentials",
    )

    # Account init-encryption
    init_enc_parser = account_subparsers.add_parser(
        "init-encryption",
        help="Re-initialize HCFS file encryption (normally set up during login)",
    )
    init_enc_parser.add_argument(
        "--mnemonic",
        help="Existing 24-word recovery phrase (generates new if not provided)",
    )

    # Account show-mnemonic
    account_subparsers.add_parser(
        "show-mnemonic",
        help="Display the saved encryption recovery phrase (requires password)",
    )


def add_miner_commands(subparsers):
    """Add miner registration/verification commands to the parser."""
    miner_parser = subparsers.add_parser(
        "miner", help="Miner registration and verification commands"
    )

    miner_subparsers = miner_parser.add_subparsers(
        dest="miner_action", help="Miner commands"
    )

    # Common miner arguments
    def add_common_miner_args(parser, include_node_type=True):
        parser.add_argument(
            "--node-id", required=True, help="Node ID (base58 or 0x hex)"
        )
        parser.add_argument(
            "--node-priv-hex",
            required=True,
            help="Node private key in hex format",
        )
        if include_node_type:
            parser.add_argument(
                "--node-type",
                required=True,
                choices=["StorageMiner", "Validator", "ComputeMiner"],
                help="Type of node to register",
            )
        parser.add_argument(
            "--ipfs-config",
            help="Path to IPFS config file for extracting peer identity",
        )
        parser.add_argument(
            "--ipfs-priv-b64",
            help="Base64-encoded IPFS private key",
        )
        parser.add_argument(
            "--ipfs-peer-id",
            help="IPFS peer ID (base58)",
        )
        parser.add_argument(
            "--expires-in",
            type=int,
            default=10,
            help="Number of blocks until challenge expires (default: 10)",
        )
        parser.add_argument(
            "--block-width",
            default="u32",
            choices=["u32", "u64"],
            help="Block number encoding width (default: u32)",
        )
        parser.add_argument(
            "--nonce-hex",
            help="Hex-encoded nonce (random if not specified)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print payload without submitting transaction",
        )

    # Register coldkey
    coldkey_parser = miner_subparsers.add_parser(
        "register-coldkey", help="Register a node with coldkey"
    )
    add_common_miner_args(coldkey_parser)
    coldkey_parser.add_argument(
        "--pay-in-credits",
        action="store_true",
        help="Pay registration fee in credits instead of tokens",
    )

    # Register hotkey
    hotkey_parser = miner_subparsers.add_parser(
        "register-hotkey", help="Register a node with hotkey"
    )
    hotkey_parser.add_argument(
        "--coldkey",
        required=True,
        help="Coldkey SS58 address",
    )
    add_common_miner_args(hotkey_parser)
    hotkey_parser.add_argument(
        "--pay-in-credits",
        action="store_true",
        help="Pay registration fee in credits instead of tokens",
    )

    # Verify node
    verify_parser = miner_subparsers.add_parser(
        "verify-node", help="Verify an existing node"
    )
    add_common_miner_args(verify_parser, include_node_type=False)

    # Verify coldkey node
    verify_coldkey_parser = miner_subparsers.add_parser(
        "verify-coldkey-node", help="Verify an existing coldkey node"
    )
    add_common_miner_args(verify_coldkey_parser, include_node_type=False)


def get_subparser(name: str):
    """Get a specific subparser by name for help display."""
    parser = create_parser()
    # Walk through the subparsers to find the named one
    for action in parser._subparsers._actions:
        if isinstance(action, argparse._SubParsersAction):
            for choice_name, subparser in action.choices.items():
                if choice_name == name:
                    return subparser
    return parser


def parse_arguments():
    """Parse command line arguments."""
    parser = create_parser()
    args = parser.parse_args()

    # Set defaults for backwards compatibility
    if not hasattr(args, "miner_ids"):
        args.miner_ids = None

    return args
