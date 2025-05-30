#!/usr/bin/env python3
"""
Command Line Interface argument parser for Hippius SDK.

This module provides the argument parsing functionality for the Hippius CLI,
defining all available commands, subcommands, and their respective arguments.
"""

import argparse

from hippius_sdk import get_config_value


def get_default_address():
    """Get the default address for read-only operations"""
    from hippius_sdk import load_config

    config = load_config()
    return config["substrate"].get("default_address")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the CLI."""
    # Import custom help action that shows the logo
    from hippius_sdk.cli_rich import RichHelpAction

    # Set up the argument parser
    parser = argparse.ArgumentParser(
        description="Hippius SDK Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # Disable the default help action
        epilog="""
examples:
  # Store a file
  hippius store example.txt
  
  # Add a file (alias for store)
  hippius add example.txt
  
  # Store a directory
  hippius store-dir ./my_directory
  
  # Download a file
  hippius download QmHash output.txt
  
  # Check if a CID exists
  hippius exists QmHash
  
  # View the content of a CID
  hippius cat QmHash
  
  # View your available credits
  hippius credits
  
  # View your stored files
  hippius files
  
  # View all miners for stored files
  hippius files --all-miners
  
  # Check file pinning status
  hippius pinning-status
  
  # Erasure code a file (Reed-Solomon)
  hippius erasure-code large_file.mp4 --k 3 --m 5
  
  # Erasure code without publishing to global IPFS network
  hippius erasure-code large_file.avi --no-publish

  # Reconstruct an erasure-coded file
  hippius reconstruct QmMetadataHash reconstructed_file.mp4

  # Pin a CID to IPFS and publish to blockchain
  hippius pin QmHash

  # Pin a CID to IPFS without publishing to blockchain
  hippius pin QmHash --no-publish

  # Delete a file from IPFS and marketplace
  hippius delete QmHash

  # Delete an erasure-coded file and all its chunks
  hippius ec-delete QmMetadataHash
  
  # Configure PostgreSQL key storage
  hippius config set key_storage database_url 'postgresql://user:pass@localhost:5432/hippius_keys'
  hippius config set key_storage enabled true
""",
    )

    # Add our custom help option
    parser.add_argument(
        "-h", "--help", action=RichHelpAction, help="Show this help message and exit"
    )

    # Optional arguments for all commands
    parser.add_argument(
        "--gateway",
        default=get_config_value("ipfs", "gateway", "https://get.hippius.network"),
        help="IPFS gateway URL for downloads (default: from config or https://get.hippius.network)",
    )
    parser.add_argument(
        "--api-url",
        default=get_config_value("ipfs", "api_url", "https://store.hippius.network"),
        help="IPFS API URL for uploads (default: from config or https://store.hippius.network)",
    )
    parser.add_argument(
        "--local-ipfs",
        action="store_true",
        default=get_config_value("ipfs", "local_ipfs", False),
        help="Use local IPFS node (http://localhost:5001) instead of remote API",
    )
    parser.add_argument(
        "--substrate-url",
        default=get_config_value("substrate", "url", "wss://rpc.hippius.network"),
        help="Substrate node WebSocket URL (default: from config or wss://rpc.hippius.network)",
    )
    parser.add_argument(
        "--miner-ids",
        help="Comma-separated list of miner IDs for storage (default: from config)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=get_config_value("cli", "verbose", False),
        help="Enable verbose debug output",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt files when uploading (overrides default)",
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Do not encrypt files when uploading (overrides default)",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt files when downloading (overrides default)",
    )
    parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Do not decrypt files when downloading (overrides default)",
    )
    parser.add_argument(
        "--encryption-key",
        help="Base64-encoded encryption key (overrides HIPPIUS_ENCRYPTION_KEY in .env)",
    )
    parser.add_argument(
        "--password",
        help="Password to decrypt the seed phrase if needed (will prompt if required and not provided)",
    )
    parser.add_argument(
        "--account",
        help="Account name to use (uses active account if not specified)",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Add all command parsers
    add_file_commands(subparsers)
    add_storage_commands(subparsers)
    add_market_commands(subparsers)
    add_erasure_coding_commands(subparsers)
    add_config_commands(subparsers)
    add_seed_commands(subparsers)
    add_account_commands(subparsers)
    add_address_commands(subparsers)

    return parser


def add_file_commands(subparsers):
    """Add file operation commands to the parser."""
    # Download command
    download_parser = subparsers.add_parser(
        "download", help="Download a file from IPFS"
    )
    download_parser.add_argument("cid", help="CID of file to download")
    download_parser.add_argument("output_path", help="Path to save downloaded file")

    # Exists command
    exists_parser = subparsers.add_parser(
        "exists", help="Check if a CID exists on IPFS"
    )
    exists_parser.add_argument("cid", help="CID to check")

    # Cat command
    cat_parser = subparsers.add_parser(
        "cat", help="Display content of a file from IPFS"
    )
    cat_parser.add_argument("cid", help="CID of file to display")
    cat_parser.add_argument(
        "--max-size",
        type=int,
        default=1024,
        help="Maximum number of bytes to display (default: 1024)",
    )


def add_storage_commands(subparsers):
    """Add storage commands to the parser."""
    # Store command (upload to IPFS then store on Substrate)
    store_parser = subparsers.add_parser(
        "store", help="Upload a file to IPFS and store it on Substrate"
    )
    store_parser.add_argument("file_path", help="Path to file to upload")
    store_parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish file to IPFS and store on the blockchain (default)",
    )
    store_parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Don't publish file to IPFS or store on the blockchain (local only)",
    )

    # Add command (alias for store)
    add_parser = subparsers.add_parser(
        "add",
        help="Upload a file to IPFS and store it on Substrate (alias for 'store')",
    )
    add_parser.add_argument("file_path", help="Path to file to upload")
    add_parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish file to IPFS and store on the blockchain (default)",
    )
    add_parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Don't publish file to IPFS or store on the blockchain (local only)",
    )

    # Store directory command
    store_dir_parser = subparsers.add_parser(
        "store-dir", help="Upload a directory to IPFS and store all files on Substrate"
    )
    store_dir_parser.add_argument("dir_path", help="Path to directory to upload")
    store_dir_parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish all files to IPFS and store on the blockchain (default)",
    )
    store_dir_parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Don't publish files to IPFS or store on the blockchain (local only)",
    )

    # Pinning status command
    pinning_status_parser = subparsers.add_parser(
        "pinning-status", help="Check the status of file pinning requests"
    )
    pinning_status_parser.add_argument(
        "--account_address",
        help="Substrate account to view pins for (defaults to your keyfile account)",
    )
    pinning_status_parser.add_argument(
        "--no-contents",
        action="store_true",
        help="Don't fetch additional content info for pins",
    )

    # Delete command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a file from IPFS and cancel its storage on the blockchain",
    )
    delete_parser.add_argument("cid", help="CID of file to delete")
    delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Delete without confirmation prompt",
    )

    # Pin command
    pin_parser = subparsers.add_parser(
        "pin",
        help="Pin a CID to IPFS and publish to blockchain",
    )
    pin_parser.add_argument("cid", help="CID to pin")
    pin_parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish file to IPFS and store on the blockchain (default)",
    )
    pin_parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Don't publish file to blockchain (local pinning only)",
    )

    # Keygen command
    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate an encryption key for secure file storage"
    )
    keygen_parser.add_argument(
        "--save",
        action="store_true",
        help="Save the generated key to the configuration",
    )
    keygen_parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy the key to clipboard (requires pyperclip)",
    )


def add_market_commands(subparsers):
    """Add marketplace commands to the parser."""
    # Credits command
    credits_parser = subparsers.add_parser(
        "credits", help="Check free credits for an account in the marketplace"
    )
    credits_parser.add_argument(
        "account_address",
        nargs="?",
        default=None,
        help="Substrate account address (uses keypair address if not specified)",
    )

    # Files command
    files_parser = subparsers.add_parser(
        "files", help="View files stored by you or another account"
    )
    files_parser.add_argument(
        "--account_address",
        help="Substrate account to view files for (defaults to your keyfile account)",
    )
    files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each file",
    )

    files_parser.add_argument(
        "cid",
        help="CID to filter on",
        default=None,
        nargs="?",
    )


def add_erasure_coding_commands(subparsers):
    """Add erasure coding commands to the parser."""
    # Erasure coded files command
    ec_files_parser = subparsers.add_parser(
        "ec-files", help="View erasure-coded files stored by you or another account"
    )
    ec_files_parser.add_argument(
        "--account_address",
        help="Substrate account to view EC files for (defaults to your keyfile account)",
    )
    ec_files_parser.add_argument(
        "--all-miners",
        action="store_true",
        help="Show all miners for each chunk",
    )
    ec_files_parser.add_argument(
        "--show-chunks",
        action="store_true",
        help="Show individual chunks for each file",
    )

    ec_files_parser.add_argument(
        "cid",
        help="CID to filter on",
        default=None,
        nargs="?",
    )

    # EC Delete command
    ec_delete_parser = subparsers.add_parser(
        "ec-delete", help="Delete an erasure-coded file and all its chunks"
    )
    ec_delete_parser.add_argument(
        "metadata_cid", help="Metadata CID of the erasure-coded file to delete"
    )
    ec_delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Delete without confirmation prompt",
    )

    # Erasure code command
    erasure_code_parser = subparsers.add_parser(
        "erasure-code", help="Erasure code a file"
    )
    erasure_code_parser.add_argument("file_path", help="Path to file to erasure code")
    erasure_code_parser.add_argument(
        "--k",
        type=int,
        default=3,
        help="Number of chunks needed for reconstruction (default: 3)",
    )
    erasure_code_parser.add_argument(
        "--m",
        type=int,
        default=5,
        help="Total number of chunks to create (default: 5)",
    )
    erasure_code_parser.add_argument(
        "--chunk-size",
        type=int,
        default=10,
        help="Chunk size in MB (default: 10)",
    )
    erasure_code_parser.add_argument(
        "--no-publish",
        action="store_true",
        help="Don't publish to the global IPFS network",
    )

    # Reconstruct command
    reconstruct_parser = subparsers.add_parser(
        "reconstruct", help="Reconstruct an erasure-coded file"
    )
    reconstruct_parser.add_argument(
        "metadata_cid", help="Metadata CID of the erasure-coded file"
    )
    reconstruct_parser.add_argument(
        "output_file", help="Path to save the reconstructed file"
    )


def add_config_commands(subparsers):
    """Add configuration commands to the parser."""
    # Config command
    config_parser = subparsers.add_parser(
        "config", help="Manage Hippius SDK configuration"
    )
    config_subparsers = config_parser.add_subparsers(
        dest="config_action", help="Configuration action"
    )

    # Get configuration value
    get_parser = config_subparsers.add_parser("get", help="Get a configuration value")
    get_parser.add_argument(
        "section",
        help="Configuration section (ipfs, substrate, encryption, erasure_coding, cli, key_storage)",
    )
    get_parser.add_argument("key", help="Configuration key")

    # Set configuration value
    set_parser = config_subparsers.add_parser("set", help="Set a configuration value")
    set_parser.add_argument(
        "section",
        help="Configuration section (ipfs, substrate, encryption, erasure_coding, cli, key_storage)",
    )
    set_parser.add_argument("key", help="Configuration key")
    set_parser.add_argument("value", help="Configuration value")

    # List configuration
    config_subparsers.add_parser("list", help="List all configuration values")

    # Reset configuration to defaults
    config_subparsers.add_parser("reset", help="Reset configuration to default values")

    # Import config from .env
    config_subparsers.add_parser(
        "import-env", help="Import configuration from .env file"
    )


def add_seed_commands(subparsers):
    """Add seed phrase commands to the parser."""
    # Seed command
    seed_parser = subparsers.add_parser("seed", help="Manage substrate seed phrase")
    seed_subparsers = seed_parser.add_subparsers(
        dest="seed_action", help="Seed phrase action"
    )

    # Set seed phrase
    set_seed_parser = seed_subparsers.add_parser(
        "set", help="Set the substrate seed phrase"
    )
    set_seed_parser.add_argument(
        "seed_phrase", help="Substrate seed phrase (12 or 24 words)"
    )
    set_seed_parser.add_argument(
        "--encode",
        action="store_true",
        help="Encrypt the seed phrase with a password",
    )
    set_seed_parser.add_argument(
        "--account",
        help="Account name to use (uses default if not specified)",
    )

    # Encode seed phrase
    encode_seed_parser = seed_subparsers.add_parser(
        "encode", help="Encrypt the existing seed phrase"
    )
    encode_seed_parser.add_argument(
        "--account",
        help="Account name to use (uses default if not specified)",
    )

    # Decode seed phrase
    decode_seed_parser = seed_subparsers.add_parser(
        "decode", help="Temporarily decrypt and display the seed phrase"
    )
    decode_seed_parser.add_argument(
        "--account",
        help="Account name to use (uses default if not specified)",
    )

    # Status seed phrase
    status_seed_parser = seed_subparsers.add_parser(
        "status", help="Check the status of the configured seed phrase"
    )
    status_seed_parser.add_argument(
        "--account",
        help="Account name to check (uses default if not specified)",
    )


def add_account_commands(subparsers):
    """Add account management commands to the parser."""
    # Account command
    account_parser = subparsers.add_parser("account", help="Manage substrate accounts")
    account_subparsers = account_parser.add_subparsers(
        dest="account_action", help="Account action"
    )

    # List accounts
    account_subparsers.add_parser("list", help="List all accounts")

    # Create account
    create_account_parser = account_subparsers.add_parser(
        "create", help="Create a new account with a generated seed phrase"
    )
    create_account_parser.add_argument(
        "--name",
        required=True,
        help="Name for the new account",
    )
    create_account_parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the seed phrase with a password",
    )

    # Export account
    export_account_parser = account_subparsers.add_parser(
        "export", help="Export an account to a file"
    )
    export_account_parser.add_argument(
        "--name",
        help="Account name to export (uses active account if not specified)",
    )
    export_account_parser.add_argument(
        "--file",
        dest="file_path",
        help="File path to export to (default: <account_name>_hippius_account.json)",
    )

    # Import account
    import_account_parser = account_subparsers.add_parser(
        "import", help="Import an account from a file"
    )
    import_account_parser.add_argument(
        "--file",
        dest="file_path",
        required=True,
        help="File path to import from",
    )
    import_account_parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the seed phrase during import",
    )

    # Account info
    info_account_parser = account_subparsers.add_parser(
        "info", help="Display detailed information about an account"
    )
    info_account_parser.add_argument(
        "--name",
        help="Account name to show info for (uses active account if not specified)",
    )

    # Account login
    login_account_parser = account_subparsers.add_parser(
        "login", help="Login with an account address and seed phrase"
    )

    # Account balance
    balance_account_parser = account_subparsers.add_parser(
        "balance", help="Check account balance"
    )
    balance_account_parser.add_argument(
        "--name",
        help="Account name to check balance for (uses active account if not specified)",
    )
    balance_account_parser.add_argument(
        "--address",
        help="Substrate address to check balance for (overrides account name)",
    )

    # Switch account
    switch_account_parser = account_subparsers.add_parser(
        "switch", help="Switch to a different account"
    )
    switch_account_parser.add_argument(
        "account_name",
        help="Account name to switch to",
    )

    # Delete account
    delete_account_parser = account_subparsers.add_parser(
        "delete", help="Delete an account"
    )
    delete_account_parser.add_argument(
        "account_name",
        help="Account name to delete",
    )


def add_address_commands(subparsers):
    """Add address management commands to the parser."""
    # Address command
    address_parser = subparsers.add_parser(
        "address", help="Manage default address for read-only operations"
    )
    address_subparsers = address_parser.add_subparsers(
        dest="address_action", help="Address action"
    )

    # Set default address
    set_default_parser = address_subparsers.add_parser(
        "set-default", help="Set the default address for read-only operations"
    )
    set_default_parser.add_argument(
        "address",
        help="Substrate account address to use as default",
    )

    # Get default address
    address_subparsers.add_parser(
        "get-default", help="Show the current default address for read-only operations"
    )

    # Clear default address
    address_subparsers.add_parser(
        "clear-default", help="Clear the default address for read-only operations"
    )


def get_subparser(command: str) -> argparse.ArgumentParser:
    """Get a subparser for a specific command.

    Args:
        command: The command name to get the subparser for

    Returns:
        The subparser for the specified command
    """
    parser = create_parser()
    return parser._subparsers._group_actions[0].choices[command]


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = create_parser()
    args = parser.parse_args()
    return args
