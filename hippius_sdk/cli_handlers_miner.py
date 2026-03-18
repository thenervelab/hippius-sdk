"""CLI handlers for miner registration and verification."""

import json
from typing import Optional

import click
from substrateinterface import SubstrateInterface

from hippius_sdk import (
    ArionClient,
    get_account_address,
    get_active_account,
    get_config_value,
    get_seed_phrase,
)
from hippius_sdk.miner import (
    build_challenge_and_sign,
    build_register_coldkey_params,
    build_register_hotkey_params,
    build_verify_params,
    format_dry_run_payload,
    submit_extrinsic,
)
from hippius_sdk.cli_ui import (
    error,
    info,
    log,
    success,
)


def _get_account_context():
    """Get current account name and address, or return (None, None) on error."""
    account = get_active_account()
    if not account:
        error(
            "No active account. Please set up an account first with 'hippius account login'"
        )
        return None, None

    account_address = get_account_address(account)
    if not account_address:
        error(f"Could not get address for account '{account}'")
        return None, None

    return account, account_address


def _run_miner_command(
    call_function: str,
    node_id: str,
    node_priv_hex: str,
    node_type: Optional[str] = None,
    coldkey: Optional[str] = None,
    ipfs_config: Optional[str] = None,
    ipfs_priv_b64: Optional[str] = None,
    ipfs_peer_id: Optional[str] = None,
    pay_in_credits: bool = False,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    """Shared implementation for all miner registration/verification commands."""
    account, account_address = _get_account_context()
    if not account:
        return 1

    # Require IPFS peer ID for certain node types during registration
    if call_function in ["register_node_with_coldkey", "register_node_with_hotkey"]:
        if (
            node_type in ["StorageMiner", "Validator"]
            and not ipfs_peer_id
            and not ipfs_config
        ):
            error("IPFS PeerID is required for StorageMiner and Validator node types")
            return 1

    info(
        f"Running {call_function} using account: [bold cyan]{account}[/bold cyan] ({account_address})"
    )
    if coldkey:
        info(f"Coldkey: [bold yellow]{coldkey}[/bold yellow]")

    # Initialize SubstrateInterface
    substrate = SubstrateInterface(url=get_config_value("substrate", "url"))

    # Build challenge and sign
    challenge = build_challenge_and_sign(
        substrate=substrate,
        account_address=account_address,
        node_id=node_id,
        node_priv_hex=node_priv_hex,
        ipfs_config=ipfs_config,
        ipfs_priv_b64=ipfs_priv_b64,
        ipfs_peer_id=ipfs_peer_id,
        expires_in=expires_in,
        block_width=block_width,
        nonce_hex=nonce_hex,
    )

    log(f"Current block number: {challenge['current_block_number']}")

    # Build call parameters based on function type
    if call_function == "register_node_with_coldkey":
        call_params = build_register_coldkey_params(
            challenge,
            node_id,
            node_type,
            account_address,
            ipfs_peer_id=ipfs_peer_id,
            pay_in_credits=pay_in_credits,
        )
    elif call_function == "register_node_with_hotkey":
        call_params = build_register_hotkey_params(
            challenge,
            node_id,
            node_type,
            account_address,
            coldkey,
            ipfs_peer_id=ipfs_peer_id,
            pay_in_credits=pay_in_credits,
        )
    else:
        call_params = build_verify_params(challenge, node_id)

    if dry_run:
        log("Dry run mode - printing payload without submitting")
        click.echo(format_dry_run_payload(challenge, call_function, call_params))
        return 0

    seed_phrase = get_seed_phrase()
    if not seed_phrase:
        error("No seed phrase available for signing transaction")
        return 1

    # Submit transaction
    log("Submitting transaction...")
    log("Using module: [bold cyan]Registration[/bold cyan]")

    result = submit_extrinsic(substrate, call_function, call_params, seed_phrase)

    if result["is_success"]:
        success(f"Transaction successful! Hash: {result['extrinsic_hash']}")
    else:
        error(f"Transaction failed: {result['error_message']}")

    log("Full result:")
    click.echo(json.dumps(result, indent=2))

    return 0 if result["is_success"] else 1


def handle_register_coldkey(
    client: ArionClient,
    node_id: str,
    node_priv_hex: str,
    node_type: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    pay_in_credits: bool = False,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner register-coldkey command"""
    return _run_miner_command(
        "register_node_with_coldkey",
        node_id,
        node_priv_hex,
        node_type=node_type,
        ipfs_config=ipfs_config,
        ipfs_priv_b64=ipfs_priv_b64,
        ipfs_peer_id=ipfs_peer_id,
        pay_in_credits=pay_in_credits,
        expires_in=expires_in,
        block_width=block_width,
        nonce_hex=nonce_hex,
        dry_run=dry_run,
    )


def handle_register_hotkey(
    client: ArionClient,
    coldkey: str,
    node_id: str,
    node_priv_hex: str,
    node_type: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    pay_in_credits: bool = False,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner register-hotkey command"""
    return _run_miner_command(
        "register_node_with_hotkey",
        node_id,
        node_priv_hex,
        node_type=node_type,
        coldkey=coldkey,
        ipfs_config=ipfs_config,
        ipfs_priv_b64=ipfs_priv_b64,
        ipfs_peer_id=ipfs_peer_id,
        pay_in_credits=pay_in_credits,
        expires_in=expires_in,
        block_width=block_width,
        nonce_hex=nonce_hex,
        dry_run=dry_run,
    )


def handle_verify_node(
    client: ArionClient,
    node_id: str,
    node_priv_hex: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner verify-node command"""
    return _run_miner_command(
        "verify_existing_node",
        node_id,
        node_priv_hex,
        ipfs_config=ipfs_config,
        ipfs_priv_b64=ipfs_priv_b64,
        ipfs_peer_id=ipfs_peer_id,
        expires_in=expires_in,
        block_width=block_width,
        nonce_hex=nonce_hex,
        dry_run=dry_run,
    )


def handle_verify_coldkey_node(
    client: ArionClient,
    node_id: str,
    node_priv_hex: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner verify-coldkey-node command"""
    return _run_miner_command(
        "verify_existing_coldkey_node",
        node_id,
        node_priv_hex,
        ipfs_config=ipfs_config,
        ipfs_priv_b64=ipfs_priv_b64,
        ipfs_peer_id=ipfs_peer_id,
        expires_in=expires_in,
        block_width=block_width,
        nonce_hex=nonce_hex,
        dry_run=dry_run,
    )
