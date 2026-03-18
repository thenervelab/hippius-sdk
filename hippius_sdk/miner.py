"""
Miner registration and verification for the Hippius SDK.

Provides programmatic access to node registration and verification
on the Hippius Substrate blockchain.
"""

import json
import secrets
from binascii import hexlify
from typing import Optional

import base58
from nacl.signing import SigningKey
from substrateinterface import Keypair, SubstrateInterface

from hippius_sdk.incentives import (
    blake2_256,
    encode_account_id,
    load_ipfs_seed,
    load_main_seed,
    manual_encode_challenge,
    verify_peer_id,
)

KEY_TYPE = "Ed25519"


def build_challenge_and_sign(
    substrate: SubstrateInterface,
    account_address: str,
    node_id: str,
    node_priv_hex: str,
    ipfs_config: Optional[str] = None,
    ipfs_priv_b64: Optional[str] = None,
    ipfs_peer_id: Optional[str] = None,
    expires_in: int = 10,
    block_width: str = "u32",
    nonce_hex: Optional[str] = None,
) -> dict:
    """
    Build a registration/verification challenge and sign it.

    Returns a dict with all computed values needed for extrinsic submission.

    Raises:
        ValueError: If keys don't match node IDs
    """
    # Get genesis hash and current block
    genesis_hash_hex = substrate.get_block_hash(0)
    genesis_hash = bytes.fromhex(genesis_hash_hex[2:])
    current_block_number = substrate.get_block_number(None)

    # Process node_id
    if node_id.startswith("0x"):
        node_id_bytes = bytes.fromhex(node_id[2:])
    else:
        node_id_bytes = base58.b58decode(node_id)

    # Load seeds and create signing keys
    ipfs_seed, peerid_from_config = load_ipfs_seed(ipfs_config, ipfs_priv_b64)
    main_seed = load_main_seed(node_priv_hex)

    main_sk = SigningKey(main_seed)
    main_pk = bytes(main_sk.verify_key)
    ipfs_sk = SigningKey(ipfs_seed)
    ipfs_pk = bytes(ipfs_sk.verify_key)

    # Resolve IPFS peer ID bytes
    if ipfs_peer_id:
        ipfs_peer_id_bytes = base58.b58decode(ipfs_peer_id)
    elif peerid_from_config:
        ipfs_peer_id_bytes = base58.b58decode(peerid_from_config)
    else:
        ipfs_peer_id_bytes = b""

    # Verify keys match node IDs
    if not verify_peer_id(main_pk, node_id_bytes, KEY_TYPE):
        raise ValueError("Main public key does not match node ID")

    if ipfs_peer_id_bytes and not verify_peer_id(ipfs_pk, ipfs_peer_id_bytes, KEY_TYPE):
        raise ValueError("IPFS public key does not match peer ID")

    # Create challenge data
    domain24 = b"HIPPIUS::REGISTER::v1" + b"\x00" * 3
    node_id_hash = blake2_256(node_id_bytes)
    ipfs_peer_id_hash = blake2_256(ipfs_peer_id_bytes)

    nonce = (
        bytes.fromhex(nonce_hex[2:])
        if nonce_hex and nonce_hex.startswith("0x")
        else bytes.fromhex(nonce_hex)
        if nonce_hex
        else secrets.token_bytes(32)
    )

    expires_at_block = current_block_number + expires_in
    account_bytes = encode_account_id(account_address)

    challenge_data = {
        "domain": domain24,
        "genesis_hash": genesis_hash,
        "account": account_bytes,
        "node_id_hash": node_id_hash,
        "ipfs_peer_id_hash": ipfs_peer_id_hash,
        "block_number": current_block_number,
        "nonce": nonce,
        "expires_at": expires_at_block,
    }

    challenge_bytes = manual_encode_challenge(challenge_data, block_width)

    # Sign challenge
    main_sig = main_sk.sign(challenge_bytes).signature
    ipfs_sig = ipfs_sk.sign(challenge_bytes).signature

    return {
        "genesis_hash": genesis_hash,
        "current_block_number": current_block_number,
        "challenge_bytes": challenge_bytes,
        "node_id_bytes": node_id_bytes,
        "ipfs_peer_id_bytes": ipfs_peer_id_bytes,
        "main_pk": main_pk,
        "main_sig": main_sig,
        "ipfs_pk": ipfs_pk,
        "ipfs_sig": ipfs_sig,
    }


def build_register_coldkey_params(
    challenge: dict,
    node_id: str,
    node_type: str,
    account_address: str,
    ipfs_peer_id: Optional[str] = None,
    pay_in_credits: bool = False,
) -> dict:
    """Build call_params for register_node_with_coldkey."""
    return {
        "node_type": node_type,
        "node_id": node_id,
        "node_id_hex": "0x" + hexlify(challenge["node_id_bytes"]).decode(),
        "pay_in_credits": pay_in_credits,
        "ipfs_node_id": ipfs_peer_id,
        "owner": account_address,
        "ipfs_peer_id": ipfs_peer_id,
        "ipfs_id_hex": "0x" + hexlify(challenge["ipfs_peer_id_bytes"]).decode(),
        "main_key_type": KEY_TYPE,
        "main_public_key": "0x" + challenge["main_pk"].hex(),
        "main_sig": "0x" + challenge["main_sig"].hex(),
        "ipfs_key_type": KEY_TYPE,
        "ipfs_public_key": "0x" + challenge["ipfs_pk"].hex(),
        "ipfs_sig": "0x" + challenge["ipfs_sig"].hex(),
        "challenge_bytes": "0x" + challenge["challenge_bytes"].hex(),
    }


def build_register_hotkey_params(
    challenge: dict,
    node_id: str,
    node_type: str,
    account_address: str,
    coldkey: str,
    ipfs_peer_id: Optional[str] = None,
    pay_in_credits: bool = False,
) -> dict:
    """Build call_params for register_node_with_hotkey."""
    return {
        "coldkey": coldkey,
        "node_type": node_type,
        "node_id": node_id,
        "node_id_hex": "0x" + hexlify(challenge["node_id_bytes"]).decode(),
        "pay_in_credits": pay_in_credits,
        "ipfs_node_id": ipfs_peer_id,
        "ipfs_peer_id": ipfs_peer_id,
        "ipfs_id_hex": "0x" + hexlify(challenge["ipfs_peer_id_bytes"]).decode(),
        "owner": account_address,
        "main_key_type": KEY_TYPE,
        "main_public_key": "0x" + challenge["main_pk"].hex(),
        "main_sig": "0x" + challenge["main_sig"].hex(),
        "ipfs_key_type": KEY_TYPE,
        "ipfs_public_key": "0x" + challenge["ipfs_pk"].hex(),
        "ipfs_sig": "0x" + challenge["ipfs_sig"].hex(),
        "challenge_bytes": "0x" + challenge["challenge_bytes"].hex(),
    }


def build_verify_params(challenge: dict, node_id: str) -> dict:
    """Build call_params for verify_existing_node / verify_existing_coldkey_node."""
    return {
        "node_id": node_id,
        "node_id_hex": "0x" + hexlify(challenge["node_id_bytes"]).decode(),
        "ipfs_id_hex": "0x" + hexlify(challenge["ipfs_peer_id_bytes"]).decode(),
        "main_key_type": KEY_TYPE,
        "main_public_key": "0x" + challenge["main_pk"].hex(),
        "main_sig": "0x" + challenge["main_sig"].hex(),
        "ipfs_key_type": KEY_TYPE,
        "ipfs_public_key": "0x" + challenge["ipfs_pk"].hex(),
        "ipfs_sig": "0x" + challenge["ipfs_sig"].hex(),
        "challenge_bytes": "0x" + challenge["challenge_bytes"].hex(),
    }


def submit_extrinsic(
    substrate: SubstrateInterface,
    call_function: str,
    call_params: dict,
    seed_phrase: str,
    call_module: str = "Registration",
) -> dict:
    """
    Compose, sign, and submit a Substrate extrinsic.

    Returns dict with extrinsic_hash, is_success, error_message, triggered_events.
    """
    kp = Keypair.create_from_mnemonic(seed_phrase)
    call = substrate.compose_call(
        call_module=call_module,
        call_function=call_function,
        call_params=call_params,
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    return {
        "extrinsic_hash": receipt.extrinsic_hash,
        "is_success": receipt.is_success,
        "error_message": receipt.error_message,
        "triggered_events": [str(event) for event in receipt.triggered_events],
    }


def format_dry_run_payload(
    challenge: dict, call_function: str, call_params: dict
) -> str:
    """Format a dry-run payload as JSON."""
    return json.dumps(
        {
            "genesis_hash_hex": "0x" + challenge["genesis_hash"].hex(),
            "current_block_number": challenge["current_block_number"],
            "challenge_bytes_hex": "0x" + challenge["challenge_bytes"].hex(),
            "call_module": "Registration",
            "call_function": call_function,
            "call_params": call_params,
        },
        indent=2,
    )
