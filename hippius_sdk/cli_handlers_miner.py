"""CLI handlers for miner registration and verification."""

import json

import click
from substrateinterface import Keypair, SubstrateInterface

from hippius_sdk import (
    ArionClient,
    get_account_address,
    get_active_account,
    get_config_value,
    get_seed_phrase,
)
from hippius_sdk.cli_ui import (
    error,
    info,
    log,
    success,
)


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
    domain: str = "HIPPIUS::REGISTER::v1",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner register-coldkey command"""
    try:
        # Get current account info
        account = get_active_account()
        if not account:
            error(
                "No active account. Please set up an account first with 'hippius account login'"
            )
            return 1

        account_address = get_account_address(account)
        if not account_address:
            error(f"Could not get address for account '{account}'")
            return 1

        info(
            f"Registering node with coldkey using account: [bold cyan]{account}[/bold cyan] ({account_address})"
        )

        # Import and use incentives.py functionality
        from hippius_sdk.incentives import (
            load_ipfs_seed,
            load_main_seed,
            encode_account_id,
            verify_peer_id,
            blake2_256,
            manual_encode_challenge,
        )
        from nacl.signing import SigningKey
        import base58
        import secrets
        from binascii import hexlify

        # Initialize SubstrateInterface
        substrate = SubstrateInterface(url=get_config_value("substrate", "url"))

        # Get genesis hash and current block
        genesis_hash_hex = substrate.get_block_hash(0)
        genesis_hash = bytes.fromhex(genesis_hash_hex[2:])
        current_block_number = substrate.get_block_number(None)

        log(f"Current block number: {current_block_number}")

        # Process node_id
        if node_id.startswith("0x"):
            node_id_bytes = bytes.fromhex(node_id[2:])
        else:
            node_id_bytes = base58.b58decode(node_id)

        # Load IPFS and main seeds
        ipfs_seed, peerid_from_config = load_ipfs_seed(ipfs_config, ipfs_priv_b64)
        main_seed = load_main_seed(node_priv_hex)

        # Create signing keys
        main_sk = SigningKey(main_seed)
        main_pk = bytes(main_sk.verify_key)
        ipfs_sk = SigningKey(ipfs_seed)
        ipfs_pk = bytes(ipfs_sk.verify_key)

        # Handle IPFS peer ID
        if ipfs_peer_id:
            ipfs_peer_id_bytes = base58.b58decode(ipfs_peer_id)
        elif peerid_from_config:
            ipfs_peer_id_bytes = base58.b58decode(peerid_from_config)
        else:
            if node_type in ["StorageMiner", "Validator"]:
                error(
                    "IPFS PeerID is required for StorageMiner and Validator node types"
                )
                return 1
            ipfs_peer_id_bytes = b""

        # Verify keys match node IDs
        if not verify_peer_id(main_pk, node_id_bytes, "Ed25519"):
            error("Main public key does not match node ID")
            return 1

        if ipfs_peer_id_bytes and not verify_peer_id(
            ipfs_pk, ipfs_peer_id_bytes, "Ed25519"
        ):
            error("IPFS public key does not match peer ID")
            return 1

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

        # Build call parameters
        call_params = {
            "node_type": node_type,
            "node_id": node_id,
            "node_id_hex": "0x" + hexlify(node_id_bytes).decode(),
            "pay_in_credits": pay_in_credits,
            "ipfs_node_id": ipfs_peer_id,
            "owner": account_address,
            "ipfs_peer_id": ipfs_peer_id,
            "ipfs_id_hex": "0x" + hexlify(ipfs_peer_id_bytes).decode(),
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "ipfs_key_type": "Ed25519",
            "ipfs_public_key": "0x" + ipfs_pk.hex(),
            "ipfs_sig": "0x" + ipfs_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }

        if dry_run:
            log("Dry run mode - printing payload without submitting")
            payload = {
                "genesis_hash_hex": "0x" + genesis_hash.hex(),
                "current_block_number": current_block_number,
                "challenge_bytes_hex": "0x" + challenge_bytes.hex(),
                "call_module": "Registration",
                "call_function": "register_node_with_coldkey",
                "call_params": call_params,
            }
            click.echo(json.dumps(payload, indent=2))
            return 0

        seed_phrase = get_seed_phrase()
        if not seed_phrase:
            error("No seed phrase available for signing transaction")
            return 1

        # Create keypair from seed phrase
        kp = Keypair.create_from_mnemonic(seed_phrase)

        # Submit transaction
        log("Submitting registration transaction...")
        log("Using module: [bold cyan]Registration[/bold cyan]")
        call = substrate.compose_call(
            call_module="Registration",
            call_function="register_node_with_coldkey",
            call_params=call_params,
        )
        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        result = {
            "extrinsic_hash": receipt.extrinsic_hash,
            "is_success": receipt.is_success,
            "error_message": receipt.error_message,
            "triggered_events": [str(event) for event in receipt.triggered_events],
        }

        if receipt.is_success:
            success("Node registered successfully with coldkey!")
            success(f"Transaction hash: {receipt.extrinsic_hash}")
        else:
            error(f"Registration failed: {receipt.error_message}")

        log("Full result:")
        click.echo(json.dumps(result, indent=2))

        return 0 if receipt.is_success else 1

    except Exception as e:
        error(f"Error registering node with coldkey: {e}")
        if hasattr(e, "__traceback__"):
            import traceback

            traceback.print_exc()
        return 1


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
    domain: str = "HIPPIUS::REGISTER::v1",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner register-hotkey command"""
    try:
        # Get current account info
        account = get_active_account()
        if not account:
            error(
                "No active account. Please set up an account first with 'hippius account login'"
            )
            return 1

        account_address = get_account_address(account)
        if not account_address:
            error(f"Could not get address for account '{account}'")
            return 1

        info(
            f"Registering node with hotkey using account: [bold cyan]{account}[/bold cyan] ({account_address})"
        )
        info(f"Coldkey: [bold yellow]{coldkey}[/bold yellow]")

        # Import and use incentives.py functionality
        from hippius_sdk.incentives import (
            load_ipfs_seed,
            load_main_seed,
            encode_account_id,
            verify_peer_id,
            blake2_256,
            manual_encode_challenge,
        )
        from nacl.signing import SigningKey
        import base58
        import secrets
        from binascii import hexlify

        # Initialize SubstrateInterface
        substrate = SubstrateInterface(url=get_config_value("substrate", "url"))

        # Get genesis hash and current block
        genesis_hash_hex = substrate.get_block_hash(0)
        genesis_hash = bytes.fromhex(genesis_hash_hex[2:])
        current_block_number = substrate.get_block_number(None)

        log(f"Current block number: {current_block_number}")

        # Process node_id
        if node_id.startswith("0x"):
            node_id_bytes = bytes.fromhex(node_id[2:])
        else:
            node_id_bytes = base58.b58decode(node_id)

        # Load IPFS and main seeds
        ipfs_seed, peerid_from_config = load_ipfs_seed(ipfs_config, ipfs_priv_b64)
        main_seed = load_main_seed(node_priv_hex)

        # Create signing keys
        main_sk = SigningKey(main_seed)
        main_pk = bytes(main_sk.verify_key)
        ipfs_sk = SigningKey(ipfs_seed)
        ipfs_pk = bytes(ipfs_sk.verify_key)

        # Handle IPFS peer ID
        if ipfs_peer_id:
            ipfs_peer_id_bytes = base58.b58decode(ipfs_peer_id)
        elif peerid_from_config:
            ipfs_peer_id_bytes = base58.b58decode(peerid_from_config)
        else:
            if node_type in ["StorageMiner", "Validator"]:
                error(
                    "IPFS PeerID is required for StorageMiner and Validator node types"
                )
                return 1
            ipfs_peer_id_bytes = b""

        # Verify keys match node IDs
        if not verify_peer_id(main_pk, node_id_bytes, "Ed25519"):
            error("Main public key does not match node ID")
            return 1

        if ipfs_peer_id_bytes and not verify_peer_id(
            ipfs_pk, ipfs_peer_id_bytes, "Ed25519"
        ):
            error("IPFS public key does not match peer ID")
            return 1

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

        # Build call parameters
        call_params = {
            "coldkey": coldkey,
            "node_type": node_type,
            "node_id": node_id,
            "node_id_hex": "0x" + hexlify(node_id_bytes).decode(),
            "pay_in_credits": pay_in_credits,
            "ipfs_node_id": ipfs_peer_id,
            "ipfs_peer_id": ipfs_peer_id,
            "ipfs_id_hex": "0x" + hexlify(ipfs_peer_id_bytes).decode(),
            "owner": account_address,
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "ipfs_key_type": "Ed25519",
            "ipfs_public_key": "0x" + ipfs_pk.hex(),
            "ipfs_sig": "0x" + ipfs_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }

        if dry_run:
            log("Dry run mode - printing payload without submitting")
            payload = {
                "genesis_hash_hex": "0x" + genesis_hash.hex(),
                "current_block_number": current_block_number,
                "challenge_bytes_hex": "0x" + challenge_bytes.hex(),
                "call_module": "Registration",
                "call_function": "register_node_with_hotkey",
                "call_params": call_params,
            }
            click.echo(json.dumps(payload, indent=2))
            return 0

        seed_phrase = get_seed_phrase()
        if not seed_phrase:
            error("No seed phrase available for signing transaction")
            return 1

        kp = Keypair.create_from_uri(seed_phrase)

        # Submit transaction
        log("Submitting registration transaction...")
        log("Using module: [bold cyan]Registration[/bold cyan]")
        call = substrate.compose_call(
            call_module="Registration",
            call_function="register_node_with_hotkey",
            call_params=call_params,
        )
        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        result = {
            "extrinsic_hash": receipt.extrinsic_hash,
            "is_success": receipt.is_success,
            "error_message": receipt.error_message,
            "triggered_events": [str(event) for event in receipt.triggered_events],
        }

        if receipt.is_success:
            success("Node registered successfully with hotkey!")
            success(f"Transaction hash: {receipt.extrinsic_hash}")
        else:
            error(f"Registration failed: {receipt.error_message}")

        log("Full result:")
        click.echo(json.dumps(result, indent=2))

        return 0 if receipt.is_success else 1

    except Exception as e:
        error(f"Error registering node with hotkey: {e}")
        if hasattr(e, "__traceback__"):
            import traceback

            traceback.print_exc()
        return 1


def handle_verify_node(
    client: ArionClient,
    node_id: str,
    node_priv_hex: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    expires_in: int = 10,
    block_width: str = "u32",
    domain: str = "HIPPIUS::REGISTER::v1",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner verify-node command"""
    try:
        # Get current account info
        account = get_active_account()
        if not account:
            error(
                "No active account. Please set up an account first with 'hippius account login'"
            )
            return 1

        account_address = get_account_address(account)
        if not account_address:
            error(f"Could not get address for account '{account}'")
            return 1

        info(
            f"Verifying existing node using account: [bold cyan]{account}[/bold cyan] ({account_address})"
        )

        # Import and use incentives.py functionality
        from hippius_sdk.incentives import (
            load_ipfs_seed,
            load_main_seed,
            encode_account_id,
            verify_peer_id,
            blake2_256,
            manual_encode_challenge,
        )
        from nacl.signing import SigningKey
        import base58
        import secrets
        from binascii import hexlify

        # Initialize SubstrateInterface
        substrate = SubstrateInterface(url=get_config_value("substrate", "url"))

        # Get genesis hash and current block
        genesis_hash_hex = substrate.get_block_hash(0)
        genesis_hash = bytes.fromhex(genesis_hash_hex[2:])
        current_block_number = substrate.get_block_number(None)

        log(f"Current block number: {current_block_number}")

        # Process node_id
        if node_id.startswith("0x"):
            node_id_bytes = bytes.fromhex(node_id[2:])
        else:
            node_id_bytes = base58.b58decode(node_id)

        # Load IPFS and main seeds
        ipfs_seed, peerid_from_config = load_ipfs_seed(ipfs_config, ipfs_priv_b64)
        main_seed = load_main_seed(node_priv_hex)

        # Create signing keys
        main_sk = SigningKey(main_seed)
        main_pk = bytes(main_sk.verify_key)
        ipfs_sk = SigningKey(ipfs_seed)
        ipfs_pk = bytes(ipfs_sk.verify_key)

        # Handle IPFS peer ID
        if ipfs_peer_id:
            ipfs_peer_id_bytes = base58.b58decode(ipfs_peer_id)
        elif peerid_from_config:
            ipfs_peer_id_bytes = base58.b58decode(peerid_from_config)
        else:
            # For verification, IPFS peer ID might not be required for all node types
            ipfs_peer_id_bytes = b""

        # Verify keys match node IDs
        if not verify_peer_id(main_pk, node_id_bytes, "Ed25519"):
            error("Main public key does not match node ID")
            return 1

        if ipfs_peer_id_bytes and not verify_peer_id(
            ipfs_pk, ipfs_peer_id_bytes, "Ed25519"
        ):
            error("IPFS public key does not match peer ID")
            return 1

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

        # Build call parameters for verify_existing_node
        call_params = {
            "node_id": node_id,
            "node_id_hex": "0x" + hexlify(node_id_bytes).decode(),
            "ipfs_id_hex": "0x" + hexlify(ipfs_peer_id_bytes).decode(),
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "ipfs_key_type": "Ed25519",
            "ipfs_public_key": "0x" + ipfs_pk.hex(),
            "ipfs_sig": "0x" + ipfs_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }

        if dry_run:
            log("Dry run mode - printing payload without submitting")
            payload = {
                "genesis_hash_hex": "0x" + genesis_hash.hex(),
                "current_block_number": current_block_number,
                "challenge_bytes_hex": "0x" + challenge_bytes.hex(),
                "call_module": "Registration",
                "call_function": "verify_existing_node",
                "call_params": call_params,
            }
            click.echo(json.dumps(payload, indent=2))
            return 0

        seed_phrase = get_seed_phrase()
        if not seed_phrase:
            error("No seed phrase available for signing transaction")
            return 1

        # Create keypair from seed phrase
        kp = Keypair.create_from_mnemonic(seed_phrase)

        # Submit transaction
        log("Submitting node verification transaction...")
        log("Using module: [bold cyan]Registration[/bold cyan]")
        call = substrate.compose_call(
            call_module="Registration",
            call_function="verify_existing_node",
            call_params=call_params,
        )
        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        result = {
            "extrinsic_hash": receipt.extrinsic_hash,
            "is_success": receipt.is_success,
            "error_message": receipt.error_message,
            "triggered_events": [str(event) for event in receipt.triggered_events],
        }

        if receipt.is_success:
            success("Node verification successful!")
            success(f"Transaction hash: {receipt.extrinsic_hash}")
        else:
            error(f"Node verification failed: {receipt.error_message}")

        log("Full result:")
        click.echo(json.dumps(result, indent=2))

        return 0 if receipt.is_success else 1

    except Exception as e:
        error(f"Error verifying node: {e}")
        if hasattr(e, "__traceback__"):
            import traceback

            traceback.print_exc()
        return 1


def handle_verify_coldkey_node(
    client: ArionClient,
    node_id: str,
    node_priv_hex: str,
    ipfs_config: str = None,
    ipfs_priv_b64: str = None,
    ipfs_peer_id: str = None,
    expires_in: int = 10,
    block_width: str = "u32",
    domain: str = "HIPPIUS::REGISTER::v1",
    nonce_hex: str = None,
    dry_run: bool = False,
) -> int:
    """Handle miner verify-coldkey-node command"""
    try:
        # Get current account info
        account = get_active_account()
        if not account:
            error(
                "No active account. Please set up an account first with 'hippius account login'"
            )
            return 1

        account_address = get_account_address(account)
        if not account_address:
            error(f"Could not get address for account '{account}'")
            return 1

        info(
            f"Verifying existing coldkey node using account: [bold cyan]{account}[/bold cyan] ({account_address})"
        )

        # Import and use incentives.py functionality
        from hippius_sdk.incentives import (
            load_ipfs_seed,
            load_main_seed,
            encode_account_id,
            verify_peer_id,
            blake2_256,
            manual_encode_challenge,
        )
        from nacl.signing import SigningKey
        import base58
        import secrets
        from binascii import hexlify

        # Initialize SubstrateInterface
        substrate = SubstrateInterface(url=get_config_value("substrate", "url"))

        # Get genesis hash and current block
        genesis_hash_hex = substrate.get_block_hash(0)
        genesis_hash = bytes.fromhex(genesis_hash_hex[2:])
        current_block_number = substrate.get_block_number(None)

        log(f"Current block number: {current_block_number}")

        # Process node_id
        if node_id.startswith("0x"):
            node_id_bytes = bytes.fromhex(node_id[2:])
        else:
            node_id_bytes = base58.b58decode(node_id)

        # Load IPFS and main seeds
        ipfs_seed, peerid_from_config = load_ipfs_seed(ipfs_config, ipfs_priv_b64)
        main_seed = load_main_seed(node_priv_hex)

        # Create signing keys
        main_sk = SigningKey(main_seed)
        main_pk = bytes(main_sk.verify_key)
        ipfs_sk = SigningKey(ipfs_seed)
        ipfs_pk = bytes(ipfs_sk.verify_key)

        # Handle IPFS peer ID
        if ipfs_peer_id:
            ipfs_peer_id_bytes = base58.b58decode(ipfs_peer_id)
        elif peerid_from_config:
            ipfs_peer_id_bytes = base58.b58decode(peerid_from_config)
        else:
            # For verification, IPFS peer ID might not be required for all node types
            ipfs_peer_id_bytes = b""

        # Verify keys match node IDs
        if not verify_peer_id(main_pk, node_id_bytes, "Ed25519"):
            error("Main public key does not match node ID")
            return 1

        if ipfs_peer_id_bytes and not verify_peer_id(
            ipfs_pk, ipfs_peer_id_bytes, "Ed25519"
        ):
            error("IPFS public key does not match peer ID")
            return 1

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

        # Build call parameters for verify_existing_coldkey_node
        call_params = {
            "node_id": node_id,
            "node_id_hex": "0x" + hexlify(node_id_bytes).decode(),
            "ipfs_id_hex": "0x" + hexlify(ipfs_peer_id_bytes).decode(),
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "ipfs_key_type": "Ed25519",
            "ipfs_public_key": "0x" + ipfs_pk.hex(),
            "ipfs_sig": "0x" + ipfs_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }

        if dry_run:
            log("Dry run mode - printing payload without submitting")
            payload = {
                "genesis_hash_hex": "0x" + genesis_hash.hex(),
                "current_block_number": current_block_number,
                "challenge_bytes_hex": "0x" + challenge_bytes.hex(),
                "call_module": "Registration",
                "call_function": "verify_existing_coldkey_node",
                "call_params": call_params,
            }
            click.echo(json.dumps(payload, indent=2))
            return 0

        seed_phrase = get_seed_phrase()
        if not seed_phrase:
            error("No seed phrase available for signing transaction")
            return 1

        kp = Keypair.create_from_uri(seed_phrase)

        # Submit transaction
        log("Submitting coldkey node verification transaction...")
        log("Using module: [bold cyan]Registration[/bold cyan]")
        call = substrate.compose_call(
            call_module="Registration",
            call_function="verify_existing_coldkey_node",
            call_params=call_params,
        )
        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        result = {
            "extrinsic_hash": receipt.extrinsic_hash,
            "is_success": receipt.is_success,
            "error_message": receipt.error_message,
            "triggered_events": [str(event) for event in receipt.triggered_events],
        }

        if receipt.is_success:
            success("Coldkey node verification successful!")
            success(f"Transaction hash: {receipt.extrinsic_hash}")
        else:
            error(f"Coldkey node verification failed: {receipt.error_message}")

        log("Full result:")
        click.echo(json.dumps(result, indent=2))

        return 0 if receipt.is_success else 1

    except Exception as e:
        error(f"Error verifying coldkey node: {e}")
        if hasattr(e, "__traceback__"):
            import traceback

            traceback.print_exc()
        return 1
