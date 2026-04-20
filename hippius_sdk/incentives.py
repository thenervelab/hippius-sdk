#!/usr/bin/env python3
import argparse
import json
import os
import base64
import secrets
from typing import Optional, Tuple
from nacl.signing import SigningKey
from binascii import unhexlify, hexlify
from hashlib import blake2b
import base58

from substrateinterface import SubstrateInterface, Keypair
from scalecodec.utils.ss58 import ss58_decode


# ---------- Helpers ----------
def blake2_256(b: bytes) -> bytes:
    return blake2b(b, digest_size=32).digest()


def _read_varint(b: bytes, i: int) -> Tuple[int, int]:
    x, s = 0, 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        x |= (c & 0x7F) << s
        if not (c & 0x80):
            return x, i
        s += 7


def decode_libp2p_privkey_b64(privkey_b64: str) -> bytes:
    """Decode go-libp2p PrivateKey proto; return ed25519 32B seed."""
    raw = base64.b64decode(privkey_b64)
    i = 0
    key_type = None
    data = None
    while i < len(raw):
        key, i = _read_varint(raw, i)
        fld, wtype = key >> 3, key & 0x7
        if fld == 1:
            if wtype != 0:
                raise ValueError("bad wiretype for Type")
            key_type, i = _read_varint(raw, i)
        elif fld == 2:
            if wtype != 2:
                raise ValueError("bad wiretype for Data")
            ln, j = _read_varint(raw, i)
            data = raw[j : j + ln]
            i = j + ln
        else:
            if wtype == 0:
                _, i = _read_varint(raw, i)
            elif wtype == 2:
                ln, j = _read_varint(raw, i)
                i = j + ln
            else:
                raise ValueError("unsupported wiretype")
    if key_type != 1:  # 1 = Ed25519
        raise ValueError(f"Only Ed25519 supported (KeyType={key_type})")
    if data is None:
        raise ValueError("no Data")
    if len(data) == 64:
        return data[:32]
    if len(data) == 32:
        return data
    raise ValueError(f"unexpected ed25519 Data length {len(data)}")


def get_peer_id_from_public_key(public_key: bytes) -> str:
    """Convert a public key to a libp2p peer ID"""
    prefix = bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20])
    peer_id_bytes = prefix + public_key
    return base58.b58encode(peer_id_bytes).decode()


def get_public_key_from_peer_id(peer_id: str) -> bytes:
    """Extract public key from a libp2p peer ID"""
    peer_id_bytes = base58.b58decode(peer_id)

    if len(peer_id_bytes) != 38:
        raise ValueError(f"Invalid peer ID length: {len(peer_id_bytes)}")

    prefix = bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20])
    if peer_id_bytes[:6] != prefix:
        raise ValueError("Invalid peer ID prefix")

    return peer_id_bytes[6:38]


def load_ipfs_seed(
    ipfs_config: str = None, ipfs_priv_b64: str = None
) -> Tuple[bytes, str]:
    if ipfs_priv_b64:
        try:
            seed = decode_libp2p_privkey_b64(ipfs_priv_b64)
            return seed, ""
        except ValueError as e:
            raise SystemExit(f"Error decoding IPFS private key: {e}")

    if not ipfs_config:
        raise SystemExit(
            "Either --ipfs-config or --ipfs-priv-b64 is required for IPFS setup."
        )

    cfg_path = os.path.expanduser(ipfs_config)
    if not os.path.exists(cfg_path):
        raise SystemExit(f"IPFS config file not found at {cfg_path}")

    try:
        cfg = json.load(open(cfg_path))
    except json.JSONDecodeError:
        raise SystemExit(f"Invalid JSON in IPFS config file: {cfg_path}")

    ident = cfg.get("Identity") or {}
    if "PrivKey" not in ident:
        raise SystemExit("IPFS config missing Identity.PrivKey")

    seed = decode_libp2p_privkey_b64(ident["PrivKey"])
    return seed, ident.get("PeerID", "")


def load_main_seed(
    node_priv_hex: Optional[str] = None, node_priv_b64: Optional[str] = None
) -> bytes:
    """
    Load the main libp2p Ed25519 seed (32B).

    - If `node_priv_b64` is provided, it is treated as go-libp2p Identity.PrivKey
      base64 and decoded via `decode_libp2p_privkey_b64`.
    - Otherwise `node_priv_hex` is interpreted as a 32B seed hex (or 64B where the
      first 32B are used as seed).
    """
    if node_priv_b64:
        try:
            return decode_libp2p_privkey_b64(node_priv_b64)
        except ValueError as e:
            raise SystemExit(f"Error decoding libp2p privkey b64: {e}")

    if not node_priv_hex:
        raise SystemExit("Provide node_priv_hex or node_priv_b64")

    h = node_priv_hex.removeprefix("0x")
    try:
        b = unhexlify(h)
    except Exception:
        raise SystemExit("Invalid hex for node_priv_hex")
    if len(b) == 32:
        return b
    if len(b) == 64:
        return b[:32]
    raise SystemExit("node_priv_hex must be 32 or 64 bytes")


def encode_account_id(ss58_address: str) -> bytes:
    """Convert SS58 address to 32-byte public key (AccountId)"""
    decoded = ss58_decode(ss58_address)
    if isinstance(decoded, str):
        decoded = bytes.fromhex(decoded)
    elif isinstance(decoded, list):
        decoded = bytes(decoded)
    if len(decoded) != 32:
        raise ValueError(f"Decoded AccountId must be 32 bytes, got {len(decoded)}")
    return decoded


def verify_peer_id(
    public_key: bytes, peer_id_bytes: bytes, key_type: str = "Ed25519"
) -> bool:
    """
    Verify that a public key corresponds to a libp2p peer ID.

    Backwards-compatible signature: older callers pass `(public_key, peer_id, key_type)`.
    Newer callers can pass just `(public_key, peer_id_bytes)`.
    """
    if key_type != "Ed25519":
        return False

    # pallet expects: [0x00,0x24,0x08,0x01,0x12,0x20] + 32B pubkey
    if len(peer_id_bytes) != 38:
        return False

    expected_prefix = bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20])
    return peer_id_bytes[:6] == expected_prefix and peer_id_bytes[6:38] == public_key


def manual_encode_challenge(challenge_data, block_width):
    """Manually encode the challenge data using basic Scale encoding"""
    encoded = b""

    encoded += challenge_data["domain"]
    encoded += challenge_data["genesis_hash"]
    encoded += challenge_data["account"]
    encoded += challenge_data["node_id_hash"]
    encoded += challenge_data["ipfs_peer_id_hash"]

    if block_width == "u32":
        encoded += challenge_data["block_number"].to_bytes(4, "little")
    else:
        encoded += challenge_data["block_number"].to_bytes(8, "little")

    encoded += challenge_data["nonce"]

    if block_width == "u32":
        encoded += challenge_data["expires_at"].to_bytes(4, "little")
    else:
        encoded += challenge_data["expires_at"].to_bytes(8, "little")

    return encoded


# ---------- CLI ----------


def main():
    ap = argparse.ArgumentParser(description="Hippius register node (no IPFS)")
    ap.add_argument(
        "--ws", required=True, help="Substrate WS endpoint (e.g. ws://127.0.0.1:9944)"
    )
    ap.add_argument("--module", default="Registration", help="Pallet name in metadata")
    ap.add_argument(
        "--function",
        default="register_node_with_coldkey",
        choices=[
            "register_node_with_coldkey",
            "register_node_with_hotkey",
        ],
        help="Call function",
    )

    ap.add_argument(
        "--owner-uri", required=True, help="Owner secret URI //path or mnemonic"
    )
    ap.add_argument("--owner-ss58", required=True, help="Owner SS58 address")
    ap.add_argument("--owner-crypto", choices=["sr25519", "ed25519"], default="sr25519")

    ap.add_argument("--node-id", required=True, help="Your main node_id (hex or utf8)")
    node_priv_group = ap.add_mutually_exclusive_group(required=True)
    node_priv_group.add_argument(
        "--node-priv-hex",
        help="Main libp2p ed25519 private key hex (32/64B)",
    )
    node_priv_group.add_argument(
        "--node-priv-b64",
        help="Main libp2p Identity.PrivKey base64 (go-libp2p proto)",
    )
    ap.add_argument("--expires-in", type=int, default=10)
    ap.add_argument("--block-width", choices=["u32", "u64"], default="u64")
    ap.add_argument("--domain", default="HIPPIUS::REGISTER::v1")
    ap.add_argument("--nonce-hex", help="32-byte hex (optional)")
    ap.add_argument(
        "--node-type",
        choices=["StorageMiner", "Validator", "ComputeMiner", "StorageS3", "GpuMiner"],
        help="Required for registration functions",
    )
    ap.add_argument(
        "--pay-in-credits", action="store_true", help="Pay in credits for registration"
    )

    ap.add_argument(
        "--coldkey",
        help="Coldkey SS58 address (required for register_node_with_hotkey)",
    )

    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not submit extrinsic; just print payload",
    )
    args = ap.parse_args()

    # Validate function-specific requirements
    if args.function == "register_node_with_hotkey" and not args.coldkey:
        raise SystemExit("--coldkey is required for register_node_with_hotkey function")
    if (
        args.function in ["register_node_with_coldkey", "register_node_with_hotkey"]
        and not args.node_type
    ):
        raise SystemExit("--node-type is required for registration functions")

    # Initialize SubstrateInterface
    substrate = SubstrateInterface(url=args.ws)

    # Connect & fetch genesis hash
    genesis_hash_hex = substrate.get_block_hash(0)
    genesis_hash = bytes.fromhex(genesis_hash_hex[2:])

    # Get current block number from chain
    try:
        current_block_number = substrate.get_block_number(None)
        print(f"Current block number: {current_block_number}")
    except Exception as e:
        raise SystemExit(f"Error fetching current block number: {e}")

    # Ensure node_id_bytes is correctly formed
    if args.node_id.startswith("0x"):
        node_id_bytes = bytes.fromhex(args.node_id[2:])
    else:
        node_id_bytes = base58.b58decode(args.node_id)

    main_seed = load_main_seed(
        node_priv_hex=args.node_priv_hex, node_priv_b64=args.node_priv_b64
    )

    # Keys & pubkeys
    main_sk = SigningKey(main_seed)
    main_pk = bytes(main_sk.verify_key)

    # DEBUG: Print what we're working with
    print(f"Main public key: 0x{main_pk.hex()}")

    expected_main_peer_id = get_peer_id_from_public_key(main_pk)
    print(f"Expected main node ID from private key: {expected_main_peer_id}")
    print(f"Provided main node ID: {args.node_id}")

    try:
        expected_main_pk = get_public_key_from_peer_id(args.node_id)
        print(f"Expected main public key from node ID: 0x{expected_main_pk.hex()}")
    except Exception as e:
        print(f"Error extracting public key from main node ID: {e}")

    if not verify_peer_id(main_pk, node_id_bytes):
        raise SystemExit("Main public key does not match node ID")

    # Challenge bytes
    domain = args.domain.encode()
    domain24 = b"HIPPIUS::REGISTER::v1" + b"\x00" * 3

    node_id_hash = blake2_256(node_id_bytes)
    # ipfs_peer_id_hash is still part of the struct; set to hash(empty)
    ipfs_peer_id_hash = blake2_256(b"")

    nonce = (
        bytes.fromhex(args.nonce_hex[2:])
        if args.nonce_hex and args.nonce_hex.startswith("0x")
        else (
            bytes.fromhex(args.nonce_hex) if args.nonce_hex else secrets.token_bytes(32)
        )
    )

    expires_at_block = current_block_number + args.expires_in

    account_bytes = encode_account_id(args.owner_ss58)

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

    try:
        challenge_bytes = manual_encode_challenge(challenge_data, args.block_width)
        print(f"Successfully encoded challenge bytes: 0x{challenge_bytes.hex()}")
    except Exception as e:
        print(f"Error encoding challenge bytes: {e}")
        raise

    main_sig = main_sk.sign(challenge_bytes).signature
    node_id_hex = "0x" + hexlify(node_id_bytes).decode()

    # Compose call params based on function
    if args.function == "register_node_with_coldkey":
        call_params = {
            "node_type": args.node_type,
            "node_id": node_id_hex,
            "node_id_hex": node_id_hex,
            "pay_in_credits": bool(args.pay_in_credits),
            "owner": args.owner_ss58,
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }
    elif args.function == "register_node_with_hotkey":
        call_params = {
            "coldkey": args.coldkey,
            "node_type": args.node_type,
            "node_id": node_id_hex,
            "node_id_hex": node_id_hex,
            "pay_in_credits": bool(args.pay_in_credits),
            "owner": args.owner_ss58,
            "main_key_type": "Ed25519",
            "main_public_key": "0x" + main_pk.hex(),
            "main_sig": "0x" + main_sig.hex(),
            "challenge_bytes": "0x" + challenge_bytes.hex(),
        }
    else:
        raise SystemExit(f"Unsupported function: {args.function}")

    if args.dry_run:
        print(
            json.dumps(
                {
                    "genesis_hash_hex": "0x" + genesis_hash.hex(),
                    "current_block_number": current_block_number,
                    "challenge_bytes_hex": "0x" + challenge_bytes.hex(),
                    "call_module": args.module,
                    "call_function": args.function,
                    "call_params": call_params,
                },
                indent=2,
            )
        )
        return

    try:
        from substrateinterface import KeypairType

        crypto_arg = (
            KeypairType.SR25519
            if args.owner_crypto == "sr25519"
            else KeypairType.ED25519
        )
        kp = Keypair.create_from_uri(args.owner_uri, crypto_type=crypto_arg)
    except Exception as e:
        print(
            f"Error creating keypair with specified type: {e}. Falling back to default sr25519."
        )
        kp = Keypair.create_from_uri(args.owner_uri)

    call = substrate.compose_call(
        call_module=args.module, call_function=args.function, call_params=call_params
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    print(
        json.dumps(
            {
                "extrinsic_hash": receipt.extrinsic_hash,
                "is_success": receipt.is_success,
                "error_message": receipt.error_message,
                "triggered_events": [str(event) for event in receipt.triggered_events],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
