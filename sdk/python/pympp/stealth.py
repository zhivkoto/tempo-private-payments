"""Core stealth address cryptography for ERC-5564 scheme ID 1 (secp256k1).

Uses coincurve (libsecp256k1 wrapper) for constant-time EC operations.
"""

from __future__ import annotations

import os
import hmac
from dataclasses import dataclass
from typing import Optional

import coincurve
from Crypto.Hash import keccak as _keccak

# secp256k1 curve order
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _hex_to_bytes(hex_str: str) -> bytes:
    clean = hex_str[2:] if hex_str.startswith("0x") else hex_str
    return bytes.fromhex(clean)


def _bytes_to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def _pub_key_to_address(uncompressed_pub: bytes) -> str:
    """Derive checksummed Ethereum address from uncompressed public key (65 bytes)."""
    pub_no_prefix = uncompressed_pub[1:]
    h = _keccak256(pub_no_prefix)
    addr_bytes = h[12:]
    return _checksum_address("0x" + addr_bytes.hex())


def _checksum_address(address: str) -> str:
    """EIP-55 checksum encoding."""
    addr = address.lower().replace("0x", "")
    hash_hex = _keccak256(addr.encode("ascii")).hex()
    result = "0x"
    for i, c in enumerate(addr):
        if c in "0123456789":
            result += c
        elif int(hash_hex[i], 16) >= 8:
            result += c.upper()
        else:
            result += c.lower()
    return result


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison for addresses."""
    return hmac.compare_digest(a.lower(), b.lower())


def _generate_valid_private_key() -> bytes:
    """Generate a random 32-byte private key that is valid for secp256k1."""
    while True:
        key_bytes = os.urandom(32)
        k = _bytes_to_int(key_bytes)
        if 0 < k < _N:
            return key_bytes


def _scalar_mult(point_bytes: bytes, scalar_bytes: bytes) -> coincurve.PublicKey:
    """Multiply an EC point by a scalar using coincurve (constant-time)."""
    pub = coincurve.PublicKey(point_bytes)
    result = pub.multiply(scalar_bytes)
    return result


# ── Types ──────────────────────────────────────────────────────────────────────


@dataclass
class StealthKeyPair:
    private_key: str  # 0x-prefixed 32-byte hex
    public_key: str  # 0x-prefixed 33-byte compressed hex


@dataclass
class StealthKeys:
    spending: StealthKeyPair
    viewing: StealthKeyPair


@dataclass
class GenerateStealthAddressResult:
    stealth_address: str
    ephemeral_pub_key: str  # compressed 33-byte hex
    view_tag: int  # 0-255


@dataclass
class StealthPaymentInfo:
    stealth_address: str
    stealth_private_key: str  # shared secret scalar (needs k_spend added)
    ephemeral_pub_key: str


# ── Core Functions ─────────────────────────────────────────────────────────────


def generate_stealth_keys() -> tuple[StealthKeys, str]:
    """Generate stealth key pairs and 66-byte meta-address.

    Returns:
        Tuple of (StealthKeys, meta_address_hex).
    """
    spending_priv = _generate_valid_private_key()
    viewing_priv = _generate_valid_private_key()

    spending_pub = coincurve.PublicKey.from_secret(spending_priv).format(compressed=True)
    viewing_pub = coincurve.PublicKey.from_secret(viewing_priv).format(compressed=True)

    keys = StealthKeys(
        spending=StealthKeyPair(
            private_key=_bytes_to_hex(spending_priv),
            public_key=_bytes_to_hex(spending_pub),
        ),
        viewing=StealthKeyPair(
            private_key=_bytes_to_hex(viewing_priv),
            public_key=_bytes_to_hex(viewing_pub),
        ),
    )

    meta_bytes = spending_pub + viewing_pub  # 66 bytes
    meta_address = _bytes_to_hex(meta_bytes)

    return keys, meta_address


def parse_stealth_meta_address(meta_address: str) -> tuple[str, str]:
    """Parse a 66-byte stealth meta-address into spending and viewing public keys.

    Returns:
        Tuple of (spending_pub_key_hex, viewing_pub_key_hex).
    """
    b = _hex_to_bytes(meta_address)
    if len(b) != 66:
        raise ValueError(f"Invalid stealth meta-address length: {len(b)}, expected 66")

    spending_pub = _bytes_to_hex(b[:33])
    viewing_pub = _bytes_to_hex(b[33:66])
    return spending_pub, viewing_pub


def parse_stealth_meta_uri(uri: str) -> tuple[str, str]:
    """Parse 'st:eth:0x...' URI into (spending_pub_key, viewing_pub_key)."""
    if not uri.startswith("st:eth:0x"):
        raise ValueError(f"Invalid stealth meta URI: {uri}")
    hex_part = uri[7:]  # Remove "st:eth:"
    return parse_stealth_meta_address(hex_part)


def format_stealth_meta_uri(meta_address: str) -> str:
    """Format a meta-address as 'st:eth:0x...' URI."""
    return f"st:eth:{meta_address}"


def generate_stealth_address(
    spending_pub_key: str,
    viewing_pub_key: str,
) -> GenerateStealthAddressResult:
    """Derive a one-time stealth address from recipient's public keys.

    Called by the PAYER.

    Algorithm:
        1. Generate ephemeral key pair (r, R = r*G)
        2. S = r * K_view (shared secret)
        3. H = keccak256(compress(S))
        4. viewTag = H[0]
        5. s = H mod n
        6. K_stealth = K_spend + s*G
        7. stealthAddr = address(K_stealth)
    """
    # Generate ephemeral key pair
    ephemeral_priv_bytes = _generate_valid_private_key()
    ephemeral_pub = coincurve.PublicKey.from_secret(ephemeral_priv_bytes).format(compressed=True)

    # Parse viewing public key
    viewing_pub_bytes = _hex_to_bytes(viewing_pub_key)

    # Shared secret: S = r * K_view (ECDH)
    shared_pub = _scalar_mult(viewing_pub_bytes, ephemeral_priv_bytes)
    shared_compressed = shared_pub.format(compressed=True)

    # Hash the shared secret
    shared_hash = _keccak256(shared_compressed)

    # View tag = first byte
    view_tag = shared_hash[0]

    # s = hash as scalar mod n
    s = _bytes_to_int(shared_hash) % _N

    # Reject degenerate zero scalar
    if s == 0:
        raise ValueError("Degenerate shared secret scalar (zero after reduction)")

    # K_stealth = K_spend + s*G
    spending_pub_bytes = _hex_to_bytes(spending_pub_key)
    spending_pub = coincurve.PublicKey(spending_pub_bytes)
    s_times_g = coincurve.PublicKey.from_secret(_int_to_bytes32(s))
    stealth_pub = coincurve.PublicKey.combine_keys([spending_pub, s_times_g])

    # Address from uncompressed stealth public key
    stealth_pub_uncompressed = stealth_pub.format(compressed=False)
    stealth_address = _pub_key_to_address(stealth_pub_uncompressed)

    return GenerateStealthAddressResult(
        stealth_address=stealth_address,
        ephemeral_pub_key=_bytes_to_hex(ephemeral_pub),
        view_tag=view_tag,
    )


def check_stealth_announcement(
    announcement: dict,
    viewing_private_key: str,
    spending_pub_key: str,
) -> Optional[StealthPaymentInfo]:
    """Check if an announcement is addressed to us.

    Args:
        announcement: Dict with schemeId, stealthAddress, ephemeralPubKey, viewTag.
        viewing_private_key: Hex viewing private key.
        spending_pub_key: Hex compressed spending public key.

    Returns:
        StealthPaymentInfo if match, None otherwise.
    """
    if announcement["schemeId"] != 1:
        return None

    viewing_priv_bytes = _hex_to_bytes(viewing_private_key)
    viewing_scalar = _bytes_to_int(viewing_priv_bytes)

    # Validate viewing key scalar range
    if viewing_scalar == 0 or viewing_scalar >= _N:
        return None

    ephemeral_pub_bytes = _hex_to_bytes(announcement["ephemeralPubKey"])

    # S' = k_view * R (constant-time via coincurve/libsecp256k1)
    try:
        shared_pub = _scalar_mult(ephemeral_pub_bytes, viewing_priv_bytes)
    except Exception:
        return None
    shared_compressed = shared_pub.format(compressed=True)

    shared_hash = _keccak256(shared_compressed)

    # Fast filter: check view tag
    computed_view_tag = shared_hash[0]
    if computed_view_tag != announcement["viewTag"]:
        return None

    # s' = hash mod n
    s = _bytes_to_int(shared_hash) % _N

    # Reject degenerate zero scalar
    if s == 0:
        return None

    # K_stealth' = K_spend + s'*G
    spending_pub_bytes = _hex_to_bytes(spending_pub_key)
    spending_pub = coincurve.PublicKey(spending_pub_bytes)
    s_times_g = coincurve.PublicKey.from_secret(_int_to_bytes32(s))
    stealth_pub = coincurve.PublicKey.combine_keys([spending_pub, s_times_g])

    stealth_pub_uncompressed = stealth_pub.format(compressed=False)
    computed_address = _pub_key_to_address(stealth_pub_uncompressed)

    # Constant-time address comparison
    if not _constant_time_compare(computed_address, announcement["stealthAddress"]):
        return None

    s_hex = "0x" + format(s, "064x")

    return StealthPaymentInfo(
        stealth_address=computed_address,
        stealth_private_key=s_hex,
        ephemeral_pub_key=announcement["ephemeralPubKey"],
    )


def compute_stealth_private_key(
    spending_private_key: str,
    ephemeral_pub_key: str,
    viewing_private_key: str,
) -> str:
    """Compute full stealth private key for spending.

    k_stealth = k_spend + keccak256(k_view * R) mod n
    """
    viewing_priv_bytes = _hex_to_bytes(viewing_private_key)
    viewing_scalar = _bytes_to_int(viewing_priv_bytes)

    # Validate key scalar ranges
    if viewing_scalar == 0 or viewing_scalar >= _N:
        raise ValueError("Invalid viewing private key: out of scalar range")

    ephemeral_pub_bytes = _hex_to_bytes(ephemeral_pub_key)

    # S = k_view * R (constant-time)
    shared_pub = _scalar_mult(ephemeral_pub_bytes, viewing_priv_bytes)
    shared_compressed = shared_pub.format(compressed=True)

    # s = keccak256(S) mod n
    shared_hash = _keccak256(shared_compressed)
    s = _bytes_to_int(shared_hash) % _N

    if s == 0:
        raise ValueError("Degenerate shared secret scalar (zero after reduction)")

    # k_stealth = k_spend + s mod n
    spending_priv_bytes = _hex_to_bytes(spending_private_key)
    k_spend = _bytes_to_int(spending_priv_bytes)

    if k_spend == 0 or k_spend >= _N:
        raise ValueError("Invalid spending private key: out of scalar range")

    k_stealth = (k_spend + s) % _N

    return "0x" + format(k_stealth, "064x")
