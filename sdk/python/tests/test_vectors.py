"""Cross-SDK deterministic test vectors for the ERC-5564 stealth address scheme.

Uses known private keys and computes the ECDH math inline (bypassing
generate_stealth_address which randomises the ephemeral key).
"""

import json
import os

import coincurve
from Crypto.Hash import keccak as _keccak

from pympp.stealth import (
    check_stealth_announcement,
    compute_stealth_private_key,
    parse_stealth_meta_address,
    _checksum_address,
)

# secp256k1 curve order
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "test-vectors", "vectors.json"
)

with open(VECTORS_PATH) as f:
    VECTORS = json.load(f)

KEYS = VECTORS["keys"]
EXPECTED = VECTORS["expected"]


def _keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _hex_to_bytes(hex_str: str) -> bytes:
    clean = hex_str[2:] if hex_str.startswith("0x") else hex_str
    return bytes.fromhex(clean)


def _bytes_to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def _pub_key_to_address(uncompressed_pub: bytes) -> str:
    pub_no_prefix = uncompressed_pub[1:]
    h = _keccak256(pub_no_prefix)
    addr_bytes = h[12:]
    return "0x" + addr_bytes.hex()


class TestCrossSDKVectors:
    def test_parse_meta_address(self):
        spending_pub, viewing_pub = parse_stealth_meta_address(
            VECTORS["meta_address"]
        )
        assert spending_pub == KEYS["spending_public_key"]
        assert viewing_pub == KEYS["viewing_public_key"]

    def test_derive_stealth_address_deterministic(self):
        ephemeral_priv_bytes = _hex_to_bytes(KEYS["ephemeral_private_key"])
        viewing_pub_bytes = _hex_to_bytes(KEYS["viewing_public_key"])

        # S = r * K_view (ECDH)
        viewing_pub = coincurve.PublicKey(viewing_pub_bytes)
        shared_pub = viewing_pub.multiply(ephemeral_priv_bytes)
        shared_compressed = shared_pub.format(compressed=True)

        assert _bytes_to_hex(shared_compressed) == EXPECTED["shared_secret_point"]

        # H = keccak256(compress(S))
        shared_hash = _keccak256(shared_compressed)
        assert _bytes_to_hex(shared_hash) == EXPECTED["shared_secret_hash"]

        # View tag
        assert shared_hash[0] == EXPECTED["view_tag"]

        # s = H mod n
        s = int.from_bytes(shared_hash, "big") % _N
        assert "0x" + format(s, "064x") == EXPECTED["shared_secret_scalar"]

        # K_stealth = K_spend + s*G
        spending_pub_bytes = _hex_to_bytes(KEYS["spending_public_key"])
        spending_pub = coincurve.PublicKey(spending_pub_bytes)
        s_times_g = coincurve.PublicKey.from_secret(s.to_bytes(32, "big"))
        stealth_pub = coincurve.PublicKey.combine_keys([spending_pub, s_times_g])

        stealth_pub_uncompressed = stealth_pub.format(compressed=False)
        stealth_address = _pub_key_to_address(stealth_pub_uncompressed)

        assert stealth_address == EXPECTED["stealth_address"]

    def test_check_stealth_announcement(self):
        detected = check_stealth_announcement(
            {
                "schemeId": 1,
                "stealthAddress": _checksum_address(EXPECTED["stealth_address"]),
                "ephemeralPubKey": KEYS["ephemeral_public_key"],
                "viewTag": EXPECTED["view_tag"],
            },
            KEYS["viewing_private_key"],
            KEYS["spending_public_key"],
        )

        assert detected is not None
        assert detected.stealth_address.lower() == EXPECTED["stealth_address"].lower()
        assert detected.shared_secret_scalar == EXPECTED["shared_secret_scalar"]

    def test_compute_stealth_private_key(self):
        stealth_priv = compute_stealth_private_key(
            KEYS["spending_private_key"],
            KEYS["ephemeral_public_key"],
            KEYS["viewing_private_key"],
        )

        assert stealth_priv == EXPECTED["stealth_private_key"]

        # Verify: derive pub from stealth priv and check address
        priv_bytes = _hex_to_bytes(stealth_priv)
        pub = coincurve.PublicKey.from_secret(priv_bytes)
        pub_uncompressed = pub.format(compressed=False)
        derived_address = _pub_key_to_address(pub_uncompressed)

        assert derived_address == EXPECTED["stealth_address"]
