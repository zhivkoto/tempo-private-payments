"""Comprehensive tests for stealth address cryptography — mirrors TS test suite."""

import re

import pytest
from ecdsa import SECP256k1, SigningKey
from Crypto.Hash import keccak as _keccak

from pympp.stealth import (
    generate_stealth_keys,
    generate_stealth_address,
    check_stealth_announcement,
    compute_stealth_private_key,
    parse_stealth_meta_uri,
    parse_stealth_meta_address,
    format_stealth_meta_uri,
    _checksum_address,
)


def _keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


COMPRESSED_PUB_RE = re.compile(r"^0x(02|03)[0-9a-f]{64}$", re.I)
HEX_32B_RE = re.compile(r"^0x[0-9a-f]{64}$", re.I)
META_ADDR_RE = re.compile(r"^0x[0-9a-f]{132}$", re.I)
ETH_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class TestGenerateStealthKeys:
    def test_valid_key_generation(self):
        keys, meta_address = generate_stealth_keys()

        # Meta-address: 66 bytes = 132 hex chars
        assert META_ADDR_RE.match(meta_address)

        # Compressed public keys: 33 bytes
        assert COMPRESSED_PUB_RE.match(keys.spending.public_key)
        assert COMPRESSED_PUB_RE.match(keys.viewing.public_key)

        # Private keys: 32 bytes
        assert HEX_32B_RE.match(keys.spending.private_key)
        assert HEX_32B_RE.match(keys.viewing.private_key)


class TestStealthAddressDerivation:
    def test_derive_and_detect(self):
        keys, _ = generate_stealth_keys()

        result = generate_stealth_address(
            keys.spending.public_key,
            keys.viewing.public_key,
        )

        assert ETH_ADDR_RE.match(result.stealth_address)
        assert COMPRESSED_PUB_RE.match(result.ephemeral_pub_key)
        assert 0 <= result.view_tag <= 255

        # Recipient scans and detects
        detected = check_stealth_announcement(
            {
                "schemeId": 1,
                "stealthAddress": result.stealth_address,
                "ephemeralPubKey": result.ephemeral_pub_key,
                "viewTag": result.view_tag,
            },
            keys.viewing.private_key,
            keys.spending.public_key,
        )

        assert detected is not None
        assert detected.stealth_address.lower() == result.stealth_address.lower()

    def test_wrong_view_tag_rejected(self):
        keys, _ = generate_stealth_keys()
        result = generate_stealth_address(
            keys.spending.public_key,
            keys.viewing.public_key,
        )

        wrong_view_tag = (result.view_tag + 1) % 256
        detected = check_stealth_announcement(
            {
                "schemeId": 1,
                "stealthAddress": result.stealth_address,
                "ephemeralPubKey": result.ephemeral_pub_key,
                "viewTag": wrong_view_tag,
            },
            keys.viewing.private_key,
            keys.spending.public_key,
        )

        assert detected is None

    def test_different_recipient_not_detected(self):
        recipient_keys, _ = generate_stealth_keys()
        other_keys, _ = generate_stealth_keys()

        result = generate_stealth_address(
            recipient_keys.spending.public_key,
            recipient_keys.viewing.public_key,
        )

        detected = check_stealth_announcement(
            {
                "schemeId": 1,
                "stealthAddress": result.stealth_address,
                "ephemeralPubKey": result.ephemeral_pub_key,
                "viewTag": result.view_tag,
            },
            other_keys.viewing.private_key,
            other_keys.spending.public_key,
        )

        assert detected is None

    def test_wrong_scheme_id_rejected(self):
        keys, _ = generate_stealth_keys()
        result = generate_stealth_address(
            keys.spending.public_key,
            keys.viewing.public_key,
        )

        detected = check_stealth_announcement(
            {
                "schemeId": 2,
                "stealthAddress": result.stealth_address,
                "ephemeralPubKey": result.ephemeral_pub_key,
                "viewTag": result.view_tag,
            },
            keys.viewing.private_key,
            keys.spending.public_key,
        )

        assert detected is None


class TestStealthPrivateKey:
    def test_compute_correct_private_key(self):
        keys, _ = generate_stealth_keys()

        result = generate_stealth_address(
            keys.spending.public_key,
            keys.viewing.public_key,
        )

        stealth_priv = compute_stealth_private_key(
            keys.spending.private_key,
            result.ephemeral_pub_key,
            keys.viewing.private_key,
        )

        assert HEX_32B_RE.match(stealth_priv)

        # Verify: derive pub from private key and check address matches
        priv_bytes = bytes.fromhex(stealth_priv[2:])
        priv_int = int.from_bytes(priv_bytes, "big")
        sk = SigningKey.from_secret_exponent(priv_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        pub_uncompressed = b'\x04' + vk.to_string()
        # Address from uncompressed pub
        pub_no_prefix = pub_uncompressed[1:]
        h = _keccak256(pub_no_prefix)
        addr_bytes = h[12:]
        derived_address = _checksum_address("0x" + addr_bytes.hex())

        assert derived_address.lower() == result.stealth_address.lower()


class TestMetaAddressParsing:
    def test_parse_and_format_uri(self):
        _, meta_address = generate_stealth_keys()
        uri = format_stealth_meta_uri(meta_address)

        assert re.match(r"^st:eth:0x[0-9a-f]{132}$", uri, re.I)

        spending_pub, viewing_pub = parse_stealth_meta_uri(uri)
        assert COMPRESSED_PUB_RE.match(spending_pub)
        assert COMPRESSED_PUB_RE.match(viewing_pub)

    def test_parse_meta_address(self):
        _, meta_address = generate_stealth_keys()
        spending_pub, viewing_pub = parse_stealth_meta_address(meta_address)
        assert COMPRESSED_PUB_RE.match(spending_pub)
        assert COMPRESSED_PUB_RE.match(viewing_pub)

    def test_invalid_uri_raises(self):
        with pytest.raises(ValueError):
            parse_stealth_meta_uri("invalid:0x1234")

    def test_invalid_meta_address_length(self):
        with pytest.raises(ValueError):
            parse_stealth_meta_address("0x" + "aa" * 30)


class TestUniqueness:
    def test_different_stealth_addresses_per_payment(self):
        keys, _ = generate_stealth_keys()

        r1 = generate_stealth_address(keys.spending.public_key, keys.viewing.public_key)
        r2 = generate_stealth_address(keys.spending.public_key, keys.viewing.public_key)

        assert r1.stealth_address != r2.stealth_address
        assert r1.ephemeral_pub_key != r2.ephemeral_pub_key

    def test_multiple_sequential_payments(self):
        keys, _ = generate_stealth_keys()
        results = []

        for _ in range(5):
            result = generate_stealth_address(
                keys.spending.public_key,
                keys.viewing.public_key,
            )
            results.append(result)

            detected = check_stealth_announcement(
                {
                    "schemeId": 1,
                    "stealthAddress": result.stealth_address,
                    "ephemeralPubKey": result.ephemeral_pub_key,
                    "viewTag": result.view_tag,
                },
                keys.viewing.private_key,
                keys.spending.public_key,
            )
            assert detected is not None

        addresses = [r.stealth_address.lower() for r in results]
        assert len(set(addresses)) == len(addresses)
