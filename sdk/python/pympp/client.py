"""MPP client for confidential payments via stealth addresses."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Optional

from .stealth import (
    generate_stealth_address,
    parse_stealth_meta_uri,
)


@dataclass
class ConfidentialChallenge:
    id: str
    method: str
    intent: str
    request: str  # base64url-encoded payment request
    stealth_meta: str  # "st:eth:0x..." URI


@dataclass
class ConfidentialPaymentResult:
    tx_hash: str
    announcement_tx_hash: str
    stealth_address: str
    credential: str


# StealthAnnouncer ABI (minimal)
ANNOUNCER_ABI = [
    {
        "name": "announce",
        "type": "function",
        "inputs": [
            {"name": "schemeId", "type": "uint256"},
            {"name": "stealthAddress", "type": "address"},
            {"name": "ephemeralPubKey", "type": "bytes"},
            {"name": "viewTag", "type": "uint8"},
            {"name": "metadata", "type": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    }
]

# ERC-20 transfer ABI
TRANSFER_ABI = [
    {
        "name": "transfer",
        "type": "function",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    }
]

_AUTH_PARAM_RE = re.compile(r'([a-zA-Z_-]+)\s*=\s*"([^"]*)"')


def _parse_auth_params(s: str) -> dict[str, str]:
    return dict(_AUTH_PARAM_RE.findall(s))


def _base64url_encode(data: str) -> str:
    encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
    return encoded.replace("+", "-").replace("/", "_").rstrip("=")


def parse_confidential_challenge(www_authenticate: str) -> Optional[ConfidentialChallenge]:
    """Parse a WWW-Authenticate header for a confidential payment challenge.

    Format: Payment id="...", method="tempo", intent="charge",
            request="base64url...", stealth-meta="st:eth:0x..."

    Returns None if not a valid stealth challenge.
    """
    if not www_authenticate.startswith("Payment"):
        return None

    params = _parse_auth_params(www_authenticate[len("Payment"):])

    stealth_meta = params.get("stealth-meta")
    if not stealth_meta:
        return None

    return ConfidentialChallenge(
        id=params.get("id", ""),
        method=params.get("method", "tempo"),
        intent=params.get("intent", "charge"),
        request=params.get("request", ""),
        stealth_meta=stealth_meta,
    )


def execute_confidential_charge(
    challenge: ConfidentialChallenge,
    w3,
    account,
    token_address: str,
    amount: int,
    announcer_address: str,
) -> ConfidentialPaymentResult:
    """Execute a confidential charge payment.

    1. Parse stealth-meta -> derive stealth address
    2. Transfer TIP-20 to stealth address
    3. Call StealthAnnouncer.announce()
    4. Return credential for Authorization header

    Args:
        challenge: Parsed confidential challenge.
        w3: web3.Web3 instance.
        account: eth_account.Account with signing capability.
        token_address: TIP-20 token contract address.
        amount: Amount to transfer (in smallest unit).
        announcer_address: StealthAnnouncer contract address.
    """
    # 1. Derive stealth address
    spending_pub, viewing_pub = parse_stealth_meta_uri(challenge.stealth_meta)
    stealth_result = generate_stealth_address(spending_pub, viewing_pub)

    # 2. Transfer TIP-20
    token_contract = w3.eth.contract(
        address=w3.to_checksum_address(token_address),
        abi=TRANSFER_ABI,
    )
    tx = token_contract.functions.transfer(
        w3.to_checksum_address(stealth_result.stealth_address),
        amount,
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

    # 3. Announce
    announcer_contract = w3.eth.contract(
        address=w3.to_checksum_address(announcer_address),
        abi=ANNOUNCER_ABI,
    )
    metadata = challenge.id.encode("utf-8")
    ephemeral_bytes = bytes.fromhex(
        stealth_result.ephemeral_pub_key[2:]
        if stealth_result.ephemeral_pub_key.startswith("0x")
        else stealth_result.ephemeral_pub_key
    )

    announce_tx = announcer_contract.functions.announce(
        1,  # scheme ID
        w3.to_checksum_address(stealth_result.stealth_address),
        ephemeral_bytes,
        stealth_result.view_tag,
        metadata,
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
    })
    signed_announce = account.sign_transaction(announce_tx)
    announce_tx_hash = w3.eth.send_raw_transaction(signed_announce.raw_transaction)
    w3.eth.wait_for_transaction_receipt(announce_tx_hash)

    # 4. Credential
    credential = _base64url_encode(tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash)

    return ConfidentialPaymentResult(
        tx_hash="0x" + (tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash),
        announcement_tx_hash="0x" + (announce_tx_hash.hex() if isinstance(announce_tx_hash, bytes) else announce_tx_hash),
        stealth_address=stealth_result.stealth_address,
        credential=credential,
    )


def build_authorization_header(challenge_id: str, credential: str) -> str:
    """Build the Authorization header from challenge ID and credential."""
    return f'Payment id="{challenge_id}", credential="{credential}"'
