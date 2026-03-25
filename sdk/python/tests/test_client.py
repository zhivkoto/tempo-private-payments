"""Tests for MPP client — mirrors TS client.test.ts."""

import pytest

from pympp.client import (
    parse_confidential_challenge,
    build_authorization_header,
)


class TestParseConfidentialChallenge:
    def test_parse_stealth_challenge(self):
        www_auth = (
            'Payment id="inv_7x9k", method="tempo", intent="charge", '
            f'request="dGVzdA", stealth-meta="st:eth:0x{"a1" * 66}"'
        )

        challenge = parse_confidential_challenge(www_auth)

        assert challenge is not None
        assert challenge.id == "inv_7x9k"
        assert challenge.method == "tempo"
        assert challenge.intent == "charge"
        assert challenge.request == "dGVzdA"
        assert "st:eth:0x" in challenge.stealth_meta

    def test_null_for_non_stealth_challenge(self):
        www_auth = 'Payment id="inv_7x9k", method="tempo", intent="charge", request="dGVzdA"'
        assert parse_confidential_challenge(www_auth) is None

    def test_null_for_non_payment_scheme(self):
        www_auth = 'Bearer realm="example"'
        assert parse_confidential_challenge(www_auth) is None


class TestBuildAuthorizationHeader:
    def test_correct_format(self):
        header = build_authorization_header("inv_7x9k", "base64url-tx-proof")
        assert header == 'Payment id="inv_7x9k", credential="base64url-tx-proof"'
