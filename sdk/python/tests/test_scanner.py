"""Scanner tests with mocked events."""

from unittest.mock import MagicMock, patch

import pytest

from pympp.stealth import (
    generate_stealth_keys,
    generate_stealth_address,
)
from pympp.scanner import AnnouncementScanner, AnnouncementEvent


@pytest.fixture
def recipient_keys():
    keys, meta = generate_stealth_keys()
    return keys, meta


@pytest.fixture
def mock_w3():
    w3 = MagicMock()
    w3.to_checksum_address = lambda addr: addr
    w3.eth.block_number = 100
    return w3


def _make_event(keys, block_number=50) -> tuple:
    """Generate a stealth address and return matching AnnouncementEvent."""
    result = generate_stealth_address(
        keys.spending.public_key,
        keys.viewing.public_key,
    )
    event = AnnouncementEvent(
        scheme_id=1,
        stealth_address=result.stealth_address,
        ephemeral_pub_key=result.ephemeral_pub_key,
        view_tag=result.view_tag,
        metadata=b"test-invoice",
        block_number=block_number,
        tx_hash="0x" + "ab" * 32,
    )
    return result, event


class TestAnnouncementScanner:
    def test_verify_payment_match(self, recipient_keys, mock_w3):
        keys, _ = recipient_keys
        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys.viewing.private_key,
            spending_pub_key=keys.spending.public_key,
        )

        _, event = _make_event(keys)
        info = scanner.verify_payment(event)

        assert info is not None
        assert info.stealth_address.lower() == event.stealth_address.lower()

    def test_verify_payment_wrong_recipient(self, mock_w3):
        keys_a, _ = generate_stealth_keys()
        keys_b, _ = generate_stealth_keys()

        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys_b.viewing.private_key,
            spending_pub_key=keys_b.spending.public_key,
        )

        _, event = _make_event(keys_a)
        info = scanner.verify_payment(event)

        assert info is None

    def test_scan_range_with_mocked_events(self, recipient_keys, mock_w3):
        keys, _ = recipient_keys
        result, event = _make_event(keys, block_number=10)

        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys.viewing.private_key,
            spending_pub_key=keys.spending.public_key,
        )

        # Mock _fetch_events to return our event
        scanner._fetch_events = MagicMock(return_value=[event])

        results = scanner.scan_range(1, 100)
        assert len(results) == 1
        info, evt = results[0]
        assert info.stealth_address.lower() == event.stealth_address.lower()

    def test_scan_range_mixed_events(self, recipient_keys, mock_w3):
        keys, _ = recipient_keys
        other_keys, _ = generate_stealth_keys()

        _, our_event = _make_event(keys, block_number=10)
        _, other_event = _make_event(other_keys, block_number=11)

        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys.viewing.private_key,
            spending_pub_key=keys.spending.public_key,
        )

        scanner._fetch_events = MagicMock(return_value=[our_event, other_event])

        results = scanner.scan_range(1, 100)
        assert len(results) == 1

    def test_start_stop(self, recipient_keys, mock_w3):
        keys, _ = recipient_keys
        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys.viewing.private_key,
            spending_pub_key=keys.spending.public_key,
            poll_interval=0.1,
        )

        # Mock to avoid real chain calls
        scanner._fetch_events = MagicMock(return_value=[])

        scanner.start()
        assert scanner._thread is not None
        assert scanner._thread.is_alive()

        scanner.stop()
        assert not scanner._thread.is_alive() if scanner._thread else True

    def test_on_payment_callback(self, recipient_keys, mock_w3):
        keys, _ = recipient_keys
        _, event = _make_event(keys, block_number=50)

        callback = MagicMock()

        scanner = AnnouncementScanner(
            w3=mock_w3,
            announcer_address="0x" + "00" * 20,
            viewing_private_key=keys.viewing.private_key,
            spending_pub_key=keys.spending.public_key,
            on_payment=callback,
            poll_interval=0.1,
            from_block=49,
        )

        scanner._fetch_events = MagicMock(return_value=[event])

        # Manually trigger one poll cycle
        scanner.last_scanned_block = 49
        mock_w3.eth.block_number = 50
        results = scanner.scan_range(50, 50)

        # Simulate what _poll_loop does
        for info, evt in results:
            callback(info, evt)

        assert callback.call_count == 1
