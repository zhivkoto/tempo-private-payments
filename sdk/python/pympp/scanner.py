"""Announcement scanner for stealth address payments."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .stealth import check_stealth_announcement, StealthPaymentInfo


# StealthAnnouncer Announcement event ABI
ANNOUNCEMENT_EVENT_ABI = [
    {
        "anonymous": False,
        "name": "Announcement",
        "type": "event",
        "inputs": [
            {"indexed": True, "name": "schemeId", "type": "uint256"},
            {"indexed": True, "name": "stealthAddress", "type": "address"},
            {"indexed": False, "name": "caller", "type": "address"},
            {"indexed": False, "name": "ephemeralPubKey", "type": "bytes"},
            {"indexed": False, "name": "viewTag", "type": "uint8"},
            {"indexed": False, "name": "metadata", "type": "bytes"},
        ],
    }
]


@dataclass
class AnnouncementEvent:
    scheme_id: int
    stealth_address: str
    ephemeral_pub_key: str
    view_tag: int
    metadata: bytes
    block_number: int
    tx_hash: str


class AnnouncementScanner:
    """Scans StealthAnnouncer events and checks if payments are addressed to us."""

    def __init__(
        self,
        w3,
        announcer_address: str,
        viewing_private_key: str,
        spending_pub_key: str,
        on_payment: Optional[Callable[[StealthPaymentInfo, AnnouncementEvent], None]] = None,
        poll_interval: float = 2.0,
        from_block: int = 0,
    ):
        self.w3 = w3
        self.announcer_address = announcer_address
        self.viewing_private_key = viewing_private_key
        self.spending_pub_key = spending_pub_key
        self.on_payment = on_payment
        self.poll_interval = poll_interval
        self.last_scanned_block = from_block
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start background scanning thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background scanner."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    def scan_range(self, from_block: int, to_block: int) -> list[tuple[StealthPaymentInfo, AnnouncementEvent]]:
        """Scan a block range for matching announcements.

        Returns list of (StealthPaymentInfo, AnnouncementEvent) tuples.
        """
        events = self._fetch_events(from_block, to_block)
        results = []
        for event in events:
            info = self.verify_payment(event)
            if info is not None:
                results.append((info, event))
        return results

    def verify_payment(self, event: AnnouncementEvent) -> Optional[StealthPaymentInfo]:
        """Check if a single announcement event is addressed to us."""
        announcement = {
            "schemeId": event.scheme_id,
            "stealthAddress": event.stealth_address,
            "ephemeralPubKey": event.ephemeral_pub_key,
            "viewTag": event.view_tag,
        }
        return check_stealth_announcement(
            announcement,
            self.viewing_private_key,
            self.spending_pub_key,
        )

    def _fetch_events(self, from_block: int, to_block: int) -> list[AnnouncementEvent]:
        """Fetch Announcement events from the chain."""
        contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(self.announcer_address),
            abi=ANNOUNCEMENT_EVENT_ABI,
        )
        logs = contract.events.Announcement().get_logs(
            fromBlock=from_block,
            toBlock=to_block,
        )
        events = []
        for log in logs:
            epk = log.args.ephemeralPubKey
            if isinstance(epk, bytes):
                epk = "0x" + epk.hex()
            events.append(AnnouncementEvent(
                scheme_id=log.args.schemeId,
                stealth_address=log.args.stealthAddress,
                ephemeral_pub_key=epk,
                view_tag=log.args.viewTag,
                metadata=log.args.metadata,
                block_number=log.blockNumber,
                tx_hash=log.transactionHash.hex() if isinstance(log.transactionHash, bytes) else log.transactionHash,
            ))
        return events

    def _poll_loop(self) -> None:
        """Background polling loop."""
        while not self._stop_event.is_set():
            try:
                current_block = self.w3.eth.block_number
                if current_block > self.last_scanned_block:
                    results = self.scan_range(self.last_scanned_block + 1, current_block)
                    for info, event in results:
                        if self.on_payment:
                            self.on_payment(info, event)
                    self.last_scanned_block = current_block
            except Exception:
                pass  # Continue polling on transient errors
            self._stop_event.wait(self.poll_interval)
