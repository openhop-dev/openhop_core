#!/usr/bin/env python3
"""Exercise MeshCore KISS v2 ``radio2`` with three physical modems.

This is an RF hardware-in-the-loop test, not a pytest test.  It needs three
MeshCore KISS v2 modems:

* a MeshCore KISS v2 image driven by OpenHop (the device under test),
* a peer whose primary radio is profile A, and
* a peer whose primary radio is profile B.

The modem under test alternates locally between profile A on KISS port 0 and
profile B on KISS port 1.  Every radio configuration command is session-only
in the MeshCore KISS firmware.  The runner snapshots and restores the primary
radio, ``radio2``, TX power, and signal-report setting before closing each
serial connection.

The runner deliberately refuses to emit RF without ``--yes-transmit``.  Use
low power plus adequate attenuation or shielding for a bench test.
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openhop_core.hardware.kiss_modem_wrapper import (  # noqa: E402
    KISS_RADIO2_PORT,
    KISS_RADIO_PORT,
    KissModemWrapper,
)


@dataclass(frozen=True)
class RadioProfile:
    """One KISS radio tuple, including the radio2-only mode/preamble fields."""

    frequency: int
    bandwidth: int
    spreading_factor: int
    coding_rate: int
    mode: int = 2
    preamble_length: int = 96

    def primary_dict(self) -> dict[str, int]:
        return {
            "frequency": self.frequency,
            "bandwidth": self.bandwidth,
            "spreading_factor": self.spreading_factor,
            "coding_rate": self.coding_rate,
        }

    def radio2_dict(self) -> dict[str, int]:
        return {
            **self.primary_dict(),
            "mode": self.mode,
            "preamble_length": self.preamble_length,
        }


@dataclass
class ModemSnapshot:
    """Session-only state restored when the runner finishes."""

    primary: dict[str, int] | None
    radio2: dict[str, int] | None
    tx_power: int | None
    signal_report: bool | None


class ReceptionLog:
    """Thread-safe callback sink for a single KISS modem."""

    def __init__(self) -> None:
        self._events: list[tuple[bytes, int, int | None, float | None]] = []
        self._condition = threading.Condition()

    def callback(
        self,
        data: bytes,
        rssi: int | None = None,
        snr: float | None = None,
        radio_port: int = KISS_RADIO_PORT,
    ) -> None:
        with self._condition:
            self._events.append((bytes(data), radio_port, rssi, snr))
            self._condition.notify_all()

    def checkpoint(self) -> int:
        with self._condition:
            return len(self._events)

    def wait_for(
        self,
        start: int,
        expected_payload: bytes,
        expected_port: int,
        timeout: float,
    ) -> tuple[bytes, int, int | None, float | None] | None:
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                for event in self._events[start:]:
                    if event[0] == expected_payload and event[1] == expected_port:
                        return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)


@dataclass
class TestModem:
    """An OpenHop KISS wrapper together with its receive ledger."""

    name: str
    modem: KissModemWrapper
    received: ReceptionLog
    snapshot: ModemSnapshot | None = None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modem-port", required=True, help="KISS modem-under-test serial path")
    parser.add_argument(
        "--modem-name",
        default="KISS modem",
        help="label for the modem under test in test output",
    )
    parser.add_argument("--peer-a-port", required=True, help="profile-A peer serial path")
    parser.add_argument("--peer-b-port", required=True, help="profile-B peer serial path")
    parser.add_argument("--frequency", type=int, default=909_500_000, help="frequency in Hz")
    parser.add_argument("--bandwidth", type=int, default=62_500, help="bandwidth in Hz")
    parser.add_argument("--profile-a-sf", type=int, default=7, choices=range(5, 13))
    parser.add_argument("--profile-b-sf", type=int, default=8, choices=range(5, 13))
    parser.add_argument("--coding-rate", type=int, default=5, choices=range(5, 9))
    parser.add_argument("--preamble", type=int, default=96, help="radio2 preamble symbols")
    parser.add_argument("--tx-power", type=int, default=2, help="temporary chip TX power in dBm")
    parser.add_argument("--trials", type=int, default=10, help="trials per directional leg")
    parser.add_argument(
        "--min-successes",
        type=int,
        default=None,
        help="required successes per leg (default: ceil(90%% of trials))",
    )
    parser.add_argument("--timeout", type=float, default=12.0, help="RX/TX timeout per frame")
    parser.add_argument("--inter-trial", type=float, default=0.15, help="seconds between trials")
    parser.add_argument(
        "--yes-transmit",
        action="store_true",
        help="acknowledge that this command will send RF packets",
    )
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="leave volatile KISS session configuration in the test state",
    )
    args = parser.parse_args(argv)
    if args.trials < 1:
        parser.error("--trials must be at least 1")
    if args.min_successes is not None and not 1 <= args.min_successes <= args.trials:
        parser.error("--min-successes must be between 1 and --trials")
    if args.preamble < 1:
        parser.error("--preamble must be positive")
    if args.timeout <= 0 or args.inter_trial < 0:
        parser.error("--timeout must be positive and --inter-trial cannot be negative")
    return args


def profile_matches(actual: dict[str, Any] | None, expected: RadioProfile) -> bool:
    if actual is None:
        return False
    return all(actual.get(key) == value for key, value in expected.radio2_dict().items())


def connect_modem(name: str, port: str, primary: RadioProfile) -> TestModem:
    received = ReceptionLog()
    modem = KissModemWrapper(
        port=port,
        auto_configure=False,
        on_frame_received=received.callback,
        radio_config={**primary.primary_dict(), "power": 2},
        connect_retries=2,
        startup_retry_budget_sec=5.0,
    )
    if not modem.connect():
        raise RuntimeError(f"{name}: could not establish a KISS connection on {port}")
    if modem.modem_version is None or modem.modem_version < 2:
        raise RuntimeError(
            f"{name}: expected KISS protocol v2 or later, got {modem.modem_version!r}"
        )
    return TestModem(name=name, modem=modem, received=received)


def capture_snapshot(test_modem: TestModem) -> None:
    modem = test_modem.modem
    test_modem.snapshot = ModemSnapshot(
        primary=modem.get_radio_config(),
        radio2=modem.get_radio2_config(),
        tx_power=modem.get_tx_power(),
        signal_report=modem.get_signal_report(),
    )


def configure_modem(
    test_modem: TestModem,
    primary: RadioProfile,
    secondary: RadioProfile,
    tx_power: int,
) -> None:
    modem = test_modem.modem
    if not modem.configure_radio(**primary.primary_dict()):
        raise RuntimeError(f"{test_modem.name}: primary profile configuration failed")
    if not modem.set_tx_power(tx_power):
        raise RuntimeError(f"{test_modem.name}: temporary TX power configuration failed")
    if not modem.set_signal_report(True):
        raise RuntimeError(f"{test_modem.name}: enabling RxMeta reporting failed")
    if not modem.set_radio2_config(**secondary.radio2_dict()):
        raise RuntimeError(f"{test_modem.name}: radio2 configuration failed")

    actual_primary = modem.get_radio_config()
    actual_secondary = modem.get_radio2_config()
    if actual_primary != primary.primary_dict():
        raise RuntimeError(
            f"{test_modem.name}: primary readback mismatch: {actual_primary!r} != "
            f"{primary.primary_dict()!r}"
        )
    if not profile_matches(actual_secondary, secondary):
        raise RuntimeError(
            f"{test_modem.name}: radio2 readback mismatch: {actual_secondary!r} != "
            f"{secondary.radio2_dict()!r}"
        )


def restore_modem(test_modem: TestModem) -> None:
    snapshot = test_modem.snapshot
    modem = test_modem.modem
    if snapshot is None:
        return
    try:
        if snapshot.primary is not None:
            modem.configure_radio(**snapshot.primary)
        if snapshot.tx_power is not None:
            modem.set_tx_power(snapshot.tx_power)
        if snapshot.radio2 is None:
            modem.set_radio2_config(0, 0, 0, 0, mode=0, preamble_length=0)
        else:
            modem.set_radio2_config(**snapshot.radio2)
        if snapshot.signal_report is not None:
            modem.set_signal_report(snapshot.signal_report)
    except Exception as exc:  # Cleanup must not mask the test's primary result.
        print(f"WARN: {test_modem.name}: failed to restore volatile state: {exc}", file=sys.stderr)


def payload(leg: int, trial: int) -> bytes:
    """Make an exact, unique raw packet for a KISS RF leg."""
    return b"OH2" + bytes((leg, trial)) + os.urandom(10)


def send_and_expect(
    sender: TestModem,
    receiver: TestModem,
    *,
    sender_port: int,
    receiver_port: int,
    packet: bytes,
    timeout: float,
) -> tuple[bool, str]:
    checkpoint = receiver.received.checkpoint()
    verdict: list[str | None] = []
    sent = sender.modem.send_frame_and_wait(
        packet,
        timeout=timeout,
        radio_port=sender_port,
        verdict=verdict,
    )
    if not sent:
        return False, f"TX failed: {verdict[-1] if verdict else 'no verdict'}"
    event = receiver.received.wait_for(checkpoint, packet, receiver_port, timeout)
    if event is None:
        return False, f"no matching RX on KISS port {receiver_port}"
    return True, f"RSSI={event[2]} SNR={event[3]} port={event[1]}"


def run_leg(
    name: str,
    leg: int,
    sender: TestModem,
    receiver: TestModem,
    sender_port: int,
    receiver_port: int,
    args: argparse.Namespace,
) -> int:
    successes = 0
    for trial in range(1, args.trials + 1):
        packet = payload(leg, trial)
        ok, detail = send_and_expect(
            sender,
            receiver,
            sender_port=sender_port,
            receiver_port=receiver_port,
            packet=packet,
            timeout=args.timeout,
        )
        successes += int(ok)
        result = "PASS" if ok else "FAIL"
        print(f"{result} {name} {trial}/{args.trials}: {detail}")
        if args.inter_trial:
            time.sleep(args.inter_trial)
    return successes


def print_plan(args: argparse.Namespace, profile_a: RadioProfile, profile_b: RadioProfile) -> None:
    print("Three-radio KISS v2 HIL plan")
    print(f"  {args.modem_name}: {args.modem_port} (primary A, radio2 B)")
    print(f"  Peer A: {args.peer_a_port} (primary A, radio2 B)")
    print(f"  Peer B: {args.peer_b_port} (primary B, radio2 A)")
    print(f"  A: {profile_a.radio2_dict()}")
    print(f"  B: {profile_b.radio2_dict()}")
    print(f"  TX: {args.tx_power} dBm, {args.trials} trials per directional leg")
    print(
        "  Required checks: "
        f"A->{args.modem_name} port0, B->{args.modem_name} port1, "
        f"{args.modem_name} port0->A, {args.modem_name} port1->B"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profile_a = RadioProfile(
        args.frequency,
        args.bandwidth,
        args.profile_a_sf,
        args.coding_rate,
        preamble_length=args.preamble,
    )
    profile_b = RadioProfile(
        args.frequency,
        args.bandwidth,
        args.profile_b_sf,
        args.coding_rate,
        preamble_length=args.preamble,
    )
    required = args.min_successes or math.ceil(args.trials * 0.9)
    print_plan(args, profile_a, profile_b)
    if not args.yes_transmit:
        print("Dry run only. Re-run with --yes-transmit after confirming the bench setup.")
        return 0

    dut: TestModem | None = None
    peer_a: TestModem | None = None
    peer_b: TestModem | None = None
    try:
        dut = connect_modem(args.modem_name, args.modem_port, profile_a)
        peer_a = connect_modem("peer A", args.peer_a_port, profile_a)
        peer_b = connect_modem("peer B", args.peer_b_port, profile_b)
        modems = (dut, peer_a, peer_b)
        for modem in modems:
            capture_snapshot(modem)

        configure_modem(dut, profile_a, profile_b, args.tx_power)
        configure_modem(peer_a, profile_a, profile_b, args.tx_power)
        configure_modem(peer_b, profile_b, profile_a, args.tx_power)

        legs = (
            (
                f"peer A -> {args.modem_name}",
                1,
                peer_a,
                dut,
                KISS_RADIO_PORT,
                KISS_RADIO_PORT,
            ),
            (
                f"peer B -> {args.modem_name}",
                2,
                peer_b,
                dut,
                KISS_RADIO_PORT,
                KISS_RADIO2_PORT,
            ),
            (
                f"{args.modem_name} port 0 -> peer A",
                3,
                dut,
                peer_a,
                KISS_RADIO_PORT,
                KISS_RADIO_PORT,
            ),
            (
                f"{args.modem_name} port 1 -> peer B",
                4,
                dut,
                peer_b,
                KISS_RADIO2_PORT,
                KISS_RADIO_PORT,
            ),
        )
        successes = {
            name: run_leg(name, leg, sender, receiver, sender_port, receiver_port, args)
            for name, leg, sender, receiver, sender_port, receiver_port in legs
        }
        print("\nSummary")
        for name, count in successes.items():
            print(f"  {name}: {count}/{args.trials} (required {required})")
        return 0 if all(count >= required for count in successes.values()) else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        for modem in (dut, peer_a, peer_b):
            if modem is None:
                continue
            if not args.no_restore:
                restore_modem(modem)
            modem.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
