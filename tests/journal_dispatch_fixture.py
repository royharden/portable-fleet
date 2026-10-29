"""Finite actual process-crash fixture, retaining every marker/database/observation."""
from contextlib import contextmanager
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_fleet.journal_dispatch import JournaledDispatcher, _CounterAdapter
from portable_fleet.permit_guard import retain
from portable_fleet.recipient import ReceiptRecipient
from test_dispatch import effect
from test_permit_guard import observation, packet, uid
from test_recipient import ack
from journal_test_support import declared_identity


def main(output, phase):
    output = Path(output)
    scope = uid()
    recipient = ReceiptRecipient(scope, "synthetic-account", clock=lambda: (1000, 50))
    request = packet(scope, observation(1000))
    recipient.begin(request)
    recipient.accept(ack(request))
    owner = JournaledDispatcher(recipient, output / "journal", declared_identity())
    command = effect(scope, 4)
    owner.enqueue(command)
    retain(output / "fixture-input.json", {"scope": scope, "command": command, "phase": phase})
    if phase == "accepted":
        original = owner.journal.connect
        calls = 0
        @contextmanager
        def connect():
            nonlocal calls
            calls += 1
            if calls == 2: os._exit(71)  # accepted commit complete, executing not begun
            with original() as db:
                yield db
        owner.journal.connect = connect
    elif phase == "before-effect":
        original = _CounterAdapter.validate
        calls = 0
        def validate(adapter, identity, kind):
            nonlocal calls
            original(adapter, identity, kind)
            calls += 1
            if calls == 2: os._exit(72)  # executing committed, counter not touched
        _CounterAdapter.validate = validate
    elif phase == "after-effect":
        class CrashLedger(list):
            def append(self, record):
                retain(output / "effect-observation.json", {
                    "observed_counter": owner.dispatcher.status()["total"], "operation": record["operation"],
                    "provenance": "fixture instrumentation AFTER volatile counter; not durable counter restoration"})
                os._exit(73)
        owner.dispatcher._effects = CrashLedger()
    else:
        raise ValueError("Unknown finite crash phase")
    owner.dispatch_next()
    raise AssertionError("Crash injection did not execute")


if __name__ == "__main__":
    main(*sys.argv[1:])
