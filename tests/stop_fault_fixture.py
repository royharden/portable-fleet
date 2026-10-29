"""Finite injected stop/close failures; no fabricated completion or file cleanup."""
import json
import mmap
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_fleet.owned_dispatch import OwnedPhaseDispatcher
from portable_fleet.permit_guard import GuardedFamily, retain
from portable_fleet.recipient import ReceiptRecipient
from family_fixture import Event, environment
from journal_test_support import declared_identity
from owned_dispatch_fixture import ROLES
from test_dispatch import effect
from test_permit_guard import observation, packet


def main(output, scope, fault):
    if fault not in ("stop-before", "stop-after", "fallback-after", "both-before", "cleanup-journal", "cleanup-guard"):
        raise ValueError("Unknown bounded stop-fault fixture")
    output = Path(output)
    names = {role: "Local\\PF-owned-" + scope + "-" + role for role in ROLES}
    events = {role: Event(name) for role, name in names.items()}
    owner = guard = None
    cleanup_attempted = False

    def report(value):
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(raw) > 65532: raise ValueError("Oversized stop-fault report")
        with mmap.mmap(-1, 65536, tagname="Local\\PF-owned-report-" + scope) as memory:
            memory[4:4 + len(raw)] = raw
            memory[:4] = len(raw).to_bytes(4, "little")

    try:
        argv = [sys.executable, "-I", "-B", str(Path(__file__).with_name("family_fixture.py")),
                "root", str(output), names["root-ready"], names["root-stop"], "120000", "work"]
        guard = GuardedFamily(argv, str(output), environment(), output / "guard-state", scope, "synthetic-account")
        recipient = ReceiptRecipient(scope, "synthetic-account")
        owner = OwnedPhaseDispatcher(guard, recipient, output / "operations", declared_identity())
        owner.activate(packet(scope, observation(time.time())))
        if not events["root-ready"].wait(10000): raise ValueError("Root readiness deadline")
        members = guard.capture_members()
        if len(members) != 6: raise ValueError("Expected six owned members")
        owner.enqueue(effect(scope, 4))
        guard.writer(output / "fixture-ready.json", {"scope": scope, "members": members, "suspended_ready": False})
        original_stop, original_family_close = guard.stop, guard.family.close
        original_journal_close, original_guard_close = owner.journal.close, guard.close
        calls = {"primary": 0, "fallback": 0}
        cleanup_order = []
        def stop(reason, *, event_started_mono=None):
            calls["primary"] += 1
            if fault == "both-before" or (fault in ("stop-before", "fallback-after") and calls["primary"] == 1):
                raise RuntimeError("Injected primary exception BEFORE native action")
            result = original_stop(reason, event_started_mono=event_started_mono)
            if fault == "stop-after" and calls["primary"] == 1:
                raise RuntimeError("Injected primary exception AFTER native completion")
            return result
        def family_close():
            calls["fallback"] += 1
            if fault == "both-before": raise RuntimeError("Injected fallback exception BEFORE handle release")
            original_family_close()
            if fault == "fallback-after" and calls["fallback"] == 1:
                raise RuntimeError("Injected fallback exception AFTER handle release")
        def journal_close():
            cleanup_order.append("journal")
            if fault == "cleanup-journal": raise RuntimeError("Injected journal close BEFORE marker-handle release")
            original_journal_close()
        def guard_close():
            cleanup_order.append("guard")
            original_guard_close()
            if fault == "cleanup-guard": raise RuntimeError("Injected guard close AFTER handle release")
        guard.stop, guard.family.close = stop, family_close
        owner.journal.close, guard.close = journal_close, guard_close
        events["ready"].set()
        if not events["go"].wait(10000): raise ValueError("Stop-fault go deadline")
        first = owner.stop("Injected stop-fault request")
        # Repeating stop must not retry the fault, mutate report or claim later success.
        repeated = owner.stop("Later repeated stop")
        same_report = repeated is first
        before = {"scope": scope, "fault": fault, "stop": first, "same_latched_report": same_report,
            "calls_before_cleanup": dict(calls), "counter": owner.dispatcher.status(), "recipient": recipient.status(),
            "job_handle_retained": bool(guard.family.job),
            "provenance": "volatile fault report; parent native handles supply physical exit proof"}
        report(before)
        events["complete"].set()
        if not events["finish"].wait(15000): raise ValueError("Stop-fault finish deadline")
        cleanup_attempted = True
        close_errors = []
        try: owner.close()
        except BaseException as error: close_errors.append(str(error))
        after = {**before, "cleanup_order": cleanup_order, "cleanup_errors": close_errors,
            "close_confirmed": not close_errors, "calls_after_cleanup": dict(calls),
            "same_report_after_cleanup": owner.stop_report is first, "final_stop": owner.stop_report,
            "counter_after": owner.dispatcher.status(), "recipient_after": recipient.status(),
            "job_handle_after_cleanup": bool(guard.family.job), "restart_admitted": False}
        report(after)
        retain(output / "fixture-final.json", after)  # test observation AFTER enforcement attempt; not journal outcome
        return 70 if fault == "both-before" else 0
    finally:
        try:
            if not cleanup_attempted:
                if owner: owner.close()
                elif guard: guard.close()
        finally:
            for event in events.values(): event.close()


if __name__ == "__main__":
    code = main(*sys.argv[1:])
    os._exit(code)  # explicit fixture owner death; may be the ONLY successful job-handle release
