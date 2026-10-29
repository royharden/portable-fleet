"""Finite owned-family/phase-failure fixture; test reports use volatile memory."""
import json
import mmap
import os
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_fleet.core import Refusal
from portable_fleet.owned_dispatch import OwnedPhaseDispatcher
from portable_fleet.permit_guard import GuardedFamily, retain
from portable_fleet.recipient import ReceiptRecipient
from family_fixture import Event, environment
from journal_test_support import declared_identity
from test_dispatch import effect
from test_permit_guard import observation, packet

ROLES = ("root-ready", "root-stop", "ready", "go", "sql-entered", "sql-release", "sql-finished",
         "guard-entered", "guard-release", "guard-finished", "complete", "finish", "cancel",
         "waiting", "control-trigger", "effect-finished")


def main(output, scope, fault):
    output = Path(output)
    idle_faults = ("idle-cancel", "idle-stop", "idle-deadline", "idle-priority", "idle-cancel-before", "idle-overflow",
                   "idle-invalid", "idle-dispatch-stop", "idle-lease-expiry", "idle-terminal-stall", "idle-duplicate", "idle-preflight-stop")
    if fault not in ("accepted", "executing", "outcome", "explicit-cancel", "dual-terminal-stall", "recipient-reject", "guard-closed", "normal", *idle_faults):
        raise Refusal("Unknown owned fixture fault")
    names = {role: "Local\\PF-owned-" + scope + "-" + role for role in ROLES}
    events = {role: Event(name) for role, name in names.items()}
    guard = owner = cancel_thread = None
    phase = "accepted" if fault in ("explicit-cancel", "dual-terminal-stall") else fault

    def guard_writer(path, value):
        if fault in ("dual-terminal-stall", "idle-terminal-stall") and path.name == "terminal.json":
            own = {role: Event(names[role]) for role in ("guard-entered", "guard-release", "guard-finished")}
            try:
                own["guard-entered"].set()
                if not own["guard-release"].wait(20000): raise OSError("Unreleased guard terminal fixture")
                retain(path, value)
            finally:
                own["guard-finished"].set()
                for event in own.values(): event.close()
        else:
            retain(path, value)

    def report(value):
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(raw) > 65532: raise Refusal("Oversized fixture observation")
        with mmap.mmap(-1, 65536, tagname="Local\\PF-owned-report-" + scope) as memory:
            memory[4:4 + len(raw)] = raw
            memory[:4] = len(raw).to_bytes(4, "little")

    try:
        argv = [sys.executable, "-I", "-B", str(Path(__file__).with_name("family_fixture.py")),
                "root", str(output), names["root-ready"], names["root-stop"], "120000", "work"]
        guard = GuardedFamily(argv, str(output), environment(), output / "guard-state", scope, "synthetic-account", writer=guard_writer)
        recipient = ReceiptRecipient(scope, "synthetic-account")
        owner = OwnedPhaseDispatcher(guard, recipient, output / "operations", declared_identity())
        request = packet(scope, observation(time.time() - (297 if fault == "idle-lease-expiry" else 0)))
        if fault == "recipient-reject":
            def reject(reply):
                recipient.close("Injected rejection after guard resume")
                raise Refusal("Injected recipient reply rejection")
            recipient.accept = reject
            ready = {"scope": scope, "members": [{"pid": guard.family.pid, "creationTime": {
                "value": guard.family.creation_time.value, "unit": guard.family.creation_time.unit}}], "suspended_ready": True}
        else:
            owner.activate(request)
            if not events["root-ready"].wait(10000): raise Refusal("Owned root readiness deadline")
            members = guard.capture_members()
            if len(members) != 6: raise Refusal("Expected six normal owned members")
            owner.enqueue(effect(scope, 4))
            ready = {"scope": scope, "members": members, "suspended_ready": False}
        guard.writer(output / "fixture-ready.json", ready)
        original = owner.journal.persist_phase
        def persist(current, operation, result=None):
            if current != phase: return original(current, operation, result)
            own = {role: Event(names[role]) for role in ("sql-entered", "sql-release", "sql-finished")}
            try:
                own["sql-entered"].set()
                if not own["sql-release"].wait(20000): raise OSError("Unreleased phase fixture")
                original(current, operation, result)
            finally:
                own["sql-finished"].set()
                for event in own.values(): event.close()
        owner.journal.persist_phase = persist
        if fault == "explicit-cancel":
            def cancel():
                if events["cancel"].wait(15000): owner.cancel("Explicit phase-wait cancellation")
            cancel_thread = threading.Thread(target=cancel, daemon=True)
            cancel_thread.start()
        events["ready"].set()
        if not events["go"].wait(10000): raise Refusal("Fixture go deadline")
        failure = None
        control_results, producer_errors = [], []
        def command(kind):
            from test_permit_guard import uid
            return {"schema": 1, "scope": scope, "operation": uid(), "kind": kind}
        def produce_control():
            if not owner.control.waiting.wait(10): return
            events["waiting"].set()
            if fault in ("idle-deadline", "idle-lease-expiry"): return
            if not events["control-trigger"].wait(10000): return
            try:
                if fault in ("idle-cancel", "idle-terminal-stall"):
                    owner.cancel("Idle external cancellation")
                elif fault == "idle-invalid":
                    owner.post_control({**command("stop"), "schema": True})
                elif fault == "idle-dispatch-stop":
                    owner.post_control(command("dispatch"))
                    if events["effect-finished"].wait(10000): owner.post_control(command("stop"))
                else: owner.post_control(command("stop"))
            except Refusal as error:
                producer_errors.append(str(error))
        try:
            if fault in idle_faults:
                if fault == "idle-cancel-before":
                    owner.cancel("Cancellation queued before wait")
                elif fault == "idle-priority":
                    for _ in range(8): owner.post_control(command("dispatch"))
                    owner.cancel("Cancellation takes priority over full queue")
                elif fault == "idle-overflow":
                    try:
                        for _ in range(9): owner.post_control(command("dispatch"))
                    except Refusal as error: producer_errors.append(str(error))
                elif fault == "idle-duplicate":
                    repeated = command("dispatch")
                    owner.post_control(repeated)
                    try: owner.post_control(repeated)
                    except Refusal as error: producer_errors.append(str(error))
                elif fault == "idle-preflight-stop":
                    original_current = recipient.require_current
                    def stop_during_preflight():
                        owner.post_control(command("stop"))
                        return original_current()  # cancellation closes it before returning
                    recipient.require_current = stop_during_preflight
                else:
                    cancel_thread = threading.Thread(target=produce_control, daemon=True)
                    cancel_thread.start()
                limit = 1.0 if fault == "idle-deadline" else (10.0 if fault == "idle-lease-expiry" else 5.0)
                result = owner.wait_control(maximum_seconds=limit)
                control_results.append(result)
                if result["kind"] == "dispatched":
                    events["effect-finished"].set()
                    control_results.append(owner.wait_control(maximum_seconds=5.0))
                if cancel_thread: cancel_thread.join(2)
            elif fault == "recipient-reject": owner.activate(request)
            else:
                if fault == "guard-closed": guard.stop("Injected prior terminal guard")
                owner.dispatch_next()
        except BaseException as error:
            failure = str(error)
        if owner.stop_report is None: owner.stop("Finite fixture explicit stop")
        before = {"scope": scope, "fault": fault, "failure": failure,
            "stop": owner.stop_report, "counter": owner.dispatcher.status(), "recipient": recipient.status(),
            "phase_actor": owner.actor.status(), "guard_journal": guard.journal.status(),
            "control_results": control_results, "mailbox": owner.control.status(), "producer_errors": producer_errors,
            "provenance": "volatile child report; parent separately pins exits; not SQL or guard durability"}
        report(before)
        events["complete"].set()
        if not events["finish"].wait(15000): raise Refusal("Fixture finish deadline")
        rejected = []
        for action in (lambda: owner.dispatch_next(), lambda: owner.activate(packet(scope, observation(time.time(), sequence=2))),
                       lambda: owner.post_control(command("dispatch"))):
            try: action(); rejected.append(False)
            except Refusal: rejected.append(True)
        report({**before, "after_release": {"counter": owner.dispatcher.status(), "recipient": recipient.status(),
            "phase_actor": owner.actor.status(), "guard_journal": guard.journal.status(),
            "dispatch_refused": rejected[0], "receipt_refused": rejected[1], "control_refused": rejected[2],
            "mailbox": owner.control.status(), "restart_admitted": False}})
        return 0
    finally:
        events["cancel"].set()
        events["control-trigger"].set()
        events["effect-finished"].set()
        if cancel_thread: cancel_thread.join(2)
        try:
            if owner: owner.close()
            elif guard: guard.close()
        finally:
            for event in events.values(): event.close()


if __name__ == "__main__":
    code = main(*sys.argv[1:])
    os._exit(code)  # after owned cleanup; finite fixture bypasses daemon-I/O interpreter teardown
