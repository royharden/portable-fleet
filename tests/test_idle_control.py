"""Finite nonpolling owner wakeup with independent native family-exit evidence."""
import threading
import time
import unittest
import os

from portable_fleet.control import ControlMailbox
from portable_fleet.core import Refusal, load
from portable_fleet.family import wait_owned_process
from portable_fleet.journal_dispatch import recover_operations
from portable_fleet.permit_guard import recover_state, retain
from test_owned_dispatch import ManagedOwnedDispatch
from test_permit_guard import directory, uid

OBSERVATIONS = []


def command(scope, kind="dispatch"):
    return {"schema": 1, "scope": scope, "operation": uid(), "kind": kind}


class MailboxTests(unittest.TestCase):
    def test_terminal_priority_is_independent_of_full_queue(self):
        scope, cancelled = uid(), threading.Event()
        mailbox = ControlMailbox(scope, cancelled)
        for _ in range(8): mailbox.post(command(scope))
        mailbox.terminate("cancel full queue")
        original = mailbox.status()["terminal"]["started_mono"]
        mailbox.terminate("later cancellation")
        self.assertEqual(mailbox.take(time.monotonic() + 1)["started_mono"], original)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(mailbox.status()["queued"], 8)
        self.assertEqual(mailbox.status()["wait_calls"], 0)

    def test_invalid_duplicate_and_lifetime_overflow_wake_terminal(self):
        for fault in ("invalid", "duplicate", "lifetime", "oversized", "reason"):
            scope, cancelled = uid(), threading.Event()
            mailbox = ControlMailbox(scope, cancelled)
            if fault == "invalid":
                with self.assertRaises(Refusal): mailbox.post({**command(scope), "schema": True})
            elif fault == "duplicate":
                repeated = command(scope)
                mailbox.post(repeated)
                with self.assertRaises(Refusal): mailbox.post(repeated)
            elif fault == "oversized":
                with self.assertRaises(Refusal): mailbox.post({str(i): i for i in range(10000)})
            elif fault == "reason":
                class BadReason:
                    def __str__(self): raise AssertionError("Cancellation must not invoke user code")
                terminal = mailbox.terminate(BadReason())
                self.assertEqual(terminal["reason"], "Invalid local cancellation reason")
            else:
                for _ in range(64):
                    mailbox.post(command(scope))
                    self.assertFalse(mailbox.take(time.monotonic() + 1)["terminal"])
                with self.assertRaises(Refusal): mailbox.post(command(scope))
            self.assertTrue(mailbox.take(time.monotonic() + 1)["terminal"])
            self.assertTrue(cancelled.is_set())

    def test_absolute_deadline_precedes_queued_dispatch_or_late_notification(self):
        for late_cancel in (False, True):
            scope, cancelled = uid(), threading.Event()
            mailbox = ControlMailbox(scope, cancelled)
            mailbox.post(command(scope))
            deadline = time.monotonic() - .01
            if late_cancel: mailbox.terminate("notification after elapsed deadline")
            result = mailbox.take(deadline)
            self.assertEqual(result["reason"], "Idle control deadline")
            self.assertEqual(result["started_mono"], deadline)
            self.assertEqual(mailbox.status()["queued"], 1)

    def test_blocking_wait_and_pre_wait_cancel_do_not_lose_notification(self):
        for before_wait in (False, True):
            mailbox = ControlMailbox(uid(), threading.Event())
            result = []
            thread = threading.Thread(target=lambda: result.append(mailbox.take(time.monotonic() + 2)))
            try:
                if before_wait: mailbox.terminate("pre-wait signal")
                thread.start()
                if not before_wait:
                    self.assertTrue(mailbox.waiting.wait(1))
                    mailbox.terminate("in-wait signal")
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertTrue(result[0]["terminal"])
                self.assertEqual(mailbox.status()["wait_calls"], 0 if before_wait else 1)
            finally:
                mailbox.terminate("test cleanup")
                thread.join(2)


@unittest.skipUnless(os.name == "nt", "Windows idle owned-family control")
class IdleControlIntegrationTests(unittest.TestCase):
    def exercise(self, fault):
        managed = ManagedOwnedDispatch(directory(fault), fault)
        prewait = fault in ("idle-priority", "idle-cancel-before", "idle-overflow", "idle-duplicate", "idle-preflight-stop")
        timer = fault in ("idle-deadline", "idle-lease-expiry")
        try:
            self.assertEqual(len(managed.pins), 6)
            started = time.monotonic()
            managed.events["go"].set()
            if not prewait:
                self.assertTrue(managed.events["waiting"].wait(3000))
                if not timer: managed.events["control-trigger"].set()
            deadline = started + 10
            for pin in managed.pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                self.assertFalse(pin.alive())
            observed = time.monotonic()
            self.assertLessEqual(observed, deadline)
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertTrue(managed.events["complete"].wait(3000))
            before = managed.report()
            family = before["stop"]["family_stop"]
            self.assertEqual(family["pinned_count"], 6)
            self.assertTrue(family["all_pinned_ended"])
            self.assertEqual(family["job_stop"]["accounting"]["active"], 0)
            self.assertEqual(family["enforcement_started_mono"], before["mailbox"]["terminal"]["started_mono"])
            self.assertLessEqual(family["request_to_all_pins_seconds"], 10)
            self.assertEqual(before["control_results"][-1]["kind"], "stopped")
            self.assertTrue(before["counter"]["closed"])
            self.assertTrue(before["recipient"]["closed"])
            expected = 4 if fault == "idle-dispatch-stop" else 0
            self.assertEqual(before["counter"]["total"], expected)
            self.assertEqual(len(before["counter"]["effects"]), 1 if expected else 0)
            if prewait: self.assertEqual(before["mailbox"]["wait_calls"], 0)
            else: self.assertGreaterEqual(before["mailbox"]["wait_calls"], 1)
            if fault == "idle-preflight-stop": self.assertIn("interrupted_check", before["control_results"][-1])
            if fault in ("idle-priority", "idle-overflow"): self.assertEqual(before["mailbox"]["queued"], 8)
            if fault == "idle-duplicate": self.assertEqual(before["mailbox"]["queued"], 1)
            if fault in ("idle-invalid", "idle-overflow", "idle-duplicate"): self.assertTrue(before["producer_errors"])
            if timer:
                result = before["control_results"][-1]
                self.assertEqual(result["control"]["reason"], "Idle control deadline")
                self.assertEqual(result["control"]["started_mono"], result["wait_deadline_mono"])
                self.assertEqual(result["deadline_kind"], "lease" if fault == "idle-lease-expiry" else "maximum")
                if fault == "idle-deadline": self.assertGreaterEqual(observed - started, .9)
            if fault == "idle-terminal-stall":
                self.assertFalse(managed.events["guard-release"].wait(0))
                self.assertTrue(managed.events["guard-entered"].wait(0))
                self.assertTrue(before["guard_journal"]["storage_pending"])
                self.assertEqual(before["stop"]["state"], "uncertain")
                self.assertFalse((managed.output / "guard-state/stop.json").exists())
            else: self.assertEqual(before["stop"]["state"], "stopped")
            work = managed.work()
            retain(managed.output / "idle-before-release.json", {
                "scope": managed.scope, "pins": managed.ready["members"], "six_exits_before_storage_release": True,
                "trigger_to_exit_observation_seconds": observed - started, "work": work,
                "sentinel_survived": True, "volatile_child_report": before})
            if fault == "idle-terminal-stall":
                managed.events["guard-release"].set()
                self.assertTrue(managed.events["guard-finished"].wait(3000))
                self.assertEqual(load(managed.output / "guard-state/terminal.json")["scope"], managed.scope)
            history = recover_operations(managed.output / "operations")
            self.assertEqual(len(history["operations"]), 1 if expected else 0)
            self.assertFalse(history["restart_admitted"])
            self.assertFalse(recover_state(managed.output / "guard-state")["restart_admitted"])
            managed.events["finish"].set()
            self.assertEqual(managed.process.wait(timeout=10), 0)
            self.assertEqual(managed.process.stdout.read(), b"")
            self.assertEqual(managed.process.stderr.read(), b"")
            after = managed.report()["after_release"]
            self.assertEqual(after["counter"]["total"], expected)
            self.assertTrue(after["dispatch_refused"])
            self.assertTrue(after["receipt_refused"])
            self.assertTrue(after["control_refused"])
            self.assertEqual(after["mailbox"]["terminal"]["started_mono"], before["mailbox"]["terminal"]["started_mono"])
            self.assertEqual(managed.work(), work)
            self.assertTrue(managed.sentinel_pin.alive())
            record = {"variant": fault, "six_independent_exits": True, "parent_observation_seconds": observed - started,
                "before_release": before, "after_release": after, "work_unchanged": work,
                "sentinel_survived": True, "sql_history": history,
                "provenance": "parent native pins plus volatile child memory; not durable counter restoration"}
            retain(managed.output / "idle-after-release.json", record)
            OBSERVATIONS.append(record)
        finally: managed.close()

    def test_idle_cancel_wakes_owner_and_stops_six(self): self.exercise("idle-cancel")
    def test_idle_stop_control_wakes_owner(self): self.exercise("idle-stop")
    def test_idle_finite_window_deadline_stops_without_control(self): self.exercise("idle-deadline")
    def test_terminal_cancel_precedes_eight_queued_dispatches(self): self.exercise("idle-priority")
    def test_cancel_before_wait_is_not_lost(self): self.exercise("idle-cancel-before")
    def test_overflow_is_terminal_even_with_full_queue(self): self.exercise("idle-overflow")
    def test_invalid_control_wakes_terminal_enforcement(self): self.exercise("idle-invalid")
    def test_dispatch_control_checks_admission_then_stop_control(self): self.exercise("idle-dispatch-stop")
    def test_idle_wait_is_clipped_to_original_source_deadline(self): self.exercise("idle-lease-expiry")
    def test_idle_cancel_stops_before_guard_storage_release(self): self.exercise("idle-terminal-stall")
    def test_duplicate_control_closes_before_queue_execution(self): self.exercise("idle-duplicate")
    def test_stop_during_admission_preflight_returns_stopped(self): self.exercise("idle-preflight-stop")
