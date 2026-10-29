"""Physical pins vs uncertain stop/fallback/cleanup outcomes; retained artifacts."""
import os
from pathlib import Path
import time
import unittest

from portable_fleet.core import load
from portable_fleet.family import wait_owned_process
from portable_fleet.journal_dispatch import recover_operations
from portable_fleet.permit_guard import recover_state, retain
from test_owned_dispatch import ManagedOwnedDispatch
from test_permit_guard import directory

OBSERVATIONS = []


@unittest.skipUnless(os.name == "nt", "Windows owned fallback exception fixtures")
class StopFaultTests(unittest.TestCase):
    def exercise(self, fault):
        managed = ManagedOwnedDispatch(directory("stop-fault-" + fault), fault,
            fixture_script=Path(__file__).with_name("stop_fault_fixture.py"))
        both_failed = fault == "both-before"
        try:
            self.assertEqual(len(managed.pins), 6)
            started = time.monotonic()
            managed.events["go"].set()
            if both_failed:
                self.assertTrue(managed.events["complete"].wait(3000))
                before = managed.report()
                self.assertTrue(all(pin.alive() for pin in managed.pins))
                self.assertTrue(before["job_handle_retained"])
            else:
                deadline = started + 10
                for pin in managed.pins:
                    self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                    self.assertFalse(pin.alive())
                self.assertTrue(managed.events["complete"].wait(3000))
                before = managed.report()
            initial_observed = time.monotonic()
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertTrue(before["same_latched_report"])
            self.assertEqual(before["counter"]["total"], 0)
            self.assertEqual(before["counter"]["effects"], [])
            self.assertTrue(before["recipient"]["closed"])
            stop = before["stop"]
            if fault.startswith("cleanup-"):
                self.assertEqual(stop["state"], "stopped")
                self.assertTrue(stop["family_stop"]["all_pinned_ended"])
            else:
                self.assertEqual(stop["state"], "uncertain")
                self.assertIsNone(stop["family_stop"])
                self.assertTrue(any("owned stop:" in error for error in stop["errors"]))
                self.assertEqual(before["calls_before_cleanup"]["primary"], 1)
                if fault in ("fallback-after", "both-before"):
                    self.assertTrue(any("owned handle fallback:" in error for error in stop["errors"]))
                if fault == "stop-after": self.assertEqual(load(managed.output / "guard-state/stop.json")["state"], "stopped")
            self.assertFalse(stop["restart_admitted"])
            work_before_finish = managed.work()
            retain(managed.output / "fault-before-owner-release.json", {
                "fault": fault, "scope": managed.scope, "pins": managed.ready["members"],
                "physical_state": "six-still-alive" if both_failed else "six-ended",
                "fault_to_initial_observation_seconds": initial_observed - started,
                "sentinel_survived": True, "work": work_before_finish, "child_report": before})
            owner_release = time.monotonic()
            managed.events["finish"].set()
            expected_exit = 70 if both_failed else 0
            self.assertEqual(managed.process.wait(timeout=10), expected_exit)
            deadline = owner_release + 10
            for pin in managed.pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                self.assertFalse(pin.alive())
            ended = time.monotonic()
            after = managed.report()
            self.assertEqual(managed.process.stdout.read(), b"")
            self.assertEqual(managed.process.stderr.read(), b"")
            self.assertEqual(after["cleanup_order"], ["journal", "guard"])
            self.assertTrue(after["same_report_after_cleanup"])
            self.assertEqual(after["final_stop"], stop)
            self.assertEqual(after["counter_after"]["total"], 0)
            self.assertTrue(after["recipient_after"]["closed"])
            self.assertFalse(after["restart_admitted"])
            should_close_fail = both_failed or fault.startswith("cleanup-")
            self.assertEqual(after["close_confirmed"], not should_close_fail)
            self.assertEqual(bool(after["cleanup_errors"]), should_close_fail)
            if both_failed: self.assertTrue(after["job_handle_after_cleanup"])
            if not both_failed: self.assertEqual(managed.work(), work_before_finish)
            self.assertTrue(managed.sentinel_pin.alive())
            history = recover_operations(managed.output / "operations")
            self.assertEqual(history["operations"], [])
            self.assertFalse(history["restart_admitted"])
            self.assertFalse(recover_state(managed.output / "guard-state")["restart_admitted"])
            final = load(managed.output / "fixture-final.json")
            self.assertEqual(final["final_stop"], stop)
            record = {"variant": fault, "initial_physical_state": "six-still-alive" if both_failed else "six-ended",
                "exit_proof_phase": "after-owner-process-death" if both_failed else "before-owner-release",
                "initial_observation_seconds": initial_observed - started, "owner_release_to_exit_observation_seconds": ended - owner_release,
                "before": before, "after": after, "sentinel_survived": True, "final_all_six_ended": True,
                "sql_history": history, "provenance": "parent native pins; exceptions/cleanup uncertainty distinct from physical exit"}
            retain(managed.output / "fault-after-owner-release.json", record)
            OBSERVATIONS.append(record)
        finally: managed.close()

    def test_primary_exception_before_action_uses_kill_on_close(self): self.exercise("stop-before")
    def test_primary_exception_after_completion_stays_uncertain(self): self.exercise("stop-after")
    def test_fallback_exception_after_close_never_fabricates_receipt(self): self.exercise("fallback-after")
    def test_both_actions_fail_only_owner_death_proves_exit(self): self.exercise("both-before")
    def test_journal_cleanup_failure_still_attempts_guard(self): self.exercise("cleanup-journal")
    def test_guard_cleanup_failure_preserves_journal_attempt(self): self.exercise("cleanup-guard")
