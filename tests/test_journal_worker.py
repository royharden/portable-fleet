"""No-delete journal actor and actual owned-job storage-stall regressions."""
import os
from pathlib import Path
import threading
import time
import unittest

from portable_fleet.core import Refusal, load
from portable_fleet.journal_worker import BoundedJournal
from portable_fleet.permit_guard import GuardedFamily, PermitState, recover_state, retain
from test_permit_guard import ManagedGuard, directory, observation, packet, uid


OBSERVATIONS = []


class JournalActorTests(unittest.TestCase):
    def test_closed_state_keeps_original_total_stop_deadline(self):
        root, scope = directory("common-deadline"), uid()
        state = PermitState(root, scope, "synthetic-account", 1000, 50)
        state.hold("Unit closure", 1001, 51)
        guard = GuardedFamily.__new__(GuardedFamily)
        guard.state = state
        guard.clock = lambda: (1001, 51)
        remaining = guard._old_lease_remaining()
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 10)
        state.closing_started_mono = time.monotonic() - 10.1
        self.assertLessEqual(guard._old_lease_remaining(), 0)
        attempted = []
        journal = BoundedJournal(lambda path, value: attempted.append(value), remaining=guard._old_lease_remaining)
        try:
            with self.assertRaises(OSError):
                journal.write("must-not-write", {})
            self.assertEqual(attempted, [])
        finally:
            journal.close()

    def test_candidate_invalidated_by_small_clock_step_during_write(self):
        root, scope = directory("candidate-clock"), uid()
        now, shift = [1000, 50], [False]

        def writer(path, value):
            retain(path, value)
            if shift[0] and path.parent.name == "commands":
                now[:] = [1000.25, 50.6]  # old lease still valid; new issued_wall would be in future

        state = PermitState(root, scope, "synthetic-account", *now, writer=writer, commit_clock=lambda: tuple(now))
        state.accept(packet(scope, observation(1000)), *now)
        now[:] = [1000.5, 50.5]
        shift[0] = True
        with self.assertRaises(Refusal) as error:
            state.accept(packet(scope, observation(1000)), *now)
        self.assertIn("Candidate permit invalid", str(error.exception))
        self.assertTrue(state.closed)
        self.assertEqual(state.permit["issued_wall"], 1000)
        self.assertFalse(recover_state(root)["restart_admitted"])

    def test_timeout_latches_failure_and_late_completion_never_clears_it(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        written = []

        def blocked(path, value):
            entered.set()
            release.wait(2)
            written.append(value)
            finished.set()

        journal = BoundedJournal(blocked, timeout=.05)
        try:
            with self.assertRaises(OSError):
                journal.write("retained-mock", {"permit": 1})
            self.assertTrue(entered.is_set())
            self.assertTrue(journal.status()["failed"])
            self.assertTrue(journal.status()["storage_pending"])
            start = time.monotonic()
            with self.assertRaises(OSError):
                journal.write("never-enqueued", {"permit": 2})
            self.assertLess(time.monotonic() - start, .05)
            release.set()
            self.assertTrue(finished.wait(2))
            self.assertEqual(written, [{"permit": 1}])
            self.assertTrue(journal.status()["failed"])
            OBSERVATIONS.append({"variant": "mock-late-storage-completion", "latch_never_cleared": True})
        finally:
            release.set()
            journal.close()

    def test_copy_and_concurrent_submission_fail_closed(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        written, errors = [], []

        def blocked(path, value):
            entered.set()
            release.wait(2)
            written.append(value)
            finished.set()

        journal = BoundedJournal(blocked)
        original = {"nested": {"value": 1}}

        def first():
            try:
                journal.write("one", original)
            except OSError as error:
                errors.append(str(error))

        caller = threading.Thread(target=first)
        caller.start()
        try:
            self.assertTrue(entered.wait(1))
            original["nested"]["value"] = 99
            with self.assertRaises(OSError):
                journal.write("two", {})
            release.set()
            caller.join(timeout=2)
            self.assertFalse(caller.is_alive())
            self.assertTrue(finished.wait(1))
            self.assertTrue(errors)
            self.assertEqual(written, [{"nested": {"value": 1}}])
            self.assertTrue(journal.status()["failed"])
        finally:
            release.set()
            journal.close()
            caller.join(timeout=2)

    def test_completed_write_at_old_lease_deadline_cannot_commit_renewal(self):
        root, scope = directory("old-deadline"), uid()
        now = [1000, 50]
        advance = [False]

        def writer(path, value):
            retain(path, value)
            if advance[0] and path.parent.name == "commands":
                now[:] = [1090, 140]  # complete bytes, but the OLD lease has expired

        state = None

        def remaining():
            if state is None or state.permit is None or state.closed:
                return None
            return min(state.permit["expires_wall"] - now[0], state.permit["expires_mono"] - now[1])

        journal = BoundedJournal(writer, remaining=remaining)
        try:
            state = PermitState(root, scope, "synthetic-account", *now, writer=journal.write, commit_clock=lambda: tuple(now))
            state.accept(packet(scope, observation(1000)), *now)
            now[:] = [1089.5, 139.5]
            advance[0] = True
            with self.assertRaises(OSError):
                state.accept(packet(scope, observation(1000)), *now)
            self.assertTrue(state.closed)
            self.assertEqual(state.permit["expires_wall"], 1090)
            self.assertTrue(journal.status()["failed"])
            self.assertFalse(recover_state(root)["restart_admitted"])
        finally:
            journal.close()

    def test_shutdown_does_not_join_blocked_storage(self):
        entered, release = threading.Event(), threading.Event()

        def blocked(path, value):
            entered.set()
            release.wait(2)

        journal = BoundedJournal(blocked, timeout=.05)
        try:
            with self.assertRaises(OSError):
                journal.write("mock", {})
            self.assertTrue(entered.is_set())
            start = time.monotonic()
            status = journal.close()
            self.assertLess(time.monotonic() - start, .05)
            self.assertTrue(status["closed"])
            self.assertTrue(status["storage_pending"])
            with self.assertRaises(OSError):
                journal.write("mock-after-close", {})
        finally:
            release.set()
            journal.close()


@unittest.skipUnless(os.name == "nt", "Windows owned-family storage stall")
class StorageStallIntegrationTests(unittest.TestCase):
    def exercise(self, fault):
        managed = ManagedGuard(directory(fault), fault)
        try:
            managed.start()
            start = time.monotonic()
            command = packet(managed.scope, managed.original_observation if fault == "renewal-stall" else None)
            managed.send(command)
            self.assertTrue(managed.events["stall-entered"][1].wait(5_000))
            result = managed.stopped(timeout=10, wait_process=False)
            total = result["all_pins_ended_mono"] - start
            self.assertLessEqual(total, 10)
            self.assertEqual(result["state"], "uncertain", result)
            self.assertTrue(result["all_pinned_ended"])
            self.assertEqual(result["pinned_count"], 6)
            self.assertTrue(result["journal"]["failed"])
            self.assertTrue(result["journal"]["storage_pending"])
            self.assertLessEqual(result["enforcement_started_mono"], result["stop_started_mono"])
            self.assertTrue(managed.sentinel_pin.alive())
            stopped_work = managed.work_counts()
            managed.events["stall-release"][1].set()
            self.assertTrue(managed.events["stall-finished"][1].wait(5000))
            history = managed.next(5)
            self.assertEqual(history["event"], "late-storage")
            self.assertTrue(history["closed"])
            self.assertTrue(history["journal"]["failed"])
            self.assertFalse(history["restart_admitted"])
            managed.process.wait(timeout=5)
            self.assertEqual(managed.work_counts(), stopped_work)
            if fault == "renewal-stall":
                late_bytes = load(managed.output / "state/commands" / (command["operation"] + ".json"))
                self.assertEqual(late_bytes["command"], command)
            else:
                late_bytes = load(managed.output / "state/terminal.json")
                self.assertEqual(late_bytes["scope"], managed.scope)
                self.assertFalse(late_bytes["restart_admitted"])
            self.assertFalse(recover_state(managed.output / "state")["restart_admitted"])
            self.assertTrue(managed.sentinel_pin.alive())
            OBSERVATIONS.append({"variant": fault, "request_to_all_pins_seconds_including_storage_wait": total,
                "all_six_pins_ended_before_storage_release": True, "late_completion_reopened": False,
                "sentinel_survived": True, "stop": result, "late_storage": history,
                "late_command_operation": command["operation"], "late_file_bytes_inspected": True,
                "work_counts_after_stop": stopped_work})
        finally:
            managed.events["stall-release"][1].set()
            managed.close()

    def test_stalled_renewal_cannot_hold_job_or_grant_late_permit(self):
        self.exercise("renewal-stall")

    def test_stalled_terminal_write_cannot_delay_stop_duty(self):
        self.exercise("terminal-stall")
