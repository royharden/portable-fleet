"""Retained local permit/job regressions. Blocking messages/deadlines, no status polling."""
import io
import mmap
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from portable_fleet.core import Refusal, load
from portable_fleet.permit_guard import GuardedFamily, PermitState, recover_state, retain
from portable_fleet.process_time import CreationTime
from portable_fleet.watchdog import WindowsProcess
from portable_fleet.family import wait_owned_process
from family_fixture import Event, environment


OBSERVATIONS = []
GUARD = str(Path(__file__).with_name("guard_fixture.py").resolve())
FAMILY = str(Path(__file__).with_name("family_fixture.py").resolve())


def uid():
    return str(uuid.uuid4())


def observation(observed, **changes):
    return {"account": "synthetic-account", "sequence": 1, "observed": observed, "percent_left": 80, "reset": "window", **changes}


def packet(scope, obs, kind="receipt", operation=None):
    return {"schema": 1, "operation": operation or uid(), "scope": scope, "kind": kind, "observation": obs}


def directory(name):
    base = os.environ.get("PF_GUARD_TEST_ROOT")
    if not base:
        raise unittest.SkipTest("Set PF_GUARD_TEST_ROOT to a fresh retained-fixture directory")
    output = Path(base).resolve() / name
    output.mkdir(parents=True, exist_ok=False)
    return output


class PermitStateTests(unittest.TestCase):
    def test_returned_acknowledgment_cannot_mutate_live_or_cached_permit(self):
        root, scope = directory("ack-copy"), uid()
        state = PermitState(root, scope, "synthetic-account", 1000, 50)
        command = packet(scope, observation(1000))
        ack = state.accept(command, 1000, 50)
        ack["permit"]["expires_wall"] = 99999999999
        ack["permit"]["scope"] = uid()
        self.assertEqual(state.permit["expires_wall"], 1090)
        self.assertEqual(state.permit["scope"], scope)
        replay = state.accept(command, 1030, 80)
        self.assertEqual(replay["permit"]["expires_wall"], 1090)
        self.assertEqual(replay["permit"]["scope"], scope)

    def test_recovery_rejects_parseable_cross_scope_records(self):
        root, scope = directory("inconsistent-recovery"), uid()
        state = PermitState(root / "original", scope, "synthetic-account", 1000, 50)
        state.accept(packet(scope, observation(1000)), 1000, 50)
        state.hold("Operator hold", 1001, 51)
        started, terminal = load(state.root / "started.json"), load(state.root / "terminal.json")
        for index, pair in enumerate(((started, {**terminal, "scope": uid()}),
                                      ({**started, "schema": True}, terminal), (started, {"schema": 1}))):
            other = root / str(index)
            retain(other / "started.json", pair[0])
            retain(other / "terminal.json", pair[1])
            recovered = recover_state(other)
            self.assertEqual(recovered["state"], "held-uncertain")
            self.assertTrue(recovered["errors"])
            self.assertFalse(recovered["restart_admitted"])

    def test_replay_does_not_renew_and_same_observation_stays_bounded(self):
        root, scope = directory("replay"), uid()
        state = PermitState(root, scope, "synthetic-account", 1000, 50)
        original = packet(scope, observation(1000))
        first = state.accept(original, 1000, 50)
        repeated = state.accept(original, 1030, 80)
        self.assertTrue(state.replayed)
        self.assertEqual(first, repeated)
        self.assertEqual(state.permit["expires_wall"], 1090)
        for offset in range(30, 300, 30):
            state.accept(packet(scope, observation(1000)), 1000 + offset, 50 + offset)
            self.assertLessEqual(state.permit["expires_wall"], 1300)
            self.assertEqual(state.permit["observation_deadline"], 1300)
        with self.assertRaises(Refusal):
            state.accept(packet(scope, observation(1300, sequence=2)), 1300, 350)
        self.assertTrue(state.closed)
        self.assertTrue(state.terminal_persisted)
        self.assertFalse(recover_state(root)["restart_admitted"])

    def test_invalid_inputs_close_and_cannot_reopen(self):
        base = directory("invalid-inputs")
        for index, change in enumerate(("account", "zero", "reset", "parse", "schema", "scope", "nan", "changed-id", "foreign-permit")):
            scope = uid()
            state = PermitState(base / str(index), scope, "synthetic-account", 1000, 50)
            original = packet(scope, observation(1000))
            state.accept(original, 1000, 50)
            bad = packet(scope, observation(1001, sequence=2))
            if change == "account": bad["observation"]["account"] = "other"
            if change == "zero": bad["observation"]["percent_left"] = 0
            if change == "reset": bad["observation"]["reset"] = "unexpected"
            if change == "parse": bad["observation"] = None
            if change == "schema": bad["schema"] = True
            if change == "scope": bad["scope"] = uid()
            if change == "nan": bad["observation"]["observed"] = float("nan")
            if change == "changed-id": bad["operation"] = original["operation"]
            if change == "foreign-permit": bad["permit"] = {"expires_wall": 99999999999}
            with self.subTest(case=change), self.assertRaises((Refusal, ValueError, TypeError)):
                state.accept(bad, 1001, 51)
            self.assertTrue(state.closed)
            with self.assertRaises(Refusal):
                state.accept(packet(scope, observation(1002, sequence=3)), 1002, 52)

    def test_clock_discontinuity_and_suspend_are_checked_before_new_grants(self):
        base = directory("clocks")
        for index, clocks in enumerate(((999, 51), (1001, 49), (1400, 450), (1400, 51), (float("nan"), 51))):
            scope = uid()
            state = PermitState(base / str(index), scope, "synthetic-account", 1000, 50)
            state.accept(packet(scope, observation(1000)), 1000, 50)
            with self.subTest(clocks=clocks), self.assertRaises(Refusal):
                state.accept(packet(scope, observation(clocks[0], sequence=2)), *clocks)
            self.assertTrue(state.closed)

    def test_existing_or_partial_state_blocks_launch_before_process_creation(self):
        root, scope = directory("recovery"), uid()
        state = PermitState(root, scope, "synthetic-account", 1000, 50)
        with patch("portable_fleet.permit_guard.OwnedFamily") as factory:
            with self.assertRaises(Refusal):
                GuardedFamily([sys.executable], str(root), environment(), root, uid(), "synthetic-account")
            factory.assert_not_called()
        with (root / "terminal.json").open("x", encoding="utf-8") as handle:
            handle.write('{"partial":')
        recovered = recover_state(root)
        self.assertEqual(recovered["state"], "held-uncertain")
        self.assertFalse(recovered["restart_admitted"])


class ManagedGuard:
    def __init__(self, output, fault="none", lifetime_ms=120000, maximum_runtime=115, *, pause_output=False, expect_waiting=True):
        self.process = self.sentinel = self.sentinel_pin = None
        self.report_memory = None
        self.events = {}
        self.reader_release = threading.Event()
        self.reader_paused = threading.Event()
        self.pause_output, self.expect_waiting = pause_output, expect_waiting
        try:
            self._start(output, fault, lifetime_ms, maximum_runtime)
        except BaseException:
            self.close()
            raise

    def _start(self, output, fault, lifetime_ms, maximum_runtime):
        self.output, self.scope, self.messages = output, uid(), []
        prefix = "Local\\PF-guard-" + uid()
        for role in ("ready", "stop", "sentinel-ready", "sentinel-stop", "crash", "stall-entered", "stall-release", "stall-finished",
                     "storage-entered", "storage-release", "storage-finished"):
            self.events[role] = (prefix + "-" + role, Event(prefix + "-" + role, True))
        self.sentinel = subprocess.Popen([sys.executable, "-I", "-B", FAMILY, "sentinel", str(output),
            self.events["sentinel-ready"][0], self.events["sentinel-stop"][0], str(lifetime_ms), "idle"],
            env=environment(), close_fds=True, creationflags=0x08000000)
        if not self.events["sentinel-ready"][1].wait(10000):
            raise Refusal("Sentinel readiness deadline")
        record = load(output / "sentinel.json")
        self.sentinel_pin = WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"]))
        self.argv = [sys.executable, "-I", "-B", GUARD, str(output), self.scope,
                     self.events["ready"][0], self.events["stop"][0], fault, self.events["crash"][0],
                     str(lifetime_ms), str(maximum_runtime), self.events["stall-entered"][0],
                     self.events["stall-release"][0], self.events["stall-finished"][0]]
        if fault.startswith("combined-"):
            self.report_memory = mmap.mmap(-1, 65536, tagname="Local\\PF-guard-report-" + self.scope)
            self.argv.extend(self.events[role][0] for role in ("storage-entered", "storage-release", "storage-finished"))
        self.process = subprocess.Popen(self.argv, env=environment(), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, creationflags=0x08000000)
        self.incoming = queue.Queue()

        def read():
            try:
                frames = 0
                for raw in iter(lambda: self.process.stdout.readline(65537), b""):
                    self.incoming.put(json.loads(raw))
                    frames += 1
                    if self.pause_output and frames == 3:
                        self.reader_paused.set()
                        self.reader_release.wait(20000 / 1000)
            except Exception as error:
                self.incoming.put({"event": "reader-error", "error": str(error)})
            self.incoming.put({"event": "eof"})

        threading.Thread(target=read, daemon=True).start()
        if self.expect_waiting:
            message = self.next(10)
            if message.get("event") != "waiting":
                raise Refusal("Guard did not reach suspended waiting state: " + str(message))

    def next(self, timeout):
        message = self.incoming.get(timeout=timeout)
        self.messages.append(message)
        return message

    def send(self, command):
        self.process.stdin.write(json.dumps(command).encode() + b"\n")
        self.process.stdin.flush()

    def start(self, observed=None):
        self.original_observation = observation(time.time() if observed is None else observed)
        self.send(packet(self.scope, self.original_observation))
        ack = self.next(10)
        if ack.get("state") != "active":
            raise Refusal("Initial permit refused: " + str(ack))
        if not self.events["ready"][1].wait(10000):
            raise Refusal("Admitted family readiness deadline")
        self.send(packet(self.scope, None, "inspect"))
        ack = self.next(10)
        if ack.get("state") != "active":
            raise Refusal("Snapshot refused: " + str(ack))
        members = load(self.output / "state/members.json")["members"]
        if len(members) != 6:
            raise Refusal("Unexpected job member count: " + str(members))
        self.initial_work = self.work_counts()

    def work_counts(self):
        result = {}
        for role in ("root", "child", "grandchild"):
            raw = (self.output / (role + ".work")).read_text(encoding="ascii")
            complete = raw[:raw.rfind("\n") + 1].splitlines()
            result[role] = max((int(line.split()[0]) for line in complete if len(line.split()) == 2), default=0)
        return result

    def stopped(self, timeout=105, wait_process=True):
        deadline = time.monotonic() + timeout
        while True:  # consume finite response stream, not readiness/status polling
            result = self.next(max(.001, deadline - time.monotonic()))
            if result.get("state") in ("stopped", "uncertain"):
                if wait_process:
                    self.process.wait(timeout=10)
                return result
            if result.get("event") in ("refused", "reader-error", "eof"):
                raise Refusal("Guard ended without stop receipt: " + str(result))

    def close(self):
        self.reader_release.set()
        for role in ("stall-release", "storage-release"):
            if role in self.events:
                self.events[role][1].set()
        try:
            if self.process:
                if not self.process.stdin.closed:
                    self.process.stdin.close()
                try:
                    self.process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    self.process.terminate()  # exact owned retained handle, never a file deletion
                    self.process.wait(timeout=5)
        finally:
            for role in ("stop", "sentinel-stop", "crash", "stall-release"):
                if role in self.events:
                    self.events[role][1].set()
            if self.sentinel:
                try:
                    self.sentinel.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    self.sentinel.terminate()
                    self.sentinel.wait(timeout=5)
            if self.sentinel_pin:
                self.sentinel_pin.close()
            for _, event in self.events.values():
                event.close()
            if self.process:
                self.process.stdout.close()
                self.process.stderr.close()
            if self.report_memory:
                self.report_memory.close()


@unittest.skipUnless(os.name == "nt", "Windows guard/job integration")
class GuardIntegrationTests(unittest.TestCase):
    def verify_stop(self, managed, result, expected="stopped"):
        self.assertEqual(result["state"], expected, result)
        self.assertTrue(result["all_pinned_ended"])
        self.assertEqual(result["pinned_count"], 6)
        self.assertTrue(managed.sentinel_pin.alive())
        self.assertFalse(recover_state(managed.output / "state")["restart_admitted"])

    def test_missing_initial_permit_never_resumes(self):
        managed = ManagedGuard(directory("no-initial"))
        try:
            result = managed.stopped(timeout=15)
            self.assertEqual(result["state"], "stopped", result)
            self.assertFalse((managed.output / "root.json").exists())
            self.assertTrue(managed.sentinel_pin.alive())
            OBSERVATIONS.append({"variant": "missing-initial-permit", "result": result, "root_executed": False})
        finally:
            managed.close()

    def test_invalid_receipt_stops_and_saved_state_cannot_restart(self):
        managed = ManagedGuard(directory("invalid-stop"))
        try:
            managed.start()
            managed.send(packet(managed.scope, None))
            result = managed.stopped()
            self.verify_stop(managed, result)
            original_launch = (managed.output / "state/launch.json").read_bytes()
            reopened = subprocess.run(managed.argv, env=environment(), input=b"", capture_output=True, timeout=15, creationflags=0x08000000)
            self.assertEqual(reopened.returncode, 2)
            self.assertIn(b'restart_admitted', reopened.stdout)
            self.assertEqual((managed.output / "state/launch.json").read_bytes(), original_launch)
            OBSERVATIONS.append({"variant": "invalid-source-and-recovery-hold", "result": result, "restart_process_exit": 2})
        finally:
            managed.close()

    def test_parser_recursion_failure_stops_without_silent_lease_wait(self):
        managed = ManagedGuard(directory("parser-depth"))
        try:
            managed.start()
            start = time.monotonic()
            managed.process.stdin.write(b"[" * 2000 + b"0" + b"]" * 2000 + b"\n")
            managed.process.stdin.flush()
            result = managed.stopped(timeout=10)
            self.verify_stop(managed, result)
            self.assertLessEqual(result["all_pins_ended_mono"] - start, 10)
            self.assertIn("parse failure", result["reason"])
            OBSERVATIONS.append({"variant": "bounded-frame-recursion-refusal", "result": result})
        finally:
            managed.close()

    def test_terminal_write_failure_still_stops_but_stays_uncertain(self):
        managed = ManagedGuard(directory("terminal-write-failure"), "terminal-write-fail")
        try:
            managed.start()
            managed.send(packet(managed.scope, None))
            result = managed.stopped()
            self.verify_stop(managed, result, "uncertain")
            self.assertTrue(any("terminal" in item for item in result["errors"]))
            self.assertEqual(recover_state(managed.output / "state")["state"], "held-uncertain")
            OBSERVATIONS.append({"variant": "injected-terminal-write-failure", "result": result})
        finally:
            managed.close()

    def test_producer_transport_loss_stops_without_waiting_for_expiry(self):
        managed = ManagedGuard(directory("producer-loss"))
        try:
            managed.start()
            managed.process.stdin.close()
            result = managed.stopped()
            self.verify_stop(managed, result)
            self.assertIn("input lost", result["reason"])
            OBSERVATIONS.append({"variant": "producer-transport-loss", "result": result})
        finally:
            managed.close()

    def test_guard_death_stops_owned_job_and_recovery_stays_held(self):
        managed = ManagedGuard(directory("guard-death"), "guard-crash")
        pins = []
        try:
            managed.start()
            members = load(managed.output / "state/members.json")["members"]
            pins = [WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"])) for record in members]
            start = time.monotonic()
            managed.events["crash"][1].set()
            self.assertEqual(managed.process.wait(timeout=5), 73)
            deadline = start + 10
            for pin in pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                self.assertFalse(pin.alive())
            self.assertTrue(managed.sentinel_pin.alive())
            recovery = recover_state(managed.output / "state")
            self.assertEqual(recovery["state"], "held-uncertain")
            self.assertFalse(recovery["restart_admitted"])
            OBSERVATIONS.append({"variant": "actual-guard-owner-death", "guard_exit": 73,
                "pinned_members_ended": len(pins), "trigger_to_all_pins_seconds": time.monotonic() - start,
                "sentinel_survived": True, "recovery": recovery})
        finally:
            for pin in pins:
                pin.close()
            managed.close()

    def test_real_silent_supervision_deadline_and_clipped_stale_observation(self):
        silent = ManagedGuard(directory("silent-90s"))
        stale = ManagedGuard(directory("preaged-observation-60s"))
        timer = None
        renewal_errors = []
        try:
            silent.start()
            stale.start(observed=time.time() - 240)

            def renew_original():
                try:
                    stale.send(packet(stale.scope, stale.original_observation))
                except Exception as error:
                    renewal_errors.append(str(error))

            timer = threading.Timer(30, renew_original)  # one scheduled internal renewal, no poll
            timer.start()
            silent_result = silent.stopped(timeout=105)
            stale_result = stale.stopped(timeout=15)
            self.verify_stop(silent, silent_result)
            self.verify_stop(stale, stale_result)
            self.assertFalse(renewal_errors)
            elapsed = silent_result["all_pins_ended_mono"] - silent_result["last_permit"]["issued_mono"]
            self.assertGreaterEqual(elapsed, 89.8)
            self.assertLessEqual(elapsed, 100)
            stale_age = stale_result["all_pins_ended_wall"] - stale.original_observation["observed"]
            self.assertGreaterEqual(stale_age, 299.8)
            self.assertLessEqual(stale_age, 310)
            self.assertEqual(stale_result["last_permit"]["observation_deadline"], stale.original_observation["observed"] + 300)
            self.assertGreater(stale_result["last_permit"]["issued_wall"], stale.original_observation["observed"] + 260)
            final_work = {"silent": silent.work_counts(), "stale": stale.work_counts()}
            self.assertTrue(all(final_work["silent"][role] > silent.initial_work[role] + 100 for role in final_work["silent"]))
            self.assertTrue(all(final_work["stale"][role] > stale.initial_work[role] + 100 for role in final_work["stale"]))
            OBSERVATIONS.append({"variant": "actual-90s-silent-supervision", "receipt_to_all_pins_seconds": elapsed,
                                 "result": silent_result, "work_counts": final_work["silent"]})
            OBSERVATIONS.append({"variant": "synthetic-observation-preaged-240s", "source_age_at_all_pins_end": stale_age,
                "actual_test_wait_about_seconds": 60, "full_300s_fresh_source_trial": False,
                "result": stale_result, "work_counts": final_work["stale"]})
        finally:
            if timer:
                timer.cancel()
                timer.join(timeout=5)
            silent.close()
            stale.close()
