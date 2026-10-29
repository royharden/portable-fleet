"""Independent native exit observation before releasing blocked phase storage."""
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from portable_fleet.core import load
from portable_fleet.family import wait_owned_process
from portable_fleet.journal_dispatch import recover_operations
from portable_fleet.permit_guard import recover_state, retain
from portable_fleet.process_time import CreationTime
from portable_fleet.watchdog import WindowsProcess
from family_fixture import Event, environment
from test_permit_guard import directory, uid
from owned_dispatch_fixture import ROLES

OBSERVATIONS = []


class ManagedOwnedDispatch:
    def __init__(self, output, fault, *, fixture_script=None):
        self.output, self.scope, self.fault = output, uid(), fault
        self.events, self.pins = {}, []
        self.process = self.sentinel = self.sentinel_pin = self.memory = None
        try:
            for role in (*ROLES, "sentinel-ready", "sentinel-stop"):
                name = "Local\\PF-owned-" + self.scope + "-" + role
                self.events[role] = Event(name, True)
            self.memory = mmap.mmap(-1, 65536, tagname="Local\\PF-owned-report-" + self.scope)
            family = str(Path(__file__).with_name("family_fixture.py"))
            self.sentinel = subprocess.Popen([sys.executable, "-I", "-B", family, "sentinel", str(output),
                "Local\\PF-owned-" + self.scope + "-sentinel-ready", "Local\\PF-owned-" + self.scope + "-sentinel-stop",
                "120000", "idle"], env=environment(), close_fds=True, creationflags=0x08000000)
            if not self.events["sentinel-ready"].wait(10000): raise AssertionError("Sentinel not ready")
            record = load(output / "sentinel.json")
            self.sentinel_pin = WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"]))
            script = Path(__file__).with_name("owned_dispatch_fixture.py") if fixture_script is None else Path(fixture_script)
            self.process = subprocess.Popen([sys.executable, "-I", "-B", str(script),
                str(output), self.scope, fault], env=environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, creationflags=0x08000000)
            if not self.events["ready"].wait(10000): raise AssertionError("Owned coordinator not ready")
            self.ready = load(output / "fixture-ready.json")
            for record in self.ready["members"]:
                self.pins.append(WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"])))
        except BaseException:
            self.close()
            raise

    def report(self):
        size = int.from_bytes(self.memory[:4], "little")
        if not 0 < size <= 65532: raise AssertionError("Invalid finite memory report")
        return json.loads(self.memory[4:4 + size])

    def work(self):
        result = {}
        for role in ("root", "child", "grandchild"):
            raw = (self.output / (role + ".work")).read_text(encoding="ascii")
            lines = raw[:raw.rfind("\n") + 1].splitlines()
            result[role] = max((int(line.split()[0]) for line in lines if len(line.split()) == 2), default=0)
        return result

    def close(self):
        for role in ("go", "sql-release", "guard-release", "finish", "cancel", "sentinel-stop", "control-trigger", "effect-finished"):
            if role in self.events: self.events[role].set()
        for process in (self.process, self.sentinel):
            if process:
                try: process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.terminate()  # exact owned fixture handle, never filesystem deletion
                    process.wait(timeout=5)
        if self.process:
            self.process.stdout.close()
            self.process.stderr.close()
        for pin in self.pins: pin.close()
        if self.sentinel_pin: self.sentinel_pin.close()
        if self.memory: self.memory.close()
        for event in self.events.values(): event.close()


@unittest.skipUnless(os.name == "nt", "Windows owned phase stop integration")
class OwnedDispatchTests(unittest.TestCase):
    def exercise(self, fault):
        managed = ManagedOwnedDispatch(directory("owned-phase-" + fault), fault)
        blocked = fault in ("accepted", "executing", "outcome", "explicit-cancel", "dual-terminal-stall")
        rejected_activation = fault == "recipient-reject"
        try:
            self.assertEqual(len(managed.pins), 1 if rejected_activation else 6)
            started = time.monotonic()
            managed.events["go"].set()
            if blocked:
                self.assertTrue(managed.events["sql-entered"].wait(3000))
                if fault == "explicit-cancel": managed.events["cancel"].set()
            # Parent independently waits the pre-opened native pins BEFORE reading
            # any child outcome/report or releasing either storage writer.
            deadline = started + 10
            for pin in managed.pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                self.assertFalse(pin.alive())
            observed = time.monotonic()
            self.assertLessEqual(observed, deadline)
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertFalse(managed.events["sql-release"].wait(0))
            self.assertFalse(managed.events["guard-release"].wait(0))
            self.assertTrue(managed.events["complete"].wait(3000))
            before = managed.report()
            family = before["stop"]["family_stop"]
            self.assertTrue(family["all_pinned_ended"])
            self.assertEqual(family["job_stop"]["accounting"]["active"], 0)
            self.assertFalse(before["stop"]["restart_admitted"])
            self.assertTrue(before["recipient"]["closed"])
            self.assertTrue(before["counter"]["closed"])
            expected_counter = 4 if fault in ("outcome", "normal") else 0
            self.assertEqual(before["counter"]["total"], expected_counter)
            if blocked:
                self.assertTrue(before["phase_actor"]["storage_pending"])
                self.assertLessEqual(family["request_to_all_pins_seconds"], 10)
                self.assertEqual(family["enforcement_started_mono"], before["stop"]["operation_started_mono"])
                self.assertGreaterEqual(family["request_to_all_pins_seconds"], .9)
            if fault == "dual-terminal-stall":
                self.assertTrue(managed.events["guard-entered"].wait(0))
                self.assertTrue(before["guard_journal"]["storage_pending"])
                self.assertEqual(before["stop"]["state"], "uncertain")
                self.assertFalse((managed.output / "guard-state/stop.json").exists())
            else:
                self.assertEqual(before["stop"]["state"], "stopped")
                self.assertTrue((managed.output / "guard-state/stop.json").exists())
            if blocked:
                self.assertTrue(before["counter"]["outcome_uncertain"])
            if not rejected_activation:
                work = managed.work()
                if blocked: self.assertTrue(all(count > 0 for count in work.values()))
            else: work = None
            retain(managed.output / "observer-before-release.json", {
                "scope": managed.scope, "pins": managed.ready["members"], "parent_all_pins_ended_before_release": True,
                "parent_trigger_to_exit_observation_seconds": observed - started, "sentinel_survived": True,
                "work": work, "child_volatile_report": before})
            if blocked:
                managed.events["sql-release"].set()
                self.assertTrue(managed.events["sql-finished"].wait(3000))
            if fault == "dual-terminal-stall":
                managed.events["guard-release"].set()
                self.assertTrue(managed.events["guard-finished"].wait(3000))
                self.assertEqual(load(managed.output / "guard-state/terminal.json")["scope"], managed.scope)
            sql_history = recover_operations(managed.output / "operations")
            self.assertFalse(sql_history["restart_admitted"])
            if blocked:
                expected_phase = "accepted" if fault in ("explicit-cancel", "dual-terminal-stall") else fault
                self.assertEqual(sql_history["operations"][0]["state"], expected_phase)
            elif fault == "normal": self.assertEqual(sql_history["operations"][0]["state"], "outcome")
            else: self.assertEqual(sql_history["operations"], [])
            self.assertFalse(recover_state(managed.output / "guard-state")["restart_admitted"])
            managed.events["finish"].set()
            self.assertEqual(managed.process.wait(timeout=10), 0)
            self.assertEqual(managed.process.stdout.read(), b"")
            self.assertEqual(managed.process.stderr.read(), b"")
            after = managed.report()["after_release"]
            self.assertEqual(after["counter"]["total"], expected_counter)
            self.assertTrue(after["dispatch_refused"])
            self.assertTrue(after["receipt_refused"])
            self.assertTrue(after["recipient"]["closed"])
            self.assertFalse(after["restart_admitted"])
            if work is not None: self.assertEqual(managed.work(), work)
            self.assertTrue(managed.sentinel_pin.alive())
            record = {"variant": fault, "pins_observed": len(managed.pins),
                "parent_exit_observation_seconds": observed - started, "all_exits_before_storage_release": True,
                "before_release": before, "after_release": after, "sql_history": sql_history,
                "unchanged_work": work, "sentinel_survived": True,
                "provenance": "parent native pins + volatile child counter; not restored/durable counter"}
            retain(managed.output / "observer-after-release.json", record)
            OBSERVATIONS.append(record)
        finally:
            managed.close()

    def test_accepted_timeout_stops_six_before_storage_release(self): self.exercise("accepted")
    def test_executing_timeout_stops_six_before_storage_release(self): self.exercise("executing")
    def test_outcome_timeout_stops_six_with_uncertain_effect(self): self.exercise("outcome")
    def test_explicit_phase_cancel_stops_six_on_owner_thread(self): self.exercise("explicit-cancel")
    def test_phase_and_guard_terminal_stalls_still_stop_six(self): self.exercise("dual-terminal-stall")
    def test_reply_rejection_after_resume_stops_owned_root(self): self.exercise("recipient-reject")
    def test_terminal_guard_cannot_leave_current_counter_admission(self): self.exercise("guard-closed")
    def test_normal_confirmed_effect_then_explicit_owned_stop(self): self.exercise("normal")
