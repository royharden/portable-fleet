"""Two-sink failure evidence uses volatile memory and independently pinned exits.

No child journal bypass, transport retry, filesystem cleanup or remote admission.
"""
import json
import os
import subprocess
import time
import unittest

from portable_fleet.core import load
from portable_fleet.family import wait_owned_process
from portable_fleet.permit_guard import recover_state, retain
from portable_fleet.process_time import CreationTime
from portable_fleet.watchdog import WindowsProcess
from family_fixture import environment
from test_permit_guard import ManagedGuard, directory, packet

OBSERVATIONS = []


def read_memory(managed):
    size = int.from_bytes(managed.report_memory[:4], "little")
    if not 0 < size <= 65532:
        raise AssertionError("Invalid bounded test memory report")
    return json.loads(managed.report_memory[4:4 + size])


@unittest.skipUnless(os.name == "nt", "Windows owned-family combined failure")
class CombinedFailureTests(unittest.TestCase):
    def exercise(self, fault, stalled):
        managed = ManagedGuard(directory(fault), fault, pause_output=True)
        pins = []
        try:
            managed.start()
            self.assertTrue(managed.reader_paused.wait(2))
            members = load(managed.output / "state/members.json")["members"]
            pins = [WindowsProcess(row["pid"], CreationTime.from_record(row["creationTime"])) for row in members]
            self.assertEqual(len(pins), 6)
            command = packet(managed.scope, managed.original_observation)
            started = time.monotonic()
            managed.send(command)
            self.assertTrue(managed.events["stall-entered"][1].wait(3000))
            self.assertTrue(managed.events["storage-entered"][1].wait(3000))
            deadline = started + 10
            for pin in pins:  # no report or journal trusted as process-exit evidence
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
                self.assertFalse(pin.alive())
            observed = time.monotonic()
            self.assertLessEqual(observed, deadline)
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertFalse(managed.reader_release.is_set())
            self.assertTrue(managed.events["stall-finished"][1].wait(3000))
            report = read_memory(managed)  # volatile child report, not durable child confirmation
            self.assertEqual(report["scope"], managed.scope)
            self.assertFalse(report["diagnostic_persisted"])
            self.assertTrue(report["diagnostic_error"])
            self.assertEqual(report["stop"]["state"], "uncertain")
            self.assertTrue(report["stop"]["all_pinned_ended"])
            self.assertEqual(report["stop"]["pinned_count"], 6)
            self.assertTrue(report["output"]["failed"])
            self.assertTrue(report["output"]["output_pending"])
            self.assertTrue(report["journal"]["failed"])
            self.assertEqual(report["journal"]["storage_pending"], stalled)
            self.assertGreaterEqual(report["stop"]["request_to_all_pins_seconds"], 1.9 if stalled else .9)
            self.assertLessEqual(report["stop"]["request_to_all_pins_seconds"], 10)
            self.assertTrue(any("terminal persistence" in error for error in report["stop"]["errors"]))
            self.assertTrue(any("stop receipt persistence" in error for error in report["stop"]["errors"]))
            for name in ("terminal.json", "stop.json", "output-failure.json"):
                self.assertFalse((managed.output / "state" / name).exists())
            before = recover_state(managed.output / "state")
            self.assertEqual(before["state"], "held-uncertain")
            self.assertFalse(before["restart_admitted"])
            counts = managed.work_counts()
            observer = {"schema": 1, "scope": managed.scope, "provenance": "parent-observed exits plus volatile child report; not child durability",
                "pins": members, "all_six_exits_before_release_or_drain": True,
                "trigger_to_six_exit_observation": observed - started, "sentinel_survived": True,
                "work": counts, "child_report": report, "recovery": before}
            retain(managed.output / "observer-before-release.json", observer)
            if stalled:
                managed.events["storage-release"][1].set()
            self.assertTrue(managed.events["storage-finished"][1].wait(3000))
            if stalled:
                late_terminal = load(managed.output / "state/terminal.json")
                self.assertEqual(late_terminal["scope"], managed.scope)
                self.assertEqual(late_terminal["permit"], report["stop"]["last_permit"])
                self.assertFalse(late_terminal["restart_admitted"])
            managed.reader_release.set()  # output releases only after independent exits + storage observation
            late_ack = managed.next(5)
            self.assertEqual(late_ack["operation"], command["operation"])
            self.assertEqual(late_ack["state"], "active")  # historical active bytes, not current permission
            managed.events["stall-release"][1].set()
            self.assertEqual(managed.process.wait(timeout=5), 3)
            after = read_memory(managed)["after_release"]
            self.assertTrue(after["closed"])
            self.assertTrue(after["same_terminal_result"])
            self.assertFalse(after["terminal_persisted"])
            self.assertTrue(after["journal"]["failed"])
            self.assertTrue(after["output"]["failed"])
            self.assertFalse(after["restart_admitted"])
            self.assertEqual(managed.work_counts(), counts)
            self.assertEqual(managed.process.stderr.read(), b"")
            recovery = recover_state(managed.output / "state")
            self.assertFalse(recovery["restart_admitted"])
            self.assertFalse((managed.output / "state/stop.json").exists())
            self.assertFalse((managed.output / "state/output-failure.json").exists())
            claim = (managed.output / "state/started.json").read_bytes()
            launch = (managed.output / "state/launch.json").read_bytes()
            reopened = subprocess.run(managed.argv, input=b"", env=environment(), capture_output=True,
                                      timeout=10, creationflags=0x08000000)
            self.assertEqual(reopened.returncode, 2)
            self.assertIn(b'restart_admitted', reopened.stdout)
            self.assertEqual((managed.output / "state/started.json").read_bytes(), claim)
            self.assertEqual((managed.output / "state/launch.json").read_bytes(), launch)
            self.assertEqual(managed.work_counts(), counts)
            self.assertTrue(managed.sentinel_pin.alive())
            final = {"schema": 1, "scope": managed.scope, "provenance": observer["provenance"],
                "after_release": after, "recovery": recovery, "unchanged_work": counts,
                "reopen_refused_exit": reopened.returncode, "restart_admitted": False}
            retain(managed.output / "observer-after-release.json", final)
            OBSERVATIONS.append({"variant": fault, "before_release": observer, "after_release": final})
        finally:
            for pin in pins:
                pin.close()
            managed.close()

    def test_blocked_output_and_terminal_failure_stop_without_diagnostics(self):
        self.exercise("combined-pipe-terminal-fail", False)

    def test_blocked_output_and_terminal_stall_stop_before_either_release(self):
        self.exercise("combined-pipe-terminal-stall", True)
