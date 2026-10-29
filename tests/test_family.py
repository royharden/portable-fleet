"""Bounded retained fixtures: one-shot kernel waits, no file cleanup or status polling."""
import ctypes
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

from portable_fleet.core import Refusal
from portable_fleet import family as native
from portable_fleet.family import OwnedFamily, wait_owned_process
from portable_fleet.process_time import CreationTime
from portable_fleet.watchdog import WindowsProcess
from family_fixture import Event, environment, capture_members, write


OBSERVATIONS = []
FIXTURE = str(Path(__file__).with_name("family_fixture.py").resolve())


@unittest.skipUnless(os.name == "nt", "Windows Job Object integration")
class FamilyTests(unittest.TestCase):
    def directory(self, name):
        base = os.environ.get("PF_FAMILY_TEST_ROOT")
        if not base:
            self.skipTest("Set PF_FAMILY_TEST_ROOT to a new retained fixture directory")
        output = Path(base).resolve() / name
        output.mkdir(parents=True, exist_ok=False)
        return output

    def events(self, *roles):
        prefix = "Local\\PF-" + str(uuid.uuid4())
        return {role: (prefix + "-" + role, Event(prefix + "-" + role, True)) for role in roles}

    def pins(self, output):
        records, pins = [], []
        for role in ("root", "child", "grandchild"):
            record = json.loads((output / (role + ".json")).read_text())
            records.append(record)
            pins.append(WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"])))
        self.assertEqual(records[1]["parent"], records[0]["pid"])
        self.assertEqual(records[2]["parent"], records[1]["pid"])
        return records, pins

    def assert_ended(self, pins, seconds=5):
        deadline = time.monotonic() + seconds
        for pin in pins:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            self.assertTrue(wait_owned_process(pin, remaining), "Pinned process did not signal within total deadline")
            self.assertFalse(pin.alive())

    def assert_member_scope(self, output, records, job_members):
        write(output / "observed-job-members.json", job_members)
        expected = {record["pid"] for record in records}
        self.assertTrue(expected.issubset({record["pid"] for record in job_members}))
        allowed_helper = str(Path(os.environ["SystemRoot"]) / "System32/conhost.exe").casefold()
        for member in job_members:
            if member["pid"] not in expected:
                self.assertEqual(member["image"].casefold(), allowed_helper, job_members)

    def sentinel(self, output, events):
        sentinel = subprocess.Popen([sys.executable, "-I", "-B", FIXTURE, "sentinel", str(output),
                    events["sentinel-ready"][0], events["sentinel-stop"][0]],
                    env=environment(), close_fds=True, creationflags=0x08000000)
        self.assertTrue(events["sentinel-ready"][1].wait(10000))
        record = json.loads((output / "sentinel.json").read_text())
        return sentinel, WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"]))

    def test_atomic_admission_and_explicit_family_stop(self):
        output = self.directory("explicit-stop")
        events = self.events("ready", "stop", "sentinel-ready", "sentinel-stop")
        family = sentinel = sentinel_pin = None
        pins = []
        try:
            sentinel, sentinel_pin = self.sentinel(output, events)
            scope = str(uuid.uuid4())
            argv = [sys.executable, "-I", "-B", FIXTURE, "root", str(output), events["ready"][0], events["stop"][0]]
            family = OwnedFamily(argv, str(output), environment(), scope)
            policy = family.policy()
            self.assertFalse((output / "root.json").exists(), "Suspended root executed before resume")
            with self.assertRaises(Refusal):
                family.stop(str(uuid.uuid4()))
            self.assertEqual(family.accounting()["active"], 1)
            family.resume()
            self.assertTrue(events["ready"][1].wait(10000))
            records, pins = self.pins(output)
            breakaway = json.loads((output / "breakaway.json").read_text())
            self.assertEqual(breakaway, {"refused": True, "winerror": 5})
            self.assertEqual(records[0]["pid"], family.pid)
            self.assertEqual(records[0]["parent"], os.getpid())
            self.assertTrue(all(family.contains(pin) for pin in pins))
            self.assertFalse(family.contains(sentinel_pin))
            job_members, all_pins = capture_members(family)
            for pin in pins:
                pin.close()
            pins = all_pins
            self.assert_member_scope(output, records, job_members)
            self.assertEqual(family.accounting()["active"], len(job_members), job_members)
            stop_started = time.monotonic()
            stopped = family.stop(scope)
            self.assert_ended(pins)
            all_pins_elapsed = time.monotonic() - stop_started
            self.assertTrue(sentinel_pin.alive())
            events["sentinel-stop"][1].set()
            self.assertEqual(sentinel.wait(timeout=5), 0)
            OBSERVATIONS.append({"variant": "explicit-job-stop", "members": records, "stop": stopped,
                "sentinel_pid": sentinel.pid, "sentinel_survived": True, "exact_membership_verified": True,
                "policy": policy, "explicit_breakaway": breakaway, "job_members": job_members,
                "request_to_all_pins_ended_seconds": all_pins_elapsed})
        finally:
            if family:
                family.close()
            for pin in pins:
                pin.close()
            if sentinel_pin:
                sentinel_pin.close()
            events["sentinel-stop"][1].set()
            if sentinel:
                sentinel.wait(timeout=25)
            for _, event in events.values():
                event.close()

    def test_launcher_crash_closes_last_job_handle(self):
        output = self.directory("launcher-crash")
        events = self.events("ready", "stop", "crash", "verified", "sentinel-ready", "sentinel-stop")
        launcher = sentinel = sentinel_pin = None
        pins = []
        try:
            sentinel, sentinel_pin = self.sentinel(output, events)
            scope = str(uuid.uuid4())
            launcher = subprocess.Popen([sys.executable, "-I", "-B", FIXTURE, "launcher", str(output),
                 events["ready"][0], events["stop"][0], events["crash"][0], events["verified"][0], scope],
                 env=environment(), close_fds=True, creationflags=0x08000000)
            self.assertTrue(events["verified"][1].wait(10000))
            records, pins = self.pins(output)
            self.assertEqual(records[0]["parent"], launcher.pid)
            membership = json.loads((output / "membership.json").read_text())
            job_members = membership["job_members"]
            for pin in pins:
                pin.close()
            pins = [WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"])) for record in job_members]
            self.assert_member_scope(output, records, job_members)
            self.assertEqual(membership["accounting"]["active"], len(job_members))
            breakaway = json.loads((output / "breakaway.json").read_text())
            self.assertEqual(breakaway, {"refused": True, "winerror": 5})
            start = time.monotonic()
            events["crash"][1].set()
            self.assertEqual(launcher.wait(timeout=5), 71)
            self.assert_ended(pins)
            all_pins_elapsed = time.monotonic() - start
            self.assertTrue(sentinel_pin.alive())
            events["sentinel-stop"][1].set()
            self.assertEqual(sentinel.wait(timeout=5), 0)
            OBSERVATIONS.append({"variant": "launcher-death-kill-on-close", "members": records,
                "launcher_pid": launcher.pid, "launcher_exit": 71, "request_to_all_pins_ended_seconds": all_pins_elapsed,
                "sentinel_pid": sentinel.pid, "sentinel_survived": True, "membership_receipt": membership,
                "explicit_breakaway": breakaway})
        finally:
            events["stop"][1].set()
            events["crash"][1].set()
            if launcher:
                launcher.wait(timeout=25)
            for pin in pins:
                pin.close()
            if sentinel_pin:
                sentinel_pin.close()
            events["sentinel-stop"][1].set()
            if sentinel:
                sentinel.wait(timeout=25)
            for _, event in events.values():
                event.close()

    def test_job_list_failure_has_no_create_process_fallback(self):
        output = self.directory("job-list-failure")
        real = native._api()

        class RefusedAttributes:
            created = 0

            def __getattr__(self, name):
                return getattr(real, name)

            def UpdateProcThreadAttribute(self, *args):
                ctypes.set_last_error(50)
                return False

            def CreateProcessW(self, *args):
                self.created += 1
                raise AssertionError("Process creation reached after rejected JOB_LIST")

        proxy = RefusedAttributes()
        with patch.object(native, "_api", return_value=proxy):
            with self.assertRaises(Refusal):
                OwnedFamily([sys.executable, "-I", "-B", "-c", "raise SystemExit(99)"], str(output), environment(), str(uuid.uuid4()))
        self.assertEqual(proxy.created, 0)
        OBSERVATIONS.append({"variant": "fault-injected-job-list-refusal", "create_process_calls": 0})

    def test_cleanup_failure_attempts_remaining_handles(self):
        class FaultAPI:
            fail = True

            def __init__(self):
                self.calls = []

            def CloseHandle(self, handle):
                self.calls.append(handle)
                return not (self.fail and handle == 11)

        owned = OwnedFamily.__new__(OwnedFamily)
        owned.job, owned.thread, owned.process, owned.port = 11, 12, 13, 14
        owned.api = FaultAPI()
        with self.assertRaises(Refusal):
            owned.close()
        self.assertEqual(owned.api.calls, [11, 12, 13, 14])
        self.assertEqual(owned.job, 11)
        self.assertTrue(all(getattr(owned, name) is None for name in ("thread", "process", "port")))
        owned.api.fail = False
        owned.close()
        self.assertIsNone(owned.job)
        self.assertEqual(owned.api.calls, [11, 12, 13, 14, 11])
        OBSERVATIONS.append({"variant": "fault-injected-close-failure", "all_handle_releases_attempted": True,
                             "failed_handle_retained_for_recovery": True, "successful_cleanup_reported_on_failure": False})

    def test_missing_notification_is_uncertain_not_success(self):
        output = self.directory("missing-notification")
        family = OwnedFamily([sys.executable, "-I", "-B", "-c", "raise SystemExit(99)"], str(output), environment(), str(uuid.uuid4()))
        pinned = WindowsProcess(family.pid, family.creation_time)
        real = family.api

        class MissingNotification:
            def __getattr__(self, name):
                return getattr(real, name)

            def GetQueuedCompletionStatus(self, *args):
                ctypes.set_last_error(258)
                return False

        try:
            family.api = MissingNotification()
            with self.assertRaises(Refusal):
                family.stop(family.scope)
            self.assert_ended([pinned])
            self.assertEqual(family.accounting()["active"], 0)
            OBSERVATIONS.append({"variant": "fault-injected-missing-notification", "reported_success": False,
                                 "pinned_root_ended": True, "accounting": family.accounting()})
        finally:
            family.close()
            pinned.close()
