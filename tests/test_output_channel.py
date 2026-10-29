"""Retained output-failure fixtures; no filesystem cleanup or remote admission."""
import json
import os
import threading
import time
import unittest

from portable_fleet.core import load
from portable_fleet.output_channel import BoundedOutput
from portable_fleet.permit_guard import recover_state
from portable_fleet.family import wait_owned_process
from portable_fleet.process_time import CreationTime
from portable_fleet.watchdog import WindowsProcess
from test_permit_guard import ManagedGuard, directory, packet

OBSERVATIONS = []


class OutputTests(unittest.TestCase):
    def test_partial_prefix_then_exception_is_uncertain_without_resend(self):
        parts = []
        def sink(data):
            if parts:
                raise BrokenPipeError("disconnected after prefix")
            parts.append(data[:2])
            return 2
        channel = BoundedOutput(sink)
        try:
            with self.assertRaises(OSError): channel.send({"scope": "local"})
            self.assertEqual(parts, [b'{"'])
            self.assertEqual(channel.status()["delivery"], "uncertain")
            with self.assertRaises(OSError): channel.send({})
            self.assertEqual(len(parts), 1)
        finally:
            channel.close()

    def test_output_wait_is_clipped_to_old_lease(self):
        entered, release = threading.Event(), threading.Event()
        deadline = time.monotonic() + .05
        def sink(data):
            entered.set()
            release.wait(2)
            return len(data)
        channel = BoundedOutput(sink, remaining=lambda: deadline - time.monotonic())
        start = time.monotonic()
        try:
            with self.assertRaises(OSError): channel.send({})
            self.assertTrue(entered.is_set())
            self.assertLess(time.monotonic() - start, .5)
            self.assertTrue(channel.status()["failed"])
            with self.assertRaises(OSError): channel.send({})
        finally:
            release.set()
            channel.close()

    def test_partial_progress_produces_exact_single_frame(self):
        parts = []
        def sink(data):
            parts.append(data[:3])
            return len(parts[-1])
        channel = BoundedOutput(sink)
        try:
            channel.send({"scope": "local", "text": "é"})
            self.assertEqual(json.loads(b"".join(parts)), {"scope": "local", "text": "é"})
            self.assertFalse(channel.status()["failed"])
        finally:
            channel.close()

    def test_invalid_progress_and_encoding_latch_without_retry(self):
        for progress in (0, -1, True, None, 100000):
            calls = []
            def sink(data):
                calls.append(data)
                return progress
            channel = BoundedOutput(sink)
            try:
                with self.assertRaises(OSError): channel.send({})
                with self.assertRaises(OSError): channel.send({})
                self.assertEqual(len(calls), 1)
                self.assertTrue(channel.status()["failed"])
            finally:
                channel.close()
        recursive = []
        recursive.append(recursive)
        for value in ({"bad": float("nan")}, recursive, {"large": "x" * 100}):
            calls = []
            channel = BoundedOutput(lambda data: calls.append(data), max_frame=32)
            try:
                with self.assertRaises((OSError, ValueError, RecursionError)): channel.send(value)
                with self.assertRaises(OSError): channel.send({})
                self.assertEqual(calls, [])
            finally:
                channel.close()

    def test_bad_budget_latches_even_before_actor_submission(self):
        calls = []
        def broken(): raise RuntimeError("budget failed")
        for remaining in (lambda: float("nan"), lambda: 0, broken):
            channel = BoundedOutput(lambda data: calls.append(data), remaining=remaining)
            try:
                with self.assertRaises((OSError, RuntimeError)): channel.send({})
                self.assertTrue(channel.status()["failed"])
                with self.assertRaises(OSError): channel.send({})
                self.assertEqual(calls, [])
            finally:
                channel.close()

    def test_timeout_close_and_late_completion_never_reopen(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        frames = []
        def blocked(data):
            entered.set()
            release.wait(3)
            frames.append(data)
            finished.set()
            return len(data)
        channel = BoundedOutput(blocked, timeout=.05)
        try:
            with self.assertRaises(OSError): channel.send({"historical": True})
            self.assertTrue(entered.is_set())
            self.assertTrue(channel.status()["output_pending"])
            start = time.monotonic()
            channel.close()
            self.assertLess(time.monotonic() - start, .1)
            release.set()
            self.assertTrue(finished.wait(2))
            with self.assertRaises(OSError): channel.send({"restart": True})
            self.assertEqual(len(frames), 1)
            self.assertTrue(channel.status()["failed"])
        finally:
            release.set()
            channel.close()

    def test_concurrent_send_refuses_and_latches_both_callers(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        def blocked(data):
            entered.set()
            release.wait(2)
            return len(data)
        channel = BoundedOutput(blocked)
        def first():
            try: channel.send({})
            except OSError as error: errors.append(str(error))
        thread = threading.Thread(target=first)
        try:
            thread.start()
            self.assertTrue(entered.wait(1))
            with self.assertRaises(OSError): channel.send({})
            release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            with self.assertRaises(OSError): channel.send({})
        finally:
            release.set()
            thread.join(3)
            channel.close()


@unittest.skipUnless(os.name == "nt", "Windows owned job/output integration")
class OutputIntegrationTests(unittest.TestCase):
    def test_initial_output_failure_never_resumes_suspended_root(self):
        managed = ManagedGuard(directory("output-initial"), "output-broken-initial", expect_waiting=False)
        try:
            self.assertTrue(managed.events["stall-finished"][1].wait(10000))
            self.assertEqual(managed.process.wait(timeout=5), 3)
            self.assertFalse((managed.output / "root.json").exists())
            result = load(managed.output / "state/output-failure.json")
            self.assertTrue(result["stop"]["all_pinned_ended"])
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertEqual(managed.next(2)["event"], "eof")
            self.assertEqual(managed.process.stderr.read(), b"")
            self.assertFalse(recover_state(managed.output / "state")["restart_admitted"])
            OBSERVATIONS.append({"variant": "initial-output-disconnection", "record": result, "root_executed": False})
        finally:
            managed.close()

    def run_active(self, fault, paused):
        managed = ManagedGuard(directory(fault), fault, pause_output=paused)
        pins = []
        try:
            managed.start()
            if paused: self.assertTrue(managed.reader_paused.wait(2))
            members = load(managed.output / "state/members.json")["members"]
            pins = [WindowsProcess(row["pid"], CreationTime.from_record(row["creationTime"])) for row in members]
            command = packet(managed.scope, managed.original_observation)
            start = time.monotonic()
            managed.send(command)
            if paused: self.assertTrue(managed.events["stall-entered"][1].wait(3000))
            self.assertTrue(managed.events["stall-finished"][1].wait(10000))
            for pin in pins:
                self.assertTrue(wait_owned_process(pin, 0))
                self.assertFalse(pin.alive())
            result = load(managed.output / "state/stop.json")
            failure = load(managed.output / "state/output-failure.json")
            self.assertEqual(result["state"], "stopped", result)
            self.assertEqual(result["pinned_count"], 6)
            self.assertTrue(managed.sentinel_pin.alive())
            self.assertLessEqual(result["all_pins_ended_mono"] - start, 10)
            self.assertGreaterEqual(result["request_to_all_pins_seconds"], result["stop_call_to_all_pins_seconds"])
            work = managed.work_counts()
            if paused:
                self.assertTrue(failure["output"]["output_pending"])
                self.assertGreaterEqual(result["request_to_all_pins_seconds"], .9)
                managed.reader_release.set()  # drain only AFTER independent six-exit observation
                late = managed.next(5)
                self.assertEqual(late["operation"], command["operation"])
                self.assertEqual(late["state"], "active")  # historical bytes, never current authority
                managed.events["stall-release"][1].set()
            self.assertEqual(managed.process.wait(timeout=5), 3)
            self.assertEqual(managed.work_counts(), work)
            self.assertEqual(managed.process.stderr.read(), b"")
            self.assertFalse(recover_state(managed.output / "state")["restart_admitted"])
            OBSERVATIONS.append({"variant": fault, "record": failure,
                "trigger_to_six_exit_observation": time.monotonic() - start,
                "six_exits_before_drain": paused, "sentinel_survived": True,
                "unchanged_work_after_drain": work})
        finally:
            for pin in pins: pin.close()
            managed.close()

    def test_broken_active_output_stops_without_diagnostic_retry(self):
        self.run_active("output-broken-active", False)

    def test_actual_nondraining_pipe_stops_before_late_drain(self):
        self.run_active("output-pipe-backpressure", True)
