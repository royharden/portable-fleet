"""Recipient checks at fixed counter use, with retained local guard integration."""
from copy import deepcopy
import os
import time
import unittest

from portable_fleet.core import Refusal, load
from portable_fleet.dispatch import SyntheticDispatcher
from portable_fleet.family import wait_owned_process
from portable_fleet.permit_guard import retain
from portable_fleet.process_time import CreationTime
from portable_fleet.recipient import ReceiptRecipient
from portable_fleet.watchdog import WindowsProcess
from test_permit_guard import ManagedGuard, directory, observation, packet, uid
from test_recipient import ack

OBSERVATIONS = []


def effect(scope, value=1, operation=None):
    return {"schema": 1, "operation": operation or uid(), "scope": scope, "kind": "add", "value": value}


class DispatchTests(unittest.TestCase):
    def setup_dispatch(self):
        now, scope = [1000, 50], uid()
        recipient = ReceiptRecipient(scope, "synthetic-account", clock=lambda: tuple(now))
        request = packet(scope, observation(1000))
        recipient.begin(request)
        recipient.accept(ack(request))
        return SyntheticDispatcher(recipient), recipient, request, now

    def test_fixed_effect_uses_live_binding_and_isolates_mutation(self):
        dispatcher, recipient, request, now = self.setup_dispatch()
        command = effect(request["scope"], 3)
        dispatcher.enqueue(command)
        command["value"] = 100
        result = dispatcher.dispatch_next()
        self.assertEqual(result["after_total"], 3)
        result["receipt"]["expires_wall"] = 999999
        result["after_total"] = 999999
        saved = dispatcher.status()
        saved["effects"].clear()
        self.assertEqual(dispatcher.status()["total"], 3)
        self.assertEqual(len(dispatcher.status()["effects"]), 1)
        self.assertEqual(recipient.require_current()["expires_wall"], 1090)

    def test_queued_work_denied_after_close_expiry_or_clock_fault(self):
        for fault in ("close", "wall-expiry", "mono-expiry", "backward"):
            dispatcher, recipient, request, now = self.setup_dispatch()
            dispatcher.enqueue(effect(request["scope"], 5))
            if fault == "close": recipient.close("local transport loss")
            if fault == "wall-expiry": now[:] = [1090, 139]
            if fault == "mono-expiry": now[:] = [1089, 140]
            if fault == "backward": now[:] = [999, 50.1]
            with self.assertRaises(Refusal): dispatcher.dispatch_next()
            self.assertEqual(dispatcher.status()["total"], 0)
            self.assertEqual(dispatcher.status()["effects"], [])
            self.assertTrue(dispatcher.status()["closed"])
            self.assertFalse(dispatcher.status()["outcome_uncertain"])
            with self.assertRaises(Refusal): dispatcher.dispatch_next()

    def test_new_receipt_cannot_retarget_queued_work(self):
        for accept_new in (False, True):
            dispatcher, recipient, request, now = self.setup_dispatch()
            dispatcher.enqueue(effect(request["scope"]))
            newer = packet(request["scope"], request["observation"])
            now[:] = [1000.1, 50.1]
            recipient.begin(newer)
            if accept_new: recipient.accept(ack(newer, 1000.1))
            with self.assertRaises(Refusal): dispatcher.dispatch_next()
            self.assertEqual(dispatcher.status()["total"], 0)
            self.assertTrue(recipient.status()["closed"])
            with self.assertRaises(Refusal): recipient.accept(ack(newer, 1000.1))

    def test_reordered_reply_closes_before_queued_effect(self):
        dispatcher, recipient, request, now = self.setup_dispatch()
        dispatcher.enqueue(effect(request["scope"], 8))
        newer = packet(request["scope"], request["observation"])
        recipient.begin(newer)
        recipient.accept(ack(newer))
        with self.assertRaises(Refusal): recipient.accept(ack(request))
        with self.assertRaises(Refusal): dispatcher.dispatch_next()
        self.assertEqual(dispatcher.status()["total"], 0)

    def test_final_recheck_rejects_expiry_during_preparation(self):
        dispatcher, recipient, request, now = self.setup_dispatch()
        dispatcher.enqueue(effect(request["scope"], 9))
        samples = iter(((1000.1, 50.1), (1090, 140)))
        recipient._clock = lambda: next(samples)
        with self.assertRaises(Refusal): dispatcher.dispatch_next()
        self.assertEqual(dispatcher.status()["total"], 0)
        self.assertFalse(dispatcher.status()["outcome_uncertain"])

    def test_duplicate_id_never_repeats_effect(self):
        for before_dispatch in (False, True):
            dispatcher, recipient, request, now = self.setup_dispatch()
            command = effect(request["scope"], 2)
            dispatcher.enqueue(command)
            if not before_dispatch: dispatcher.dispatch_next()
            command["value"] = 99
            with self.assertRaises(Refusal): dispatcher.enqueue(command)
            with self.assertRaises(Refusal): dispatcher.dispatch_next()
            self.assertEqual(dispatcher.status()["total"], 0 if before_dispatch else 2)

    def test_fixed_schema_queue_and_lifetime_limits_close(self):
        for change in ("scope", "value-bool", "value-zero", "value-large", "kind", "extra"):
            dispatcher, recipient, request, now = self.setup_dispatch()
            command = effect(request["scope"])
            if change == "scope": command["scope"] = uid()
            if change == "value-bool": command["value"] = True
            if change == "value-zero": command["value"] = 0
            if change == "value-large": command["value"] = 101
            if change == "kind": command["kind"] = "shell"
            if change == "extra": command["callback"] = "none"
            with self.assertRaises(Refusal): dispatcher.enqueue(command)
            self.assertEqual(dispatcher.status()["total"], 0)
        dispatcher, recipient, request, now = self.setup_dispatch()
        for _ in range(8): dispatcher.enqueue(effect(request["scope"]))
        with self.assertRaises(Refusal): dispatcher.enqueue(effect(request["scope"]))
        self.assertEqual(dispatcher.status()["total"], 0)
        dispatcher, recipient, request, now = self.setup_dispatch()
        for _ in range(64):
            dispatcher.enqueue(effect(request["scope"], 100))
            dispatcher.dispatch_next()
        self.assertEqual(dispatcher.status()["total"], 6400)
        with self.assertRaises(Refusal): dispatcher.enqueue(effect(request["scope"]))
        self.assertEqual(len(dispatcher.status()["effects"]), 64)

    def test_exception_after_counter_mutation_is_terminal_uncertainty(self):
        class FailedLedger(list):
            def append(self, value): raise MemoryError("Injected ledger failure after effect")
        dispatcher, recipient, request, now = self.setup_dispatch()
        dispatcher.enqueue(effect(request["scope"], 4))
        dispatcher._effects = FailedLedger()  # controlled private fault, not a callback API
        with self.assertRaises(MemoryError): dispatcher.dispatch_next()
        self.assertEqual(dispatcher.status()["total"], 4)
        self.assertTrue(dispatcher.status()["outcome_uncertain"])
        self.assertEqual(dispatcher.status()["effects"], [])
        with self.assertRaises(Refusal): dispatcher.dispatch_next()
        self.assertEqual(dispatcher.status()["total"], 4)


def start_bound(managed):
    recipient = ReceiptRecipient(managed.scope, "synthetic-account")
    source = observation(time.time())
    request = packet(managed.scope, source)
    recipient.begin(request)
    managed.send(request)
    recipient.accept(managed.next(5))
    if not managed.events["ready"][1].wait(10000):
        raise Refusal("Family readiness deadline")
    managed.send(packet(managed.scope, None, "inspect"))
    if managed.next(5)["state"] != "active":
        raise Refusal("Family snapshot not active")
    return recipient, source


@unittest.skipUnless(os.name == "nt", "Windows local dispatch integration")
class DispatchIntegrationTests(unittest.TestCase):
    def test_timely_reply_effect_then_close_blocks_queued_effect(self):
        managed = ManagedGuard(directory("dispatch-timely"))
        try:
            recipient, source = start_bound(managed)
            dispatcher = SyntheticDispatcher(recipient)
            dispatcher.enqueue(effect(managed.scope, 3))
            dispatcher.dispatch_next()
            dispatcher.enqueue(effect(managed.scope, 7))
            recipient.close("local operator closure")
            with self.assertRaises(Refusal): dispatcher.dispatch_next()
            self.assertEqual(dispatcher.status()["total"], 3)
            self.assertEqual(len(dispatcher.status()["effects"]), 1)
            managed.send(packet(managed.scope, None, "stop"))
            stopped = managed.stopped(timeout=10)
            self.assertTrue(stopped["all_pinned_ended"])
            self.assertEqual(stopped["pinned_count"], 6)
            self.assertTrue(managed.sentinel_pin.alive())
            record = {"variant": "timely-effect-then-close", "counter": dispatcher.status(),
                "recipient": recipient.status(), "owned_family_stop": stopped, "sentinel_survived": True,
                "provenance": "parent synthetic memory counter; observer record is not durable child effect delivery"}
            retain(managed.output / "dispatch-observation.json", record)
            OBSERVATIONS.append(record)
        finally:
            managed.close()

    def test_delayed_reply_after_six_exits_cannot_run_queued_effect(self):
        managed = ManagedGuard(directory("dispatch-delayed"), "output-pipe-backpressure", pause_output=True)
        pins = []
        try:
            recipient, source = start_bound(managed)
            self.assertTrue(managed.reader_paused.wait(2))
            rows = load(managed.output / "state/members.json")["members"]
            pins = [WindowsProcess(row["pid"], CreationTime.from_record(row["creationTime"])) for row in rows]
            self.assertEqual(len(pins), 6)
            dispatcher = SyntheticDispatcher(recipient)
            dispatcher.enqueue(effect(managed.scope, 9))
            renewal = packet(managed.scope, source)
            recipient.begin(renewal)
            managed.send(renewal)
            deadline = time.monotonic() + 10
            for pin in pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
            self.assertTrue(managed.events["stall-finished"][1].wait(3000))
            work = managed.work_counts()
            self.assertTrue(managed.sentinel_pin.alive())
            managed.reader_release.set()
            late = managed.next(5)
            self.assertEqual(late["operation"], renewal["operation"])
            self.assertEqual(late["state"], "active")
            with self.assertRaisesRegex(Refusal, "response deadline"): recipient.accept(late)
            with self.assertRaises(Refusal): dispatcher.dispatch_next()
            with self.assertRaises(Refusal): dispatcher.enqueue(effect(managed.scope))
            self.assertEqual(dispatcher.status()["total"], 0)
            self.assertEqual(dispatcher.status()["effects"], [])
            managed.events["stall-release"][1].set()
            self.assertEqual(managed.process.wait(timeout=5), 3)
            self.assertEqual(managed.work_counts(), work)
            record = {"variant": "delayed-reply-no-counter-effect", "counter": dispatcher.status(),
                "recipient": recipient.status(), "late_frame": late, "all_six_exits_before_drain": True,
                "sentinel_survived": True, "unchanged_family_work": work,
                "provenance": "parent synthetic memory counter; observer record is not durable child effect delivery"}
            retain(managed.output / "dispatch-observation.json", record)
            OBSERVATIONS.append(record)
        finally:
            for pin in pins: pin.close()
            managed.close()
