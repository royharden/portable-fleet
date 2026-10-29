"""Deterministic recipient protocol checks plus a retained actual delayed pipe."""
from copy import deepcopy
import os
import time
import unittest

from portable_fleet.core import Refusal, load
from portable_fleet.family import wait_owned_process
from portable_fleet.permit_guard import retain
from portable_fleet.process_time import CreationTime
from portable_fleet.recipient import ReceiptRecipient
from portable_fleet.supervision import Observation, Supervisor
from portable_fleet.watchdog import WindowsProcess
from test_permit_guard import ManagedGuard, directory, observation, packet, uid

OBSERVATIONS = []


def ack(command, wall=1000, mono=9000000):
    issuer = Supervisor(command["observation"]["account"])
    issuer.observe(Observation(**command["observation"]), wall)
    return {"state": "active", "operation": command["operation"], "kind": "receipt", "replayed": False,
            "permit": issuer.permit(wall, mono, command["scope"])}


class RecipientTests(unittest.TestCase):
    def setup_recipient(self):
        now, scope = [1000, 50], uid()
        recipient = ReceiptRecipient(scope, "synthetic-account", clock=lambda: tuple(now))
        command = packet(scope, observation(1000))
        return recipient, command, now

    def test_local_send_deadline_ignores_foreign_mono_origin_and_copies(self):
        recipient, command, now = self.setup_recipient()
        response = ack(command, 1000.1, 9000000)
        recipient.begin(command)
        command["observation"]["observed"] = 999999
        now[:] = [1000.2, 50.2]
        view = recipient.accept(response)
        self.assertEqual(view["expires_wall"], 1090)
        self.assertAlmostEqual(view["expires_mono"], 140)
        view["expires_mono"] = 99999999
        response["permit"]["expires_wall"] = 999999
        self.assertEqual(recipient.require_current()["expires_wall"], 1090)
        now[:] = [1090, 140]
        with self.assertRaises(Refusal): recipient.require_current()
        self.assertTrue(recipient.status()["closed"])

    def test_same_source_renewals_never_extend_original_observation(self):
        recipient, command, now = self.setup_recipient()
        source = deepcopy(command["observation"])
        for offset in range(0, 300, 30):
            now[:] = [1000 + offset, 50 + offset]
            request = packet(command["scope"], source)
            recipient.begin(request)
            now[:] = [1000.1 + offset, 50.1 + offset]
            result = recipient.accept(ack(request, 1000 + offset))
            self.assertLessEqual(result["expires_wall"], 1300)
        self.assertEqual(result["expires_wall"], 1300)
        now[:] = [1300, 350]
        with self.assertRaises(Refusal): recipient.begin(packet(command["scope"], observation(1300, sequence=2)))
        self.assertTrue(recipient.status()["closed"])

    def test_pending_deadline_closes_before_ack_or_new_request(self):
        for action, clocks in (("ack", (1001, 51)), ("new-request", (1001, 51)),
                               ("ack", (1001.1, 50.1)), ("new-request", (1001.1, 50.1)),
                               ("ack", (1000.1, 51.1))):
            recipient, command, now = self.setup_recipient()
            recipient.begin(command)
            now[:] = clocks
            with self.assertRaises(Refusal):
                if action == "ack": recipient.accept(ack(command))
                else: recipient.begin(packet(command["scope"], observation(1001, sequence=2)))
            self.assertTrue(recipient.status()["closed"])
            with self.assertRaises(Refusal): recipient.accept(ack(command))

    def test_coherent_shorter_reply_expiry_is_preserved(self):
        recipient, command, now = self.setup_recipient()
        recipient.begin(command)
        response = ack(command)
        response["permit"]["expires_wall"] -= 60
        response["permit"]["expires_mono"] -= 60
        now[:] = [1000.1, 50.1]
        view = recipient.accept(response)
        self.assertEqual(view["expires_wall"], 1030)
        self.assertEqual(view["expires_mono"], 80)
        now[:] = [1030, 80]
        with self.assertRaises(Refusal): recipient.require_current()
        with self.assertRaises(Refusal): recipient.begin(packet(command["scope"], command["observation"]))

    def test_superseded_reordered_and_duplicate_acknowledgments_close(self):
        for order in ("old-first", "new-then-old", "duplicate", "duplicate-request"):
            recipient, command, now = self.setup_recipient()
            recipient.begin(command)
            if order.startswith("duplicate"):
                recipient.accept(ack(command))
                with self.assertRaises(Refusal):
                    if order == "duplicate": recipient.accept(ack(command))
                    else: recipient.begin(command)
            else:
                newer = packet(command["scope"], command["observation"])
                now[:] = [1000.1, 50.1]
                recipient.begin(newer)
                with self.assertRaises(Refusal): recipient.require_current()
                if order == "new-then-old": recipient.accept(ack(newer, 1000.1))
                with self.assertRaises(Refusal): recipient.accept(ack(command))
                with self.assertRaises(Refusal): recipient.accept(ack(newer, 1000.1))
            self.assertTrue(recipient.status()["closed"])

    def test_local_close_cannot_reopen_from_fresh_ack(self):
        recipient, command, now = self.setup_recipient()
        recipient.begin(command)
        recipient.close("local transport uncertainty")
        with self.assertRaises(Refusal): recipient.accept(ack(command))
        with self.assertRaises(Refusal): recipient.begin(packet(command["scope"], command["observation"]))
        self.assertFalse(recipient.status()["restart_admitted"])

    def test_validation_crossing_response_deadline_cannot_install_admission(self):
        recipient, command, now = self.setup_recipient()
        recipient.begin(command)
        samples = iter(((1000.1, 50.1), (1001.1, 51.1)))
        recipient._clock = lambda: next(samples)
        with self.assertRaises(Refusal): recipient.accept(ack(command))
        self.assertTrue(recipient.status()["closed"])
        self.assertIsNone(recipient.status()["current"])

    def test_malformed_wrong_bound_and_unrequested_responses_latch(self):
        changes = ("scope", "account", "sequence", "sequence-bool", "schema-bool", "warning", "nan", "future",
                   "duration", "mono-duration", "negative-mono", "observation-deadline", "operation", "kind", "state", "replayed", "extra", "nonobject")
        for change in changes:
            with self.subTest(change=change):
                recipient, command, now = self.setup_recipient()
                recipient.begin(command)
                response = ack(command)
                permit = response["permit"]
                if change == "scope": permit["scope"] = uid()
                if change == "account": permit["account"] = "foreign"
                if change == "sequence": permit["sequence"] = 2
                if change == "sequence-bool": permit["sequence"] = True
                if change == "schema-bool": permit["schema"] = True
                if change == "warning": permit["warning"] = 0
                if change == "nan": permit["issued_wall"] = float("nan")
                if change == "future": permit["issued_wall"] += 1
                if change == "duration": permit["expires_wall"] = permit["issued_wall"]
                if change == "mono-duration": permit["expires_mono"] += 1
                if change == "negative-mono": permit["issued_mono"], permit["expires_mono"] = -100, -10
                if change == "observation-deadline": permit["observation_deadline"] += 1
                if change == "operation": response["operation"] = uid()
                if change == "kind": response["kind"] = "inspect"
                if change == "state": response["state"] = "stopped"
                if change == "replayed": response["replayed"] = True
                if change == "extra": response["generation"] = 999
                if change == "nonobject": response = None
                with self.assertRaises(Refusal): recipient.accept(response)
                self.assertTrue(recipient.status()["closed"])
                with self.assertRaises(Refusal): recipient.accept(ack(command))
        recipient, command, now = self.setup_recipient()
        with self.assertRaises(Refusal): recipient.accept(ack(command))

    def test_clock_continuity_cannot_reset_across_request_generations(self):
        for clocks in ((999, 50.1), (1000.1, 49), (1003, 50.1), (1000.1, float("nan"))):
            recipient, command, now = self.setup_recipient()
            recipient.begin(command)
            now[:] = clocks
            with self.assertRaises(Refusal): recipient.begin(packet(command["scope"], command["observation"]))
            self.assertTrue(recipient.status()["closed"])
        recipient, command, now = self.setup_recipient()
        recipient.begin(command)
        recipient.accept(ack(command))
        now[:] = [1001.5, 50.1]
        newer = packet(command["scope"], command["observation"])
        recipient.begin(newer)  # first1.4s divergence below threshold, old anchor must survive
        now[:] = [1003, 50.2]
        with self.assertRaises(Refusal): recipient.begin(packet(command["scope"], command["observation"]))
        self.assertTrue(recipient.status()["closed"])


@unittest.skipUnless(os.name == "nt", "Windows delayed output integration")
class RecipientIntegrationTests(unittest.TestCase):
    def test_timely_real_local_reply_then_local_close(self):
        managed = ManagedGuard(directory("recipient-timely"))
        try:
            managed.start()
            recipient = ReceiptRecipient(managed.scope, "synthetic-account")
            command = packet(managed.scope, managed.original_observation)
            recipient.begin(command)
            managed.send(command)
            response = managed.next(5)
            accepted = recipient.accept(response)
            self.assertEqual(accepted["operation"], command["operation"])
            self.assertEqual(recipient.require_current()["scope"], managed.scope)
            recipient.close("local operator stop")
            managed.send(packet(managed.scope, None, "stop"))
            stopped = managed.stopped(timeout=10)
            self.assertTrue(stopped["all_pinned_ended"])
            self.assertEqual(stopped["pinned_count"], 6)
            self.assertTrue(managed.sentinel_pin.alive())
            with self.assertRaises(Refusal): recipient.accept(response)
            record = {"variant": "timely-local-then-close", "accepted": accepted,
                "recipient": recipient.status(), "stop": stopped, "sentinel_survived": True}
            retain(managed.output / "recipient-rejection.json", record)
            OBSERVATIONS.append(record)
        finally:
            managed.close()

    def test_real_delayed_active_frame_rejected_after_independent_family_exit(self):
        managed = ManagedGuard(directory("recipient-delayed-pipe"), "output-pipe-backpressure", pause_output=True)
        pins = []
        try:
            managed.start()
            self.assertTrue(managed.reader_paused.wait(2))
            rows = load(managed.output / "state/members.json")["members"]
            pins = [WindowsProcess(row["pid"], CreationTime.from_record(row["creationTime"])) for row in rows]
            recipient = ReceiptRecipient(managed.scope, "synthetic-account")
            command = packet(managed.scope, managed.original_observation)
            recipient.begin(command)
            sent = time.monotonic()
            managed.send(command)
            deadline = sent + 10
            for pin in pins:
                self.assertTrue(wait_owned_process(pin, max(0, int((deadline - time.monotonic()) * 1000))))
            self.assertTrue(managed.events["stall-finished"][1].wait(3000))
            self.assertTrue(managed.sentinel_pin.alive())
            work = managed.work_counts()
            managed.reader_release.set()
            late = managed.next(5)
            self.assertEqual(late["operation"], command["operation"])
            self.assertEqual(late["state"], "active")
            # Raw padding stays retained. Deadline rejection occurs before schema
            # parsing, so this cannot pass merely by rejecting the fixture field.
            with self.assertRaisesRegex(Refusal, "response deadline"):
                recipient.accept(late)
            with self.assertRaises(Refusal): recipient.begin(packet(managed.scope, managed.original_observation))
            with self.assertRaises(Refusal): recipient.require_current()
            managed.events["stall-release"][1].set()
            self.assertEqual(managed.process.wait(timeout=5), 3)
            self.assertEqual(managed.work_counts(), work)
            record = {"schema": 1, "scope": managed.scope, "recipient": recipient.status(),
                "delivery_delay_seconds": time.monotonic() - sent, "all_six_exits_before_drain": len(pins) == 6,
                "sentinel_survived": True, "unchanged_work": work,
                "late_active_frame": late, "restart_admitted": False}
            retain(managed.output / "recipient-rejection.json", record)
            OBSERVATIONS.append(record)
        finally:
            for pin in pins: pin.close()
            managed.close()
