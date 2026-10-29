"""Fresh, real-clock 300-second synthetic observation window; no policy scaling."""
import os
import threading
import time
import unittest

from portable_fleet.core import load
from portable_fleet.permit_guard import recover_state
from test_permit_guard import ManagedGuard, directory, packet


OBSERVATIONS = []


@unittest.skipUnless(os.name == "nt", "Windows real observation-window fixture")
class FreshWindowTests(unittest.TestCase):
    def test_fresh_observation_renewals_stop_by_original_310_second_target(self):
        managed = ManagedGuard(directory("fresh-300s"), lifetime_ms=350000, maximum_runtime=340)
        timers, scheduled, errors = [], [], []
        try:
            origin_wall, origin_mono = time.time(), time.monotonic()
            managed.start(observed=origin_wall)
            self.assertLess(time.monotonic() - origin_mono, 10)
            source = dict(managed.original_observation)

            def renew(offset):
                try:
                    managed.send(packet(managed.scope, source))
                    scheduled.append({"offset": offset, "sent_mono": time.monotonic()})
                except Exception as error:
                    errors.append(str(error))

            for offset in range(30, 300, 30):
                timer = threading.Timer(max(0, origin_mono + offset - time.monotonic()), renew, args=(offset,))
                timer.start()
                timers.append(timer)
            result = managed.stopped(timeout=320)
            for timer in timers:
                timer.join(timeout=2)
            self.assertFalse(errors)
            self.assertEqual(len(scheduled), 9)
            self.assertEqual(result["state"], "stopped", result)
            self.assertTrue(result["all_pinned_ended"])
            self.assertEqual(result["pinned_count"], 6)
            self.assertTrue(managed.sentinel_pin.alive())
            wall_elapsed = result["all_pins_ended_wall"] - origin_wall
            mono_elapsed = result["all_pins_ended_mono"] - origin_mono
            self.assertGreaterEqual(mono_elapsed, 299.8)
            self.assertLessEqual(mono_elapsed, 310)
            self.assertGreaterEqual(wall_elapsed, 299.8)
            self.assertLessEqual(wall_elapsed, 310)
            receipt_acks = [message for message in managed.messages if message.get("state") == "active" and message.get("kind") == "receipt"]
            self.assertEqual(len(receipt_acks), 10)
            self.assertEqual(len({message["operation"] for message in receipt_acks}), 10)
            for ack in receipt_acks:
                permit = ack["permit"]
                self.assertEqual(permit["observation_deadline"], origin_wall + 300)
                self.assertLessEqual(permit["expires_wall"], origin_wall + 300)
                self.assertGreater(permit["expires_wall"] - permit["issued_wall"], 0)
                self.assertLessEqual(permit["expires_wall"] - permit["issued_wall"], 90.000001)
                command = load(managed.output / "state/commands" / (ack["operation"] + ".json"))
                self.assertEqual(command["command"]["observation"], source)
            self.assertGreater(result["last_permit"]["issued_wall"], origin_wall + 260)
            final_work = managed.work_counts()
            self.assertTrue(all(final_work[role] > managed.initial_work[role] + 1000 for role in final_work))
            self.assertFalse(recover_state(managed.output / "state")["restart_admitted"])
            OBSERVATIONS.append({"variant": "fresh-real-clock-300-second-observation", "source": source,
                "origin_wall": origin_wall, "origin_mono": origin_mono, "no_preaging": True, "policy_scaling": False,
                "renewal_offsets_seconds": sorted(item["offset"] for item in scheduled), "renewal_send_receipts": scheduled,
                "all_observation_payloads_identical": True, "accepted_receipts_including_initial": len(receipt_acks),
                "source_to_all_pins_seconds_wall": wall_elapsed, "source_to_all_pins_seconds_mono": mono_elapsed,
                "all_six_pinned_ended": True, "sentinel_survived": True, "initial_work_counts": managed.initial_work,
                "final_work_counts": final_work, "result": result})
        finally:
            for timer in timers:
                timer.cancel()
                timer.join(timeout=2)
            managed.close()
