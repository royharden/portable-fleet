"""Bounded persistence only; late storage never dispatches fixed effects."""
from copy import deepcopy
import threading
import time
import unittest

from portable_fleet.bounded_dispatch import BoundedJournalDispatcher
from portable_fleet.core import Refusal
from portable_fleet.journal_dispatch import recover_operations
from portable_fleet.permit_guard import retain
from portable_fleet.recipient import ReceiptRecipient
from test_dispatch import effect
from test_permit_guard import directory, observation, packet, uid
from test_recipient import ack
from journal_test_support import declared_identity

OBSERVATIONS = []


class BoundedDispatchTests(unittest.TestCase):
    def owner(self, name, timeout=1.0):
        root, scope, now = directory(name), uid(), [1000, 50]
        recipient = ReceiptRecipient(scope, "synthetic-account", clock=lambda: tuple(now))
        request = packet(scope, observation(1000))
        recipient.begin(request)
        recipient.accept(ack(request))
        owner = BoundedJournalDispatcher(recipient, root / "journal", declared_identity(), persistence_seconds=timeout)
        owner.enqueue(effect(scope, 4))
        return owner, root, now

    def observe(self, root, variant, owner, **values):
        record = {"variant": variant, "counter": owner.dispatcher.status(), "actor": owner.actor.status(),
            "recovery": recover_operations(root / "journal"),
            "provenance": "parent volatile counter plus retained SQLite history; no replay/restoration authority", **values}
        retain(root / (variant + ".json"), record)
        OBSERVATIONS.append(record)
        return record

    def test_storage_worker_never_owns_effect_normal_path(self):
        owner, root, now = self.owner("bounded-normal")
        threads, effects = [], []
        original = owner.journal.persist_phase
        def persist(phase, request, result=None):
            threads.append((phase, threading.get_ident()))
            original(phase, request, result)
        class ObservedLedger(list):
            def append(self, value):
                effects.append(threading.get_ident())
                super().append(value)
            def __deepcopy__(self, memo):
                return [deepcopy(value, memo) for value in self]  # observation must not look like another effect
        owner.journal.persist_phase = persist
        owner.dispatcher._effects = ObservedLedger()  # controlled observation, no callback API
        try:
            result = owner.dispatch_next()
            self.assertEqual(result["effect"]["after_total"], 4)
            self.assertEqual([phase for phase, thread in threads], ["accepted", "executing", "outcome"])
            self.assertEqual(len(set(thread for phase, thread in threads)), 1)
            self.assertNotEqual(threads[0][1], threading.get_ident())
            self.assertEqual(effects, [threading.get_ident()])
            recorded = self.observe(root, "normal-thread-boundary", owner, storage_threads=threads, effect_threads=effects)
            self.assertEqual(effects, [threading.get_ident()])
            self.assertEqual(recorded["effect_threads"], [threading.get_ident()])
        finally:
            owner.close()

    def stall(self, phase):
        owner, root, now = self.owner("bounded-stall-" + phase)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = owner.journal.persist_phase
        def persist(current, request, result=None):
            if current != phase:
                return original(current, request, result)
            entered.set()
            if not release.wait(3): raise OSError("Unreleased phase fixture")
            try: original(current, request, result)
            finally: finished.set()
        owner.journal.persist_phase = persist
        try:
            started = time.monotonic()
            with self.assertRaises(OSError): owner.dispatch_next()
            elapsed = time.monotonic() - started
            self.assertTrue(entered.is_set())
            self.assertLess(elapsed, 2)
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.assertEqual(owner.dispatcher.status()["effects"], [])
            self.assertTrue(owner.actor.status()["storage_pending"])
            self.assertTrue(owner.dispatcher.status()["closed"])
            self.observe(root, phase + "-before-release", owner, caller_seconds=elapsed)
            release.set()
            self.assertTrue(finished.wait(3))
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.assertEqual(owner.dispatcher.status()["effects"], [])
            with self.assertRaises(Refusal): owner.dispatch_next()
            with self.assertRaises(Refusal): owner.enqueue(effect(uid()))
            late = self.observe(root, phase + "-after-release", owner)
            self.assertEqual(late["recovery"]["operations"][0]["state"], phase)
            self.assertFalse(late["recovery"]["restart_admitted"])
            self.assertTrue(owner.actor.status()["closed"])
        finally:
            release.set()
            finished.wait(3)
            owner.close()

    def test_accepted_timeout_late_commit_cannot_create_effect(self): self.stall("accepted")
    def test_executing_timeout_late_commit_cannot_create_effect(self): self.stall("executing")

    def test_explicit_cancel_before_dispatch_never_submits_storage(self):
        owner, root, now = self.owner("bounded-cancel-before")
        try:
            owner.cancel("operator cancellation before submission")
            with self.assertRaises(Refusal): owner.dispatch_next()
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.assertEqual(recover_operations(root / "journal")["operations"], [])
            self.observe(root, "cancel-before", owner)
        finally: owner.close()

    def test_explicit_cancel_during_wait_is_permanent_without_join(self):
        owner, root, now = self.owner("bounded-cancel-during")
        entered, release, finished, cancelled = [threading.Event() for _ in range(4)]
        original = owner.journal.persist_phase
        def persist(phase, request, result=None):
            entered.set()
            if not release.wait(3): raise OSError("Unreleased cancel fixture")
            try: original(phase, request, result)
            finally: finished.set()
        owner.journal.persist_phase = persist
        def cancel():
            if entered.wait(1):
                owner.cancel("explicit cancellation while SQL wait pending")
                cancelled.set()
        thread = threading.Thread(target=cancel)
        try:
            thread.start()
            started = time.monotonic()
            with self.assertRaises((OSError, Refusal)): owner.dispatch_next()
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(cancelled.wait(1))
            self.assertTrue(owner.recipient.status()["closed"])
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            release.set()
            self.assertTrue(finished.wait(3))
            with self.assertRaises(Refusal): owner.dispatch_next()
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.observe(root, "cancel-during-late-history", owner)
        finally:
            release.set()
            finished.wait(3)
            thread.join(2)
            owner.close()

    def test_accepted_and_executing_share_one_pre_effect_cutoff(self):
        owner, root, now = self.owner("bounded-aggregate", .5)
        release, finished = threading.Event(), threading.Event()
        cutoffs = []
        original = owner.journal.persist_phase
        def persist(phase, request, result=None):
            cutoffs.append((phase, owner._cutoff))
            if phase == "accepted":
                gate = threading.Event()
                timer = threading.Timer(.15, gate.set)
                timer.start()
                if not gate.wait(1): raise OSError("Accepted timer failed")
                timer.join(1)
            if phase == "executing":
                if not release.wait(3): raise OSError("Unreleased aggregate fixture")
                try: return original(phase, request, result)
                finally: finished.set()
            return original(phase, request, result)
        owner.journal.persist_phase = persist
        try:
            started = time.monotonic()
            with self.assertRaises(OSError): owner.dispatch_next()
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.5)
            self.assertEqual([p for p, cutoff in cutoffs], ["accepted", "executing"])
            self.assertEqual(cutoffs[0][1], cutoffs[1][1])
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            release.set()
            self.assertTrue(finished.wait(3))
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.observe(root, "aggregate-cutoff", owner, cutoffs=cutoffs, caller_seconds=elapsed)
        finally:
            release.set(); finished.wait(3); owner.close()

    def test_expiry_after_phase_and_budget_errors_cancel_before_effect(self):
        for fault in ("expire-after-accepted", "invalid-clock"):
            owner, root, now = self.owner("bounded-" + fault, .5)
            original = owner.journal.persist_phase
            def persist(phase, request, result=None):
                original(phase, request, result)
                now[:] = [1090, 140]
            if fault == "expire-after-accepted": owner.journal.persist_phase = persist
            else: now[:] = [float("nan"), 50]
            try:
                with self.assertRaises((Refusal, OSError)): owner.dispatch_next()
                self.assertEqual(owner.dispatcher.status()["total"], 0)
                self.assertTrue(owner.actor.status()["closed"])
                with self.assertRaises(Refusal): owner.dispatch_next()
                self.observe(root, fault, owner)
            finally: owner.close()

    def test_outcome_timeout_retains_effect_uncertainty_after_late_outcome(self):
        owner, root, now = self.owner("bounded-outcome-timeout")
        entered, release, finished = [threading.Event() for _ in range(3)]
        original = owner.journal.persist_phase
        def persist(phase, request, result=None):
            if phase != "outcome": return original(phase, request, result)
            entered.set()
            if not release.wait(3): raise OSError("Unreleased outcome fixture")
            try: original(phase, request, result)
            finally: finished.set()
        owner.journal.persist_phase = persist
        try:
            with self.assertRaises(OSError): owner.dispatch_next()
            self.assertTrue(entered.is_set())
            self.assertEqual(owner.dispatcher.status()["total"], 4)
            self.assertTrue(owner.dispatcher.status()["outcome_uncertain"])
            self.assertEqual(recover_operations(root / "journal")["operations"][0]["state"], "executing")
            release.set()
            self.assertTrue(finished.wait(3))
            self.assertEqual(owner.dispatcher.status()["total"], 4)
            self.assertTrue(owner.dispatcher.status()["outcome_uncertain"])
            with self.assertRaises(Refusal): owner.dispatch_next()
            late = self.observe(root, "late-outcome-no-reopen", owner)
            self.assertEqual(late["recovery"]["operations"][0]["state"], "outcome")
            self.assertFalse(late["recovery"]["restart_admitted"])
        finally:
            release.set(); finished.wait(3); owner.close()

    def test_invalid_second_budget_sample_prevents_any_phase_submission(self):
        owner, root, now = self.owner("bounded-invalid-second-clock", .5)
        calls = 0
        def clock():
            nonlocal calls
            calls += 1
            return (float("nan"), 50) if calls == 2 else (1000, 50)
        owner.recipient._clock = clock
        try:
            with self.assertRaises(Refusal): owner.dispatch_next()
            self.assertEqual(calls, 2)
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.assertEqual(recover_operations(root / "journal")["operations"], [])
            self.assertTrue(owner._cancelled.is_set())
            self.assertTrue(owner.actor.status()["closed"])
            with self.assertRaises(Refusal): owner.dispatch_next()
            self.observe(root, "invalid-second-budget-sample", owner, clock_samples=calls)
        finally: owner.close()

    def test_phase_api_refuses_prior_state_digest_and_replays(self):
        owner, root, now = self.owner("bounded-phase-schema")
        request = owner._request_for(owner.dispatcher.status()["queued"][0])
        try:
            with self.assertRaises(Refusal): owner.journal.persist_phase("executing", request)
            owner.journal.persist_phase("accepted", request)
            with self.assertRaises(Refusal): owner.journal.persist_phase("accepted", request)
            changed = {**request, "text": request["text"] + "x"}
            with self.assertRaises(Refusal): owner.journal.persist_phase("executing", changed)
            owner.journal.persist_phase("executing", request)
            with self.assertRaises(Refusal): owner.journal.persist_phase("executing", request)
            with self.assertRaises(Refusal): owner.journal.persist_phase("outcome", request, {"state": "outcome", "operation": uid()})
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.observe(root, "phase-transition-holds", owner)
        finally: owner.close()

    def test_final_fixed_fences_refuse_cancelled_or_elapsed_effect(self):
        for cancelled in (False, True):
            owner, root, now = self.owner("bounded-final-fence-" + str(cancelled))
            try:
                event = threading.Event()
                if cancelled: event.set()
                cutoff = time.monotonic() + 1 if cancelled else time.monotonic() - 1
                with self.assertRaises(Refusal): owner.dispatcher.dispatch_next(cutoff_mono=cutoff, cancellation=event)
                self.assertEqual(owner.dispatcher.status()["total"], 0)
            finally: owner.close()
