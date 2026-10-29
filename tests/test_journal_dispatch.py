"""Retained existing-journal integration; no legacy delete-bearing paths run."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from portable_fleet.core import Refusal, canonical, digest, load
from portable_fleet.journal_dispatch import JournaledDispatcher, recover_operations
from portable_fleet.permit_guard import retain
from portable_fleet.recipient import ReceiptRecipient
from portable_fleet.seat import Journal
from family_fixture import environment
from test_dispatch import effect
from test_permit_guard import directory, observation, packet, uid
from test_recipient import ack
from journal_test_support import declared_identity

OBSERVATIONS = []


def contents(root):
    return {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
            for p in root.iterdir() if p.is_file()}


class JournalDispatchTests(unittest.TestCase):
    def setup_owner(self, name):
        root, scope, now = directory(name), uid(), [1000, 50]
        recipient = ReceiptRecipient(scope, "synthetic-account", clock=lambda: tuple(now))
        request = packet(scope, observation(1000))
        recipient.begin(request)
        recipient.accept(ack(request))
        return JournaledDispatcher(recipient, root / "journal", declared_identity()), scope, now, root

    def test_existing_table_outcomes_and_cached_history_never_repeat_effect(self):
        owner, scope, now, root = self.setup_owner("journal-normal")
        try:
            owner.enqueue(effect(scope, 3))
            first = owner.dispatch_next()
            self.assertEqual(first["effect"]["after_total"], 3)
            request = deepcopy(owner.last_request)
            class NoEffect:
                def validate(self, *args): raise AssertionError("Historical replay validated fresh admission")
                def act(self, *args): raise AssertionError("Historical replay repeated effect")
            self.assertEqual(owner.journal.execute(request, NoEffect(), now=999999), first)
            changed = {**request, "text": request["text"] + "x"}
            with self.assertRaises(Refusal): owner.journal.execute(changed, NoEffect(), now=1000)
            owner.enqueue(effect(scope, 2))
            owner.dispatch_next()
            recovery = recover_operations(root / "journal")
            self.assertEqual([r["state"] for r in recovery["operations"]], ["outcome", "outcome"])
            self.assertFalse(recovery["restart_admitted"])
            self.assertEqual(owner.dispatcher.status()["total"], 5)
            self.assertEqual(next(row["digest"] for row in recovery["operations"] if row["id"] == request["operation"]), digest(canonical(request)))
            with owner.journal.connect() as db:
                self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "persist")
                self.assertEqual(db.execute("PRAGMA temp_store").fetchone()[0], 2)
                self.assertEqual(db.execute("PRAGMA synchronous").fetchone()[0], 2)
                self.assertEqual(db.execute("PRAGMA journal_size_limit").fetchone()[0], -1)
            journal = root / "journal/operations.sqlite-journal"
            self.assertTrue(journal.exists())
            self.assertGreater(journal.stat().st_size, 0)
            OBSERVATIONS.append({"variant": "retained-normal-history", "total": 5, "recovery": recovery,
                                 "retained_files": contents(root / "journal")})
        finally:
            owner.close()
        before = contents(root / "journal")
        with self.assertRaises(Refusal): Journal(root / "journal", retain_files=True)
        self.assertEqual(contents(root / "journal"), before)

    def test_nonempty_unclaimed_roots_refuse_before_sqlite_open(self):
        root = directory("journal-orphan")
        retain(root / "operations.sqlite", {"orphan": True})
        before = contents(root)
        with patch("portable_fleet.seat.sqlite3.connect") as connect:
            with self.assertRaises(Refusal): Journal(root, retain_files=True)
            connect.assert_not_called()
        self.assertEqual(contents(root), before)

    def test_expiry_after_executing_commit_prevents_counter(self):
        owner, scope, now, root = self.setup_owner("journal-expiry")
        original, calls = owner.journal.connect, 0
        @contextmanager
        def connect():
            nonlocal calls
            calls += 1
            with original() as db: yield db
            if calls == 2: now[:] = [1090, 140]
        owner.journal.connect = connect
        try:
            owner.enqueue(effect(scope, 4))
            with self.assertRaises(Refusal): owner.dispatch_next()
            self.assertEqual(owner.dispatcher.status()["total"], 0)
            self.assertTrue(owner.dispatcher.status()["closed"])
            recovery = recover_operations(root / "journal")
            self.assertEqual(recovery["operations"][0]["state"], "executing")
            self.assertEqual(recovery["state"], "held-uncertain")
            OBSERVATIONS.append({"variant": "expired-after-journal-io", "counter": owner.dispatcher.status(), "recovery": recovery})
        finally:
            owner.close()

    def test_outcome_persistence_failure_after_counter_is_uncertain_no_retry(self):
        owner, scope, now, root = self.setup_owner("journal-outcome-fail")
        original, calls = owner.journal.connect, 0
        @contextmanager
        def connect():
            nonlocal calls
            calls += 1
            if calls == 3: raise OSError("Injected outcome commit unavailable")
            with original() as db: yield db
        owner.journal.connect = connect
        try:
            owner.enqueue(effect(scope, 4))
            with self.assertRaises(OSError): owner.dispatch_next()
            self.assertEqual(owner.dispatcher.status()["total"], 4)
            self.assertTrue(owner.dispatcher.status()["outcome_uncertain"])
            with self.assertRaises(Refusal): owner.dispatch_next()
            recovery = recover_operations(root / "journal")
            self.assertEqual(recovery["operations"][0]["state"], "executing")
            self.assertFalse(recovery["restart_admitted"])
            OBSERVATIONS.append({"variant": "effect-before-outcome-failure", "counter": owner.dispatcher.status(), "recovery": recovery})
        finally:
            owner.close()

    def test_read_only_corrupt_missing_state_stays_held_without_repair(self):
        root = directory("journal-corrupt")
        retain(root / "operations.sqlite", {"not": "sqlite"})
        before = contents(root)
        report = recover_operations(root)
        self.assertEqual(report["state"], "held-uncertain")
        self.assertTrue(report["errors"])
        self.assertFalse(report["restart_admitted"])
        self.assertEqual(contents(root), before)
        self.assertEqual(recover_operations(root / "missing")["state"], "held-uncertain")
        self.assertFalse((root / "missing").exists())

    def test_readable_partial_schema_returns_hold_without_changes(self):
        root = directory("journal-partial-schema")
        journal = Journal(root / "journal", retain_files=True)
        try:
            with journal.connect() as db:
                # Preserve the original table; no DROP or deletion in the fixture.
                db.execute("ALTER TABLE operations RENAME TO retained_original_operations")
                db.execute("CREATE TABLE operations (id TEXT PRIMARY KEY)")
                db.execute("INSERT INTO operations VALUES (?)", (uid(),))
        finally:
            journal.close()
        before = contents(root / "journal")
        report = recover_operations(root / "journal")
        self.assertEqual(report["state"], "held-uncertain")
        self.assertTrue(report["errors"])
        self.assertFalse(report["restart_admitted"])
        self.assertEqual(contents(root / "journal"), before)
        OBSERVATIONS.append({"variant": "readable-partial-schema", "recovery": report, "unchanged_files": before})


@unittest.skipUnless(os.name == "nt", "Windows retained crash process fixture")
class CrashJournalTests(unittest.TestCase):
    def crash(self, phase, exit_code, expected_state):
        root = directory("journal-crash-" + phase)
        child = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("journal_dispatch_fixture.py")),
            str(root), phase], env=environment(), capture_output=True, timeout=15, creationflags=0x08000000)
        self.assertEqual(child.returncode, exit_code, child.stderr.decode(errors="replace"))
        self.assertEqual(child.stdout, b"")
        self.assertEqual(child.stderr, b"")
        before = contents(root / "journal")
        recovery = recover_operations(root / "journal")
        self.assertEqual(recovery["operations"][0]["state"], expected_state)
        self.assertEqual(recovery["state"], "held-uncertain")
        self.assertFalse(recovery["restart_admitted"])
        with self.assertRaises(Refusal): Journal(root / "journal", retain_files=True)
        self.assertEqual(contents(root / "journal"), before)
        self.assertTrue((root / "journal/seat.lock").exists())
        self.assertTrue((root / "journal/operations.sqlite-journal").exists())
        if phase == "after-effect":
            observed = load(root / "effect-observation.json")
            self.assertEqual(observed["observed_counter"], 4)
            self.assertEqual(observed["operation"], recovery["operations"][0]["id"])
        else:
            self.assertFalse((root / "effect-observation.json").exists())
        record = {"variant": "actual-process-crash-" + phase, "exit_code": exit_code, "recovery": recovery,
                  "unchanged_retained_files": before, "provenance": "fixed parent instrumentation observes volatile counter only; no replay/restored counter"}
        retain(root / "recovery-observation.json", record)
        OBSERVATIONS.append(record)

    def test_actual_crash_after_accepted_commit(self): self.crash("accepted", 71, "accepted")
    def test_actual_crash_after_executing_before_effect(self): self.crash("before-effect", 72, "executing")
    def test_actual_crash_after_counter_before_outcome(self): self.crash("after-effect", 73, "executing")
