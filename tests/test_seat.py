from dataclasses import asdict, replace
from pathlib import Path
import tempfile
import unittest
import uuid

from portable_fleet.core import Refusal
from portable_fleet.seat import Identity, Journal, SyntheticConsole, read_status
from portable_fleet.process_time import FILETIME


def uid():
    return str(uuid.uuid4())


def identity():
    return Identity(uid(), "boot-1", "fixture-sid", 1, uid(), uid(), 1, uid(), uid(), uid(), 100, 1234, "fixture.exe", 99, 1233, FILETIME, FILETIME)


class SeatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = Journal(self.temp.name)
        self.console = SyntheticConsole(identity())

    def request(self, kind="send", text="hello"):
        return {"schema": 1, "operation": uid(), "identity": asdict(self.console.identity), "kind": kind, "expires": 100, "text": text}

    def test_duplicate_and_lost_response_no_retype(self):
        req = self.request()
        first = self.journal.execute(req, self.console, now=1)
        restarted = Journal(self.temp.name)
        self.assertEqual(restarted.execute(req, self.console, now=200), first)
        self.assertEqual(len(self.console.events), 1)
        req["text"] = "changed"
        with self.assertRaises(Refusal):
            restarted.execute(req, self.console, now=1)

    def test_crash_after_action_is_uncertain_and_holds_new_send(self):
        req = self.request()
        with self.assertRaises(RuntimeError):
            self.journal.execute(req, self.console, now=1, crash_after_action=True)
        self.assertEqual(self.journal.execute(req, self.console, now=1)["state"], "uncertain")
        with self.assertRaises(Refusal):
            self.journal.execute(self.request(), self.console, now=1)
        self.assertEqual(len(self.console.events), 1)

    def test_identity_all_fields_refused(self):
        for key, value in asdict(self.console.identity).items():
            req = self.request()
            req["identity"][key] = value + 1 if type(value) is int else value + "wrong"
            with self.subTest(field=key), self.assertRaises(Refusal):
                self.journal.execute(req, self.console, now=1)
        self.assertFalse(self.console.events)

    def test_invalid_and_unknown_dialog_operator_draft(self):
        for text in ("", "\n", "a\nb", "\x1b", "😀", "x" * 8193):
            with self.subTest(text=text[:10]), self.assertRaises(Refusal):
                self.journal.execute(self.request(text=text), self.console, now=1)
        for field, value in (("dialog", "trust"), ("operator", True), ("draft", "keep me")):
            setattr(self.console, field, value)
            with self.assertRaises(Refusal):
                self.journal.execute(self.request(), self.console, now=1)
            setattr(self.console, field, {"dialog": "ready", "operator": False, "draft": ""}[field])
        req = self.request("launch", "")
        with self.assertRaises(Refusal):
            self.journal.execute(req, self.console, now=1)

    def test_owned_esc_stop_sentinel_survival(self):
        sentinel = SyntheticConsole(identity())
        with self.assertRaises(Refusal):
            self.journal.execute(self.request("esc", ""), self.console, now=1)
        self.console.dialog = "owned-daybreak"
        self.journal.execute(self.request("esc", ""), self.console, now=1)
        self.journal.execute(self.request("stop", ""), self.console, now=1)
        self.assertFalse(self.console.alive)
        self.assertTrue(sentinel.alive)
        self.assertEqual(sentinel.events, [])

    def test_stale_lock_is_hold(self):
        (Path(self.temp.name) / "seat.lock").write_text("crashed")
        with self.assertRaises(Refusal):
            self.journal.execute(self.request(), self.console, now=1)

    def test_read_only_status_never_creates_or_changes_database(self):
        import sqlite3
        path = Path(self.temp.name) / "operations.sqlite"
        before = path.read_bytes()
        self.assertEqual(read_status(self.temp.name), [])
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaises(sqlite3.OperationalError):
            read_status(Path(self.temp.name) / "missing")
        self.assertFalse((Path(self.temp.name) / "missing").exists())

    def test_real_process_crash_after_effect_survives_restart(self):
        import json
        import subprocess
        import sys
        req = self.request()
        effect = Path(self.temp.name) / "effect.txt"
        code = '''import json,os,sys
from pathlib import Path
from portable_fleet.seat import Journal,Identity,SyntheticConsole
request=json.loads(sys.argv[2])
class Crash(SyntheticConsole):
 def act(self,kind,text):
  with open(sys.argv[3],'x') as stream:
   stream.write(text);stream.flush();os.fsync(stream.fileno())
  os._exit(73)
Journal(sys.argv[1]).execute(request,Crash(Identity(**request['identity'])),now=1)
'''
        child = subprocess.run([sys.executable, "-c", code, self.temp.name, json.dumps(req), str(effect)], capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 73, child.stderr.decode(errors="replace"))
        self.assertEqual(effect.read_text(), req["text"])
        self.assertEqual(read_status(self.temp.name)[0]["state"], "executing")
        with self.assertRaises(Refusal):
            self.journal.execute(req, self.console, now=1)
        # Explicit simulated operator recovery of only this disposable lock.
        (Path(self.temp.name) / "seat.lock").unlink()
        self.assertEqual(self.journal.execute(req, self.console, now=1)["state"], "uncertain")
        self.assertEqual(self.console.events, [])
        self.assertEqual(effect.read_text(), req["text"])
