from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from portable_fleet.core import Refusal
from portable_fleet.process_time import FILETIME
from portable_fleet.seat import Identity, Journal
from portable_fleet.windows_console import PublicConsole


class ConsoleWireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)  # Only this test's newly created files.
        root = Path(self.temp.name)
        uid = lambda: str(uuid.uuid4())
        self.identity = Identity(uid(), "boot", "fixture-sid", 1, uid(), uid(), 1,
                                 uid(), uid(), uid(), 123, 456, "fixture.exe", 122, 455, FILETIME, FILETIME)
        self.console = PublicConsole(self.identity, root, {}, "pin", sys.executable,
                                     "agy", lambda: asdict(self.identity), root / "operator",
                                     root / "ipc", lambda: True)
        self.verify = self.enterContext(patch("portable_fleet.windows_console.verify", return_value="pin"))
        self.process = self.enterContext(patch("portable_fleet.windows_console.WindowsProcess"))
        self.process.return_value.alive.return_value = True
        self.invoke = self.enterContext(patch("portable_fleet.windows_console.subprocess.run"))

    def response(self, raw):
        self.invoke.return_value = subprocess.CompletedProcess([], 0, raw, b"")

    def test_escaped_nonascii_and_utf8_remain_exact(self):
        # A real OEM console changed an arrow into raw SUB and a box into0xC0.
        # ASCII-escaped public JSON must preserve those exact Unicode characters.
        text = "\u2514 \u2192 \u2022 \U0001f680"
        for escaped in (True, False):
            with self.subTest(escaped=escaped):
                self.response(json.dumps({"success": True, "state": {"tail": text}},
                                         ensure_ascii=escaped).encode("utf-8"))
                result = self.console.act("read", "")
                self.assertEqual(result["public_result"]["state"]["tail"], text)

    def test_oem_or_control_damage_is_uncertain_and_replay_never_resends(self):
        for raw in (b'{"success":true,"tail":"\xc0"}', b'{"success":true,"tail":"\x1a"}'):
            with self.subTest(raw=raw):
                journal = Journal(Path(self.temp.name) / str(uuid.uuid4()))
                request = {"schema": 1, "operation": str(uuid.uuid4()), "identity": asdict(self.identity),
                           "kind": "send", "expires": 100, "text": "one fixed message"}
                self.response(raw)
                before = self.invoke.call_count
                with self.assertRaisesRegex(Refusal, "encoding.*uncertain"):
                    journal.execute(request, self.console, now=1)
                self.assertEqual(self.invoke.call_count, before + 1)
                args = self.invoke.call_args.args[0]
                self.assertIn("-NoEnterRetry", args)
                self.assertIn("queue", args)
                self.assertEqual(journal.execute(request, self.console, now=2)["state"], "uncertain")
                self.assertEqual(self.invoke.call_count, before + 1)
                self.process.return_value.close.assert_called()

    def test_nonobject_or_false_success_refuses(self):
        for value in ([], None, {"success": "true"}, {"success": False}):
            with self.subTest(value=value):
                self.response(json.dumps(value).encode())
                with self.assertRaises(Refusal):
                    self.console.act("read", "")

    def test_timeout_has_one_call_and_no_success(self):
        self.invoke.side_effect = subprocess.TimeoutExpired("public", 100)
        with self.assertRaisesRegex(Refusal, "uncertain, never resend"):
            self.console.act("send", "one fixed message")
        self.assertEqual(self.invoke.call_count, 1)
        self.process.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
