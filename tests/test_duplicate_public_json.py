"""Meaningful malformed-wire regressions; must fail old adapter and pass fix."""
from dataclasses import asdict
from pathlib import Path
import unittest
import uuid

from portable_fleet.core import Refusal
from portable_fleet.seat import Journal
from test_windows_console import ConsoleWireTests

class DuplicatePublicJsonTests(unittest.TestCase):
    setUp=ConsoleWireTests.setUp
    response=ConsoleWireTests.response
    def test_contradictory_duplicate_success_is_uncertain(self):
        self.response(b'{"success":false,"success":true}')
        with self.assertRaises(Refusal):self.console.act('read','')
        self.assertEqual(self.invoke.call_count,1)
    def test_duplicate_nested_state_keys_are_refused(self):
        for raw in (b'{"success":true,"state":{"blocked":true,"blocked":false}}',b'{"success":true,"state":{"ready":false},"state":{"ready":true}}'):
            with self.subTest(raw=raw):
                self.response(raw)
                with self.assertRaises(Refusal):self.console.act('read','')
    def test_duplicate_identical_keys_are_also_refused(self):
        self.response(b'{"success":true,"state":{"tail":"x","tail":"x"}}')
        with self.assertRaises(Refusal):self.console.act('read','')
    def test_duplicate_send_is_uncertain_and_replay_never_retypes(self):
        journal=Journal(Path(self.temp.name)/str(uuid.uuid4()))
        request=dict(schema=1,operation=str(uuid.uuid4()),identity=asdict(self.identity),kind='send',expires=100,text='one fixed fixture message')
        self.response(b'{"success":false,"success":true,"submitted":true}')
        with self.assertRaises(Refusal):journal.execute(request,self.console,now=1)
        self.assertEqual(self.invoke.call_count,1)
        self.assertEqual(journal.execute(request,self.console,now=2)['state'],'uncertain')
        self.assertEqual(self.invoke.call_count,1)
        self.assertIn('-NoEnterRetry',self.invoke.call_args.args[0])

if __name__=='__main__':unittest.main()
