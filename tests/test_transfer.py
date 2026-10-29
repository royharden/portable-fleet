from pathlib import Path
import subprocess
import tempfile
import unittest

from portable_fleet.core import Refusal, canonical, digest, load
from portable_fleet.transfer import *


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fleet-transfer ' ü ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_parent_child_restore_corrupt_and_collision(self):
        source = self.root / "source"
        source.mkdir()
        (source / "parent.jsonl").write_bytes(b'{"id":"parent"}\n')
        (source / "child.jsonl").write_bytes(b'{"id":"child","parent":"parent"}\n')
        (source / "private").write_text("not authorized")
        pin = capture(source, ["parent.jsonl", "child.jsonl"], self.root / "version1",
                      {"variant": "fixture", "parent": "parent", "children": ["child"], "boundary": "complete-fixture"})
        restore(self.root / "version1", self.root / "restored", pin)
        self.assertEqual((source / "parent.jsonl").read_bytes(), (self.root / "restored/parent.jsonl").read_bytes())
        self.assertFalse((self.root / "restored/private").exists())
        with self.assertRaises(FileExistsError):
            restore(self.root / "version1", self.root / "restored", pin)
        (self.root / "version1/child.jsonl").write_text("corrupt")
        with self.assertRaises(Refusal):
            restore(self.root / "version1", self.root / "corrupt", pin)

    def fixture(self):
        source = self.root / "source"
        source.mkdir()
        git(source, "init")
        git(source, "config", "user.name", "Fixture")
        git(source, "config", "user.email", "fixture@example.invalid")
        for name in ("same.txt", "delete.txt", "rename.txt"):
            (source / name).write_text("base\n")
        (source / "binary.bin").write_bytes(b"\0base\xff")
        git(source, "add", ".")
        git(source, "commit", "-m", "fixture base")
        (source / "same.txt").write_text("staged\n")
        (source / "binary.bin").write_bytes(b"\0staged\xfe")
        git(source, "add", "same.txt", "binary.bin")
        (source / "same.txt").write_text("unstaged\n")
        (source / "binary.bin").write_bytes(b"\0unstaged\xfd")
        git(source, "mv", "rename.txt", "renamed.txt")
        (source / "delete.txt").unlink()
        (source / "untracked ü.txt").write_text("approved note")
        notes = self.root / "notes"
        notes.mkdir()
        (notes / "registry.json").write_text('{"ids":["0000","0001"],"high_water":"0001"}')
        (notes / "counters.json").write_text('{"INT":3,"D":9}')
        close_source(self.root / "authority", "fixture-project", 1, {"variant": "fixture", "all_ended": True, "launches": []})
        return source, notes

    def test_index_worktree_binary_rename_delete_notes_and_fencing(self):
        source, notes = self.fixture()
        before = git(source, "status", "--porcelain=v1", "-z")
        index_before = (source / ".git/index").read_bytes()
        pin = export_git(source, self.root / "packet", self.root / "authority", ["untracked ü.txt"], notes, ["registry.json", "counters.json"])
        acceptance = import_git(self.root / "packet", self.root / "target", pin, self.root / "target-authority")
        self.assertEqual(git(self.root / "target", "diff", "--cached", "--binary"), git(source, "diff", "--cached", "--binary"))
        self.assertEqual(git(self.root / "target", "diff", "--binary"), git(source, "diff", "--binary"))
        self.assertFalse(admission(self.root / "target-authority", 2))
        wrong = {**acceptance, "generation": 99}
        with self.assertRaises(Refusal):
            acknowledge(self.root / "authority", wrong)
        ack_digest = acknowledge(self.root / "authority", acceptance)
        with self.assertRaises(Refusal):
            admit_target(self.root / "target-authority", wrong, ack_digest)
        admit_target(self.root / "target-authority", acceptance, ack_digest)
        self.assertTrue(admission(self.root / "target-authority", 2))
        self.assertFalse(admission(self.root / "target-authority", 1))
        self.assertFalse(admission(self.root / "authority", 1))
        self.assertTrue((self.root / "authority/closed.json").exists())
        self.assertEqual(git(source, "status", "--porcelain=v1", "-z"), before)
        # Source content/staging preserved; Git may refresh cache metadata on read operations.
        self.assertEqual(load(self.root / "packet/notes/registry.json")["high_water"], "0001")
        # Reverse transfer through a fresh authority: index/worktree remain separate twice.
        close_source(self.root / "target-authority", "fixture-project", 2, {"variant": "fixture", "all_ended": True, "launches": []})
        self.assertFalse(admission(self.root / "target-authority", 2))
        back_pin = export_git(self.root / "target", self.root / "return-packet", self.root / "target-authority", ["untracked ü.txt"], notes, ["registry.json", "counters.json"])
        back = import_git(self.root / "return-packet", self.root / "returned", back_pin, self.root / "returned-authority")
        self.assertEqual(back["generation"], 3)
        self.assertEqual(git(self.root / "returned", "diff", "--binary"), git(source, "diff", "--binary"))

    def test_missing_untracked_or_corrupt_partial_holds(self):
        source, notes = self.fixture()
        with self.assertRaises(Refusal):
            export_git(source, self.root / "bad", self.root / "authority", [], notes, [])
        pin = export_git(source, self.root / "packet", self.root / "authority", ["untracked ü.txt"], notes, [])
        (self.root / "packet/index.patch").write_bytes(b"corrupt")
        with self.assertRaises(Refusal):
            import_git(self.root / "packet", self.root / "target", pin, self.root / "target-authority")
        self.assertFalse((self.root / "target").exists())
        self.assertTrue((self.root / "authority/closed.json").exists())
