import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from portable_fleet.core import *


class Foundations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fleet ' ü ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "a.txt").write_text("héllo ' spaces", encoding="utf-8")

    def test_release_dependency_hash_and_collision(self):
        manifest = make_manifest(self.root, ["a.txt"], {"a.txt": []})
        pin = package(self.root, self.root / "release", manifest)
        self.assertEqual(verify(self.root / "release", manifest), pin)
        with self.assertRaises(FileExistsError):
            package(self.root, self.root / "release", manifest)
        with self.assertRaises(Refusal):
            make_manifest(self.root, ["a.txt"], {"a.txt": ["missing"]})
        (self.root / "release/a.txt").write_text("changed")
        with self.assertRaises(Refusal):
            verify(self.root / "release", manifest)

    def test_paths_and_case_collisions(self):
        for name in ("../a.txt", "/a.txt", "C:/a", "a/../b", "a\\b", "NUL", "a.", "a//b", "x:stream"):
            with self.subTest(name=name), self.assertRaises(Refusal):
                within(self.root, name)
        with self.assertRaises(Refusal):
            inventory(self.root, ["a.txt", "A.TXT"])
        try:
            (self.root / "link").symlink_to(self.root / "a.txt")
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        with self.assertRaises(Refusal):
            inventory(self.root, ["link"])

    def test_profile_missing_ambiguous_unknown_and_precedence(self):
        value = {"schema": 1, "host_id": str(uuid.uuid4()), "hostname": "fixture", "pj_root": str(self.root),
                 "skills_root": str(self.root), "state_root": str(self.root), "projects": []}
        config = self.root / "profile.json"
        config.write_bytes(canonical(value))
        self.assertEqual(profile(config)["hostname"], "fixture")
        self.assertEqual(select_config("missing", {"FLEET_CONFIG": str(config)}), Path("missing"))
        with self.assertRaises(FileNotFoundError):
            profile(select_config("missing", {"FLEET_CONFIG": str(config)}))
        value["pj_root"] = [str(self.root), str(self.root)]
        config.write_bytes(canonical(value))
        with self.assertRaises((Refusal, TypeError)):
            profile(config)
        value["pj_root"] = str(self.root / "missing")
        config.write_bytes(canonical(value))
        with self.assertRaises(Refusal):
            profile(config)
        config.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(Refusal):
            load(config)

    def test_argv_round_trip_without_shell(self):
        args = ["space here", "apostrophe'", 'quote"x', "Ünicode", "trailing\\", "$() ; &"]
        result = subprocess.run(command(sys.executable, ["-c", "import sys,json;print(json.dumps(sys.argv[1:]))", *args]), capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), args)
        self.assertIsInstance(windows_commandline(args), str)

    def test_publish_never_overwrites(self):
        publish(self.root / "new", b"one")
        with self.assertRaises(Refusal):
            publish(self.root / "new", b"two")
        self.assertEqual((self.root / "new").read_bytes(), b"one")

    def test_generated_run_pins_profile_and_release(self):
        config = self.root / "host.json"
        config.write_bytes(canonical({"schema": 1, "host_id": str(uuid.uuid4()), "hostname": "fixture",
            "pj_root": str(self.root), "skills_root": str(self.root), "state_root": str(self.root), "projects": []}))
        envelope = generate_run(self.root, self.root / "run", make_manifest(self.root, ["a.txt"], {}), config)
        self.assertEqual(envelope["admission"], "closed")
        self.assertEqual(envelope["environment"]["SKILLS_ROOT"], envelope["environment"]["PJ_SKILLS"])
        self.assertEqual(envelope["profile_digest"], digest(canonical(profile(config))))
        self.assertEqual(load(self.root / "run/run.json"), envelope)
