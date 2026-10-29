from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from portable_fleet.core import Refusal
from portable_fleet.provider_usage import ProfileScope
from portable_fleet.provider_windows import DefaultProfileContext, DEFAULT_ROUTE, scope_settings_fingerprint, native_boot

REQUIRED_NATIVE_DENIES = ("command(*)", "read_file(*)", "write_file(*)", "read_url(*)", "execute_url(*)", "mcp(*)")


class ProfileContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.profile = self.home / ".gemini/antigravity-cli"
        self.profile.mkdir(parents=True)
        self.path = self.profile / "settings.json"
        self.settings = {"toolPermission": "strict", "permissions": {"deny": list(REQUIRED_NATIVE_DENIES)}}
        self.path.write_text(json.dumps(self.settings), encoding="utf-8")
        self.scope = ProfileScope("attested-profile", "owner", "bounded test", 1, "HOST", "boot", "SID", 1,
                                  str(self.profile), DEFAULT_ROUTE,
                                  configuration_sha256=scope_settings_fingerprint(self.settings))
        self.enterContext(patch("portable_fleet.provider_windows.Path.home", return_value=self.home))
        self.enterContext(patch("portable_fleet.provider_windows.identity", return_value={"host": "host", "sid": "SID", "session": 1}))
        self.enterContext(patch("portable_fleet.provider_windows.native_boot", return_value="boot"))

    def test_effective_false_and_trust_only_do_not_change_profile(self):
        reader = DefaultProfileContext(self.scope)
        self.assertEqual(reader(), self.scope)
        self.path.write_text(json.dumps({**self.settings, "useG1Credits": False,
                                         "allowNonWorkspaceAccess": False, "disableSlashCommands": False,
                                         "trustedWorkspaces": ["C:/owned/new"], "verbosity": "low"}), encoding="utf-8")
        self.assertEqual(reader(), self.scope)

    def test_routing_key_is_refused_without_inspecting_its_value(self):
        class SecretValue:
            def __str__(self):
                raise AssertionError("Protected value inspected")
        for name in ("modelProvider", "gcp", "api_key", "nested-endpoint", "auth"):
            with self.subTest(name=name), self.assertRaises(Refusal):
                scope_settings_fingerprint({**self.settings, name: SecretValue()})
        for value in (True, "false", None):
            with self.subTest(flag=value), self.assertRaises(Refusal):
                scope_settings_fingerprint({**self.settings, "useG1Credits": value})

    def test_native_identity_change_refuses_before_settings_read(self):
        reader = DefaultProfileContext(self.scope)
        with patch("portable_fleet.provider_windows.native_boot", return_value="new-boot"), patch.object(Path, "open", side_effect=AssertionError("Read wrong profile")):
            with self.assertRaisesRegex(Refusal, "Native"):
                reader()
        with patch("portable_fleet.provider_windows.identity", return_value={"host": "host", "sid": "OTHER", "session": 1}), patch.object(Path, "open", side_effect=AssertionError("Read wrong identity")):
            with self.assertRaisesRegex(Refusal, "Native"):
                reader()

    def test_missing_native_deny_cannot_keep_the_admitted_policy(self):
        reader = DefaultProfileContext(self.scope)
        for missing in REQUIRED_NATIVE_DENIES:
            settings = {**self.settings, "permissions": {"deny": [rule for rule in REQUIRED_NATIVE_DENIES if rule != missing] + ["unsandboxed(*)"]}}
            self.path.write_text(json.dumps(settings), encoding="utf-8")
            with self.subTest(missing=missing), self.assertRaisesRegex(Refusal, "Six recognized"):
                reader()
    def test_unsealed_fingerprint_and_nondefault_profile_refuse(self):
        with self.assertRaisesRegex(Refusal, "sealed"):
            DefaultProfileContext(replace(self.scope, configuration_sha256="0" * 64))
        reader = DefaultProfileContext(replace(self.scope, profile_root=str(self.home / "other")))
        with self.assertRaisesRegex(Refusal, "profile changed"):
            reader()

    def test_malformed_oversized_or_unsafe_settings_refuse(self):
        reader = DefaultProfileContext(self.scope)
        for raw in (b'{"toolPermission":"strict","toolPermission":"strict"}',
                    b'{"toolPermission":"strict","x":NaN}',
                    ("[" * 2000 + "0" + "]" * 2000).encode(),
                    b" " * 65537, b"\xff", b"[]",
                    b'{"toolPermission":"always-proceed"}'):
            with self.subTest(raw=raw[:40]):
                self.path.write_bytes(raw)
                with self.assertRaises(Refusal):
                    reader()


if __name__ == "__main__":
    unittest.main()
