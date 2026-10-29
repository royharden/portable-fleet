"""Pinned public console adapter. No raw worker entrypoint or automatic launch/auth."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess

from .core import Refusal, command, verify
from .watchdog import WindowsProcess
from .process_time import CreationTime


def _unique_public_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate public JSON key")
        result[key] = value
    return result


class PublicConsole:
    def __init__(self, identity, dependency_root, manifest, expected_digest, pwsh, cli,
                 identity_probe, operator_marker, scratch, permit_check):
        if cli not in ("agy", "claude"):
            raise Refusal("Initial real-console candidates are AGY or approved Claude")
        identity.validate()
        self.identity = identity
        self.root = Path(dependency_root)
        self.manifest = manifest
        self.pin = expected_digest
        self.pwsh, self.cli = pwsh, cli
        self.probe, self.marker, self.scratch = identity_probe, Path(operator_marker), Path(scratch)
        self.permit_check = permit_check

    def validate(self, expected, kind):
        if expected != asdict(self.identity) or self.probe() != expected:
            raise Refusal("Full current identity mismatch")
        if verify(self.root, self.manifest) != self.pin:
            raise Refusal("Pinned console dependency changed")
        if kind not in ("read", "send"):
            raise Refusal("Esc/stop need separately admitted public/owned adapters")
        if kind == "send" and (self.marker.exists() or not self.permit_check()):
            raise Refusal("Operator control or expired admission")

    def act(self, kind, text):
        self.validate(asdict(self.identity), kind)
        retained = WindowsProcess(self.identity.pid, CreationTime(self.identity.creation_ticks, self.identity.creation_time_unit))
        try:
            if not retained.alive():
                raise Refusal("Owned console ended")
            script = "Read-ConsoleTail.ps1" if kind == "read" else "Send-ConsoleMessage.ps1"
            args = ["-NoProfile", "-NonInteractive", "-File", str(self.root / "scripts" / script),
                    "-TargetPid", str(self.identity.pid), "-AllowPid", str(self.identity.pid), "-Cli", self.cli, "-Json"]
            if kind == "send":
                args += ["-Text", text, "-Mode", "queue", "-Verify", "-NoEnterRetry"]
            import os
            env = dict(os.environ, CONSOLE_DIRECT_SEND_SCRATCH=str(self.scratch))
            try:
                result = subprocess.run(command(self.pwsh, args), shell=False, env=env, capture_output=True, timeout=100)
            except subprocess.TimeoutExpired:
                raise Refusal("Public sender timed out: outcome uncertain, never resend") from None
            # Script errors, partial output and timeouts leave journal executing/uncertain.
            try:
                output = json.loads(result.stdout.decode("utf-8-sig"), object_pairs_hook=_unique_public_object)
            except (UnicodeDecodeError, ValueError):
                # Never guess an OEM code page or replace damaged console text:
                # that could turn a dialog/draft into apparently admissible input.
                raise Refusal("Invalid public JSON encoding: outcome uncertain, never resend") from None
            if not isinstance(output, dict) or result.returncode or output.get("success") is not True:
                raise Refusal("Public adapter refused/failed: inspect private result before recovery")
            return {"variant": "public-console", "public_result": output,
                    "assistant_response": None, "submitted": output.get("submitted", False),
                    "visible_admission": output.get("verified", False)}
        finally:
            retained.close()
