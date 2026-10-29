"""No-cleanup regression gate: no temporary directories, deletion, models or remote calls."""
from dataclasses import asdict
import json
import os
import shutil
import subprocess
import sys
import queue
import threading
import unittest

from portable_fleet.core import Refusal
from portable_fleet.process_time import CreationTime, DOTNET_TICKS, EPOCH_OFFSET, FILETIME, MAX_DOTNET_TICKS, MAX_FILETIME, legacy_dotnet_creation_time
from portable_fleet.seat import Identity
from portable_fleet.watchdog import WindowsProcess, query_creation_time


LIVE_OBSERVATIONS = []


def read_line_bounded(stream, timeout):
    """One blocking queue wait, not a repeated readiness/status poll."""
    result = queue.Queue(maxsize=1)

    def read():
        try:
            result.put((True, stream.readline()))
        except Exception as error:
            result.put((False, error))

    threading.Thread(target=read, daemon=True).start()
    try:
        successful, value = result.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError("Owned fixture did not produce its identity in time") from None
    if not successful:
        raise value
    return value


class ProcessTimeTests(unittest.TestCase):
    def test_exact_integer_conversion_and_roundtrip(self):
        # Precision-sensitive actual historical creation value; float conversion loses ticks.
        expected = 134376348003022961
        legacy = expected + EPOCH_OFFSET
        self.assertEqual(CreationTime(legacy, DOTNET_TICKS).filetime(), expected)
        self.assertEqual(CreationTime(expected, FILETIME).filetime(), expected)
        self.assertEqual(legacy_dotnet_creation_time(legacy), CreationTime(expected, FILETIME))
        self.assertEqual(CreationTime(MAX_DOTNET_TICKS, DOTNET_TICKS).filetime(), MAX_FILETIME)

    def test_missing_unknown_units_and_numeric_types_refuse(self):
        for value in (None, True, False, 1.0, "134376348003022961", -1, 0, MAX_FILETIME + 1):
            with self.subTest(value=value), self.assertRaises(Refusal):
                CreationTime(value, FILETIME).filetime()
        for unit in (None, "ticks", "", "filetime", 1):
            with self.subTest(unit=unit), self.assertRaises(Refusal):
                CreationTime(134376348003022961, unit).filetime()
        for value in (EPOCH_OFFSET, EPOCH_OFFSET - 1, MAX_DOTNET_TICKS + 1):
            with self.subTest(value=value), self.assertRaises(Refusal):
                CreationTime(value, DOTNET_TICKS).filetime()

    def test_fixed_record_schema_and_legacy_is_explicit(self):
        stamp = CreationTime.from_record({"value": 123, "unit": FILETIME})
        self.assertEqual(stamp.filetime(), 123)
        for record in ({"value": 123}, {"creationTicks": 639287652324701544},
                       {"value": 123, "unit": FILETIME, "other": True}):
            with self.subTest(record=record), self.assertRaises(Refusal):
                CreationTime.from_record(record)
        with self.assertRaises(Refusal):
            WindowsProcess(1, None)
        with self.assertRaises(Refusal):
            WindowsProcess(1, 134376348003022961)

    def test_identity_requires_both_process_and_parent_units(self):
        uid = "00000000-0000-4000-8000-000000000001"
        record = dict(host=uid, boot="fixture", sid="fixture", session=1, helper=uid, project=uid,
                      generation=1, run=uid, seat=uid, launch=uid, pid=1, creation_ticks=2,
                      executable="fixture", parent_pid=3, parent_ticks=4,
                      creation_time_unit=FILETIME, parent_time_unit=FILETIME)
        Identity(**record).validate()
        for key in ("creation_time_unit", "parent_time_unit"):
            wrong = {**record, key: "unknown"}
            with self.subTest(field=key), self.assertRaises(Refusal):
                Identity(**wrong).validate()
            missing = {k: v for k, v in record.items() if k != key}
            with self.assertRaises(TypeError):
                Identity(**missing)

    def test_failed_wait_is_unknown_never_ended(self):
        class FakeAPI:
            def __init__(self, result):
                self.result = result

            def WaitForSingleObject(self, handle, timeout):
                return self.result

        process = WindowsProcess.__new__(WindowsProcess)
        process.handle = 1
        for result in (0xffffffff, -1, 0x80, 17):
            process.api = FakeAPI(result)
            with self.subTest(result=result), self.assertRaises(Refusal):
                process.alive()
        process.api = FakeAPI(0)
        self.assertFalse(process.alive())
        process.api = FakeAPI(0x102)
        self.assertTrue(process.alive())
        process.handle = None
        with self.assertRaises(Refusal):
            process.alive()

    def test_first_read_has_its_own_timeout(self):
        release = threading.Event()

        class SlowStream:
            def readline(self):
                release.wait(1)
                return b"late"

        try:
            with self.assertRaises(TimeoutError):
                read_line_bounded(SlowStream(), .01)
        finally:
            release.set()

    @unittest.skipUnless(os.name == "nt", "Windows native identity integration")
    def test_live_owned_process_matches_both_shells_without_cleanup(self):
        # Natural exit is expected. Only an owned Popen handle can be stopped on timeout;
        # there is no filesystem cleanup, broad process match or PID-based fallback kill.
        script = r"""$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')
$self=Get-Process -Id $PID
@{pid=$PID;creationTime=@{value=$self.StartTime.ToFileTimeUtc();unit='windows-filetime-100ns'};legacyTicks=$self.StartTime.ToUniversalTime().Ticks} | ConvertTo-Json -Compress
$request=[Console]::In.ReadLineAsync()
if(-not $request.Wait(8000)){exit 92}
if($request.Result -cne 'fixture-exit'){exit 91}
exit 0
"""
        import base64
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        for shell in ("powershell.exe", "pwsh"):
            with self.subTest(shell=shell):
                executable = shutil.which(shell)
                self.assertIsNotNone(executable)
                child = subprocess.Popen([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                retained = None
                try:
                    line = read_line_bounded(child.stdout, 10)
                    record = json.loads(line.decode("utf-8-sig"))
                    self.assertEqual(record["pid"], child.pid)
                    stamp = CreationTime.from_record(record["creationTime"])
                    self.assertEqual(query_creation_time(child.pid), stamp)
                    self.assertEqual(legacy_dotnet_creation_time(record["legacyTicks"]), stamp)
                    retained = WindowsProcess(child.pid, stamp)
                    self.assertTrue(retained.alive())
                    legacy_handle = WindowsProcess(child.pid, CreationTime(record["legacyTicks"], DOTNET_TICKS))
                    legacy_handle.close()
                    with self.assertRaises(Refusal):
                        WindowsProcess(child.pid, CreationTime(stamp.value + 1, FILETIME))
                    with self.assertRaises(Refusal):
                        WindowsProcess(child.pid, CreationTime(record["legacyTicks"], FILETIME))
                    child.stdin.write(b"fixture-exit\r\n")
                    child.stdin.flush()
                    child.stdin.close()
                    child.wait(timeout=10)
                    stderr = child.stderr.read()
                    self.assertEqual(child.returncode, 0, stderr.decode(errors="replace"))
                    self.assertFalse(retained.alive())
                    LIVE_OBSERVATIONS.append({"shell": shell, "pid": child.pid, "creationTime": record["creationTime"],
                        "legacyTicks": record["legacyTicks"], "matched_native": True, "wrong_pin_refused": True,
                        "natural_exit": True, "exit_code": child.returncode})
                finally:
                    if retained:
                        retained.close()
                    if child.returncode is None:
                        try:
                            if not child.stdin.closed:
                                child.stdin.write(b"fixture-exit\r\n")
                                child.stdin.flush()
                                child.stdin.close()
                        except (OSError, BrokenPipeError):
                            pass
                        try:
                            child.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            child.terminate()  # exact retained owned handle, never a file deletion
                            child.wait(timeout=5)
                    child.stdout.close()
                    child.stderr.close()


if __name__ == "__main__":
    unittest.main()
