"""Independent Windows watchdog for a disposable process, using a retained kernel handle.

No child-tree/production admission: this adapter deliberately supports a single fixture PID.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import time

from .core import Refusal, load, publish, canonical
from .process_time import CreationTime, FILETIME, DOTNET_TICKS
from .supervision import expired


def _kernel_api(pid):
    if os.name != "nt":
        raise Refusal("Windows adapter required")
    if type(pid) is not int or not 0 < pid <= 0xffffffff:
        raise Refusal("Invalid PID")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    return api


def _creation_time(api, handle):
    times = [wintypes.FILETIME() for _ in range(4)]
    if not api.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
        raise Refusal("Cannot read creation identity")
    value = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    stamp = CreationTime(value, FILETIME)
    stamp.filetime()
    return stamp


def query_creation_time(pid):
    """Read-only discovery: no terminate/synchronize rights and no actionable handle."""
    api = _kernel_api(pid)
    handle = api.OpenProcess(0x1000, False, pid)
    if not handle:
        raise Refusal("Cannot observe process creation identity")
    try:
        return _creation_time(api, handle)
    finally:
        api.CloseHandle(handle)


class WindowsProcess:
    def __init__(self, pid, expected):
        if not isinstance(expected, CreationTime):
            raise Refusal("An explicit unit-tagged creation-time pin is required")
        expected_filetime = expected.filetime()
        self.api = _kernel_api(pid)
        self.handle = self.api.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
        if not self.handle:
            raise Refusal("Cannot retain process handle")
        try:
            self.creation_time = _creation_time(self.api, self.handle)
            if self.creation_time.value != expected_filetime:
                raise Refusal("Reused/wrong PID or creation-time pin")
        except BaseException:
            self.close()
            raise

    def alive(self):
        if not self.handle:
            raise Refusal("Process handle is closed")
        result = self.api.WaitForSingleObject(self.handle, 0)
        if result == 0x102:
            return True
        if result == 0:
            return False
        raise Refusal(f"Process wait failed: {result}; end state unknown")

    def stop(self):
        if self.alive() and not self.api.TerminateProcess(self.handle, 125):
            raise Refusal("Owned process termination failed")
        if self.api.WaitForSingleObject(self.handle, 5000) != 0:
            raise Refusal("Owned process did not end within stop budget")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def run(permit_path, scope, pid, ticks, receipt, *, ticks_unit, maximum=360):
    process = WindowsProcess(pid, CreationTime(ticks, ticks_unit))
    start = time.monotonic()
    reason = "process-ended"
    try:
        while process.alive():
            try:
                bad = expired(load(permit_path), time.time(), time.monotonic(), scope)
            except (ValueError, OSError):
                bad = True
            if bad or time.monotonic() - start >= maximum:
                reason = "permit-expired-or-invalid"
                process.stop()
                break
            time.sleep(0.2)  # independent of helper; 0.2s detection + <=5s stop budget
        publish(receipt, canonical({"variant": "windows-single-process-fixture", "reason": reason,
                "pid": pid, "ticks": process.creation_time.value, "ticks_unit": FILETIME, "ended": not process.alive(),
                "ended_wall": time.time(), "elapsed": time.monotonic() - start}))
    finally:
        process.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--permit", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--ticks", type=int, required=True)
    parser.add_argument("--ticks-unit", choices=(FILETIME, DOTNET_TICKS), required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    run(args.permit, json.loads(args.scope), args.pid, args.ticks, args.receipt, ticks_unit=args.ticks_unit)


if __name__ == "__main__":
    main()
