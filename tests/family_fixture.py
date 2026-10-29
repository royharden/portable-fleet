"""Retained local Job Object fixtures. No deletion, model, network or polling."""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portable_fleet.core import Refusal
from portable_fleet.family import OwnedFamily
from portable_fleet.watchdog import WindowsProcess, query_creation_time
from portable_fleet.process_time import CreationTime


class Event:
    def __init__(self, name, create=False):
        self.api = c.WinDLL("kernel32", use_last_error=True)
        self.api.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
        self.api.CreateEventW.restype = w.HANDLE
        self.api.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
        self.api.OpenEventW.restype = w.HANDLE
        self.api.SetEvent.argtypes = [w.HANDLE]
        self.api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self.api.WaitForSingleObject.restype = w.DWORD
        self.api.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.api.CreateEventW(None, True, False, name) if create else self.api.OpenEventW(0x100002, False, name)
        if not self.handle:
            raise Refusal("Cannot create/open fixture event")
        if create and c.get_last_error() == 183:
            self.close()
            raise Refusal("Fixture event collision")

    def set(self):
        if not self.api.SetEvent(self.handle):
            raise Refusal("Cannot signal fixture event")

    def wait(self, milliseconds):
        result = self.api.WaitForSingleObject(self.handle, milliseconds)
        if result == 0:
            return True
        if result == 0x102:
            return False
        raise Refusal("Fixture event wait failed")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def write(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def environment():
    return {"SystemRoot": os.environ["SystemRoot"], "PATH": str(Path(sys.executable).parent)}


def capture_members(family):
    """One job snapshot, exact pinned handles and image proof; never a host process scan."""
    members, pinned = [], []
    try:
        for pid in family.member_ids():
            stamp = query_creation_time(pid)
            process = WindowsProcess(pid, stamp)
            pinned.append(process)
            if not family.contains(process):
                raise Refusal("Membership changed during observation")
            api = process.api
            api.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
            api.QueryFullProcessImageNameW.restype = w.BOOL
            image, size = c.create_unicode_buffer(32768), w.DWORD(32768)
            if not api.QueryFullProcessImageNameW(process.handle, 0, image, c.byref(size)):
                raise Refusal("Cannot inspect owned-job member image")
            members.append({"pid": pid, "creationTime": asdict(stamp), "image": image.value})
        return members, pinned
    except BaseException:
        for process in pinned:
            process.close()
        raise


def node(role, output, ready_name, stop_name, lifetime_ms="20000", work_mode="idle"):
    lifetime_ms = int(lifetime_ms)
    if not 1 <= lifetime_ms <= 360000 or work_mode not in ("idle", "work"):
        raise Refusal("Invalid finite fixture workload")
    ready, stop = Event(ready_name), Event(stop_name)
    child = None
    halt, worker = threading.Event(), None
    try:
        if work_mode == "work":
            first_effect = threading.Event()

            def work():
                with (Path(output) / (role + ".work")).open("x", encoding="ascii", buffering=1) as stream:
                    for count in range(1, 7201):
                        value = hashlib.sha256((role + str(count)).encode()).hexdigest()
                        stream.write(str(count) + " " + value + "\n")
                        first_effect.set()
                        if halt.wait(.05):  # bounded paced fixture work, not a status/receipt poll
                            return

            worker = threading.Thread(target=work, daemon=True)
            worker.start()
            if not first_effect.wait(5):
                raise Refusal("Fixture work did not start")
        write(Path(output) / (role + ".json"), {"pid": os.getpid(), "parent": os.getppid(),
              "creationTime": asdict(query_creation_time(os.getpid())), "role": role})
        if role == "root":
            try:
                attempted = subprocess.Popen([sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"],
                    close_fds=True, env=environment(), creationflags=0x01000000 | 0x08000000)
            except OSError as error:
                write(Path(output) / "breakaway.json", {"refused": True, "winerror": error.winerror})
                if error.winerror != 5:
                    raise Refusal("Breakaway failed for an unverified reason")
            else:
                attempted.wait(timeout=5)
                write(Path(output) / "breakaway.json", {"refused": False, "pid": attempted.pid})
                raise Refusal("Explicit breakaway unexpectedly permitted")
        if role in ("root", "child"):
            child_role = "child" if role == "root" else "grandchild"
            child = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), child_role, output, ready_name, stop_name, str(lifetime_ms), work_mode],
                                     close_fds=True, env=environment(), creationflags=0x08000000)
        else:
            ready.set()
        if not stop.wait(lifetime_ms):
            return 92
        if child:
            child.wait(timeout=5)
        return 0
    finally:
        halt.set()
        if worker:
            worker.join(timeout=5)
        ready.close()
        stop.close()


def launcher(output, ready_name, stop_name, crash_name, verified_name, scope):
    family = None
    ready, crash, verified = Event(ready_name), Event(crash_name), Event(verified_name)
    try:
        argv = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "root", output, ready_name, stop_name]
        family = OwnedFamily(argv, str(Path(output).resolve()), environment(), scope)
        write(Path(output) / "launch.json", {"pid": family.pid, "creationTime": asdict(family.creation_time),
              "atomic_job_list": True, "suspended_before_resume": True, "scope": scope, "policy": family.policy()})
        family.resume()
        if not ready.wait(10000):
            raise Refusal("Family never reached complete fixture readiness")
        members = []
        for role in ("root", "child", "grandchild"):
            record = json.loads((Path(output) / (role + ".json")).read_text())
            pinned = WindowsProcess(record["pid"], CreationTime.from_record(record["creationTime"]))
            try:
                if not family.contains(pinned):
                    raise Refusal("Fixture descendant outside owned job")
                members.append(record)
            finally:
                pinned.close()
        job_members, job_pins = capture_members(family)
        try:
            write(Path(output) / "membership.json", {"members": members, "accounting": family.accounting(), "job_members": job_members})
        finally:
            for process in job_pins:
                process.close()
        verified.set()
        if not crash.wait(10000):
            raise Refusal("No crash trigger before finite launcher deadline")
        os._exit(71)  # actual launcher death; kernel closes the sole noninherited job handle
    finally:
        if family:
            family.close()
        ready.close()
        crash.close()
        verified.close()


if __name__ == "__main__":
    if sys.argv[1] == "launcher":
        launcher(*sys.argv[2:])
    else:
        sys.exit(node(*sys.argv[1:]))
