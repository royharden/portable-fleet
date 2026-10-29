"""Windows owned-job process boundary; no attach-by-PID or create/assign fallback.

Normal CreateProcess descendants inherit the job. Broker/WMI launches and hostile
same-user behavior are outside this adapter's admission scope.
"""
import ctypes as c
from ctypes import wintypes as w
import math
import os
from pathlib import Path
import time

from .core import Refusal, absolute_directory, command, identifier, windows_commandline
from .watchdog import _creation_time


class BasicLimit(c.Structure):
    _fields_ = [("process_time", c.c_longlong), ("job_time", c.c_longlong), ("flags", w.DWORD),
                ("min_ws", c.c_size_t), ("max_ws", c.c_size_t), ("active_limit", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class IOCounters(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]


class ExtendedLimit(c.Structure):
    _fields_ = [("basic", BasicLimit), ("io", IOCounters), ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [(name, c.c_longlong) for name in ("user", "kernel", "period_user", "period_kernel")] + [
        (name, w.DWORD) for name in ("faults", "total", "active", "terminated")]


class ProcessIds(c.Structure):
    _fields_ = [("assigned", w.DWORD), ("listed", w.DWORD), ("pids", c.c_size_t * 64)]


class PortAssociation(c.Structure):
    _fields_ = [("key", c.c_void_p), ("port", w.HANDLE)]


class Startup(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
                *[(name, w.DWORD) for name in ("x", "y", "xsize", "ysize", "xchars", "ychars", "fill", "flags")],
                ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_bytes", c.c_void_p),
                ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class StartupEx(c.Structure):
    _fields_ = [("startup", Startup), ("attributes", c.c_void_p)]


class ProcessInfo(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


def _api():
    if os.name != "nt":
        raise Refusal("Windows job adapter required")
    api = c.WinDLL("kernel32", use_last_error=True)
    specs = {
        "CreateJobObjectW": ([c.c_void_p, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        "QueryInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
        "CreateIoCompletionPort": ([w.HANDLE, w.HANDLE, c.c_size_t, w.DWORD], w.HANDLE),
        "GetQueuedCompletionStatus": ([w.HANDLE, c.POINTER(w.DWORD), c.POINTER(c.c_size_t), c.POINTER(c.c_void_p), w.DWORD], w.BOOL),
        "InitializeProcThreadAttributeList": ([c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
        "UpdateProcThreadAttribute": ([c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
        "DeleteProcThreadAttributeList": ([c.c_void_p], None),  # frees memory metadata, not filesystem data
        "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(StartupEx), c.POINTER(ProcessInfo)], w.BOOL),
        "ResumeThread": ([w.HANDLE], w.DWORD),
        "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
        "IsProcessInJob": ([w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
        "GetHandleInformation": ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        "GetProcessTimes": ([w.HANDLE, *([c.POINTER(w.FILETIME)] * 4)], w.BOOL),
        "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        "CloseHandle": ([w.HANDLE], w.BOOL),
    }
    for name, (args, result) in specs.items():
        getattr(api, name).argtypes = args
        getattr(api, name).restype = result
    return api


def wait_owned_process(process, timeout_ms):
    """One kernel wait on an already pinned retained process, never a PID search."""
    if type(timeout_ms) is not int or not 0 <= timeout_ms <= 60000 or not process.handle:
        raise Refusal("Invalid retained-process wait")
    result = process.api.WaitForSingleObject(process.handle, timeout_ms)
    if result == 0:
        return True
    if result == 0x102:
        return False
    raise Refusal("Unknown process wait; exit not established")


def environment_block(environment):
    if not isinstance(environment, dict) or not environment:
        raise Refusal("Explicit nonempty child environment required")
    entries = []
    seen = set()
    for key, value in environment.items():
        if (not isinstance(key, str) or not key or "=" in key or "\0" in key
                or not isinstance(value, str) or "\0" in value or key.casefold() in seen):
            raise Refusal("Invalid/colliding child environment")
        seen.add(key.casefold())
        entries.append((key, value))
    return c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(entries, key=lambda p: p[0].casefold())) + "\0\0")


class OwnedFamily:
    """One new root, atomic job admission before execution, owned-handle stopping."""
    def __init__(self, argv, cwd, environment, scope, *, stdio=None, console_mode="hidden"):
        if console_mode not in ("hidden", "new"):
            raise Refusal("Explicit console mode required")
        identifier(scope)
        if not isinstance(argv, list) or not argv:
            raise Refusal("Explicit argv required")
        self.argv = command(argv[0], argv[1:])
        self.cwd = str(absolute_directory(str(cwd)))
        env = environment_block(environment)
        self.scope, self.resumed = scope, False
        self.job = self.port = self.process = self.thread = None
        self.api = _api()
        self.events = []
        attributes = None
        initialized = False
        try:
            self.job = self.api.CreateJobObjectW(None, None)  # unnamed, noninheritable
            if not self.job:
                raise Refusal("Cannot create owned job")
            limits = ExtendedLimit()
            limits.basic.flags = 0x2000 | 0x8  # KILL_ON_JOB_CLOSE + ACTIVE_PROCESS; no BREAKAWAY flags
            limits.basic.active_limit = 8
            if not self.api.SetInformationJobObject(self.job, 9, c.byref(limits), c.sizeof(limits)):
                raise Refusal("Cannot enforce job limits")
            self.port = self.api.CreateIoCompletionPort(w.HANDLE(-1), None, 0, 1)
            association = PortAssociation(1, self.port)
            if not self.port or not self.api.SetInformationJobObject(self.job, 7, c.byref(association), c.sizeof(association)):
                raise Refusal("Cannot associate job completion port")
            size = c.c_size_t()
            self.api.InitializeProcThreadAttributeList(None, 2 if stdio else 1, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                raise Refusal("Invalid startup attribute size")
            attributes = c.create_string_buffer(size.value)
            if not self.api.InitializeProcThreadAttributeList(attributes, 2 if stdio else 1, 0, c.byref(size)):
                raise Refusal("Cannot initialize job-list attributes")
            initialized = True
            jobs = (w.HANDLE * 1)(self.job)
            if not self.api.UpdateProcThreadAttribute(attributes, 0, 0x0002000d, jobs, c.sizeof(jobs), None, None):
                raise Refusal("JOB_LIST unsupported/refused; no fallback launch")
            startup = StartupEx()
            startup.startup.cb = c.sizeof(startup)
            startup.attributes = c.cast(attributes, c.c_void_p)
            if stdio is not None:
                if type(stdio) is not tuple or len(stdio) != 3 or any(type(h) is not int or h <= 0 for h in stdio):
                    raise Refusal("Explicit three inherited std handles required")
                handles = (w.HANDLE * 3)(*stdio)
                for handle in stdio:
                    handle_flags = w.DWORD()
                    if not self.api.GetHandleInformation(handle, c.byref(handle_flags)) or not handle_flags.value & 1:
                        raise Refusal("Std handle must be inheritable")
                if not self.api.UpdateProcThreadAttribute(attributes, 0, 0x00020002, handles, c.sizeof(handles), None, None):
                    raise Refusal("Cannot restrict inherited HANDLE_LIST")
                startup.startup.flags = 0x100
                startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdio
            info = ProcessInfo()
            # Root is born in the job AND suspended. The job owner handle is never
            # inherited; optional stdio uses only the explicit three-handle list.
            flags = 0x00080000 | 0x4 | (0x10 if console_mode == "new" else 0x08000000) | 0x400
            if not self.api.CreateProcessW(self.argv[0], c.create_unicode_buffer(windows_commandline(self.argv)),
                    None, None, stdio is not None, flags, env, self.cwd, c.byref(startup), c.byref(info)):
                raise Refusal(f"Contained process creation refused ({c.get_last_error()}); no fallback")
            self.process, self.thread, self.pid = info.process, info.thread, info.pid
            self.creation_time = _creation_time(self.api, self.process)
            if not self._contains_handle(self.process):
                raise Refusal("Root job admission mismatch before resume")
            self.policy()
        except BaseException as original:
            try:
                self.close()
            except Refusal as cleanup:
                raise Refusal(f"{original}; cleanup uncertain: {cleanup}") from original
            raise
        finally:
            if initialized:
                self.api.DeleteProcThreadAttributeList(attributes)

    def _require_open(self):
        if not self.job:
            raise Refusal("Owned job handle is closed")

    def _contains_handle(self, handle):
        self._require_open()
        result = w.BOOL()
        if not self.api.IsProcessInJob(handle, self.job, c.byref(result)):
            raise Refusal("Cannot verify exact job membership")
        return bool(result.value)

    def contains(self, pinned_process):
        if not pinned_process.handle:
            raise Refusal("Pinned process handle is closed")
        return self._contains_handle(pinned_process.handle)

    def resume(self):
        self._require_open()
        if self.resumed:
            raise Refusal("Root already resumed")
        self.policy()
        if self.api.ResumeThread(self.thread) != 1:
            try:
                self.close()
            except Refusal as cleanup:
                raise Refusal(f"Unexpected root suspend state; cleanup uncertain: {cleanup}") from cleanup
            raise Refusal("Unexpected root suspend state; owned job closed")
        self.resumed = True

    def policy(self):
        self._require_open()
        limits, handle_flags = ExtendedLimit(), w.DWORD()
        if (not self.api.QueryInformationJobObject(self.job, 9, c.byref(limits), c.sizeof(limits), None)
                or not self.api.GetHandleInformation(self.job, c.byref(handle_flags))):
            raise Refusal("Cannot verify effective job policy")
        if (limits.basic.flags & 0x2008 != 0x2008 or limits.basic.flags & 0x1800
                or limits.basic.active_limit != 8 or handle_flags.value & 1):
            raise Refusal("Job policy drift or inherited owner handle")
        return {"limit_flags": limits.basic.flags, "active_limit": limits.basic.active_limit,
                "owner_handle_inheritable": bool(handle_flags.value & 1), "breakaway_allowed": False}

    def accounting(self):
        self._require_open()
        value = Accounting()
        if not self.api.QueryInformationJobObject(self.job, 1, c.byref(value), c.sizeof(value), None):
            raise Refusal("Cannot verify job accounting")
        return {"total": value.total, "active": value.active, "terminated": value.terminated}

    def member_ids(self):
        """One bounded, read-only job snapshot; never used as stop authority."""
        self._require_open()
        value = ProcessIds()
        if (not self.api.QueryInformationJobObject(self.job, 3, c.byref(value), c.sizeof(value), None)
                or value.listed != value.assigned or value.listed > 64):
            raise Refusal("Incomplete job membership snapshot")
        return list(value.pids[:value.listed])

    def stop(self, expected_scope, timeout_seconds=5):
        self._require_open()
        if expected_scope != self.scope:
            raise Refusal("Wrong family scope; no stop requested")
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 10:
            raise Refusal("Invalid family stop deadline")
        start = time.monotonic()
        if not self.api.TerminateJobObject(self.job, 125):
            raise Refusal("Owned job stop request failed; outcome unknown")
        deadline = start + timeout_seconds
        while True:  # consume kernel events with a finite total deadline; no status polling
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal("Missing job completion event; end state uncertain")
            message, key, value = w.DWORD(), c.c_size_t(), c.c_void_p()
            if not self.api.GetQueuedCompletionStatus(self.port, c.byref(message), c.byref(key), c.byref(value), max(1, int(remaining * 1000))):
                raise Refusal("Job completion wait failed/timed out; end state uncertain")
            if key.value != 1:
                raise Refusal("Unexpected job completion key")
            self.events.append({"message": message.value, "pid": value.value})
            if message.value == 4:  # ACTIVE_PROCESS_ZERO is notification, followed by one accounting check
                accounting = self.accounting()
                if accounting["active"] != 0:
                    raise Refusal("Completion/accounting conflict; end state uncertain")
                return {"scope": self.scope, "accounting": accounting, "elapsed": time.monotonic() - start,
                        "events": list(self.events), "variant": "owned-job-fixture"}

    def close(self):
        # Last job-handle close requests kernel family termination. It is NOT a completion receipt.
        failed = []
        for name in ("job", "thread", "process", "port"):
            handle = getattr(self, name, None)
            if handle:
                if not self.api.CloseHandle(handle):
                    failed.append(name)
                else:
                    setattr(self, name, None)
        if failed:
            raise Refusal(f"Cannot close owned handles {failed}; state uncertain")
