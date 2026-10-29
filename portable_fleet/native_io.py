"""Windows identity and explicit native file handles; no shell or cleanup routines."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import os


class SecurityAttributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


def api():
    if os.name != "nt":
        raise ValueError("Windows required")
    k = c.WinDLL("kernel32", use_last_error=True)
    specs = {
        "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(SecurityAttributes), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        "ReadFile": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "GetComputerNameW": ([w.LPWSTR, c.POINTER(w.DWORD)], w.BOOL),
        "GetCurrentProcess": ([], w.HANDLE),
        "GetCurrentProcessId": ([], w.DWORD),
        "ProcessIdToSessionId": ([w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
        "LocalFree": ([c.c_void_p], c.c_void_p),
    }
    for name, (args, result) in specs.items():
        getattr(k, name).argtypes, getattr(k, name).restype = args, result
    return k


def identity():
    k = api()
    a = c.WinDLL("advapi32", use_last_error=True)
    a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    token, size, session = w.HANDLE(), w.DWORD(), w.DWORD()
    host = c.create_unicode_buffer(256)
    length = w.DWORD(len(host))
    if not k.GetComputerNameW(host, c.byref(length)) or not k.ProcessIdToSessionId(k.GetCurrentProcessId(), c.byref(session)):
        raise ValueError("Native host/session unavailable")
    if not a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)):
        raise ValueError("Native token unavailable")
    try:
        a.GetTokenInformation(token, 1, None, 0, c.byref(size))
        if not 0 < size.value < 65536:
            raise ValueError("Invalid token size")
        data = c.create_string_buffer(size.value)
        if not a.GetTokenInformation(token, 1, data, size, c.byref(size)):
            raise ValueError("Token user unavailable")
        sid = c.cast(data, c.POINTER(c.c_void_p))[0]
        text = w.LPWSTR()
        if not a.ConvertSidToStringSidW(sid, c.byref(text)):
            raise ValueError("SID unavailable")
        try:
            return {"host": host.value, "sid": text.value, "session": session.value}
        finally:
            k.LocalFree(c.cast(text, c.c_void_p))
    finally:
        k.CloseHandle(token)


class NativeFile:
    def __init__(self, path, *, output=False, nul=False):
        self.api, self.handle = api(), None
        attrs = SecurityAttributes(c.sizeof(SecurityAttributes), None, True) if output or nul else None
        access = 0x40000000 if output else 0x80000000
        creation = 1 if output else 3  # CREATE_NEW / OPEN_EXISTING
        self.handle = self.api.CreateFileW(str(path), access, 1, c.byref(attrs) if attrs else None, creation, 0x80, None)
        if self.handle in (None, 0, c.c_void_p(-1).value):
            self.handle = None
            raise ValueError("Cannot retain native file: " + str(path))

    def digest(self):
        value, count = hashlib.sha256(), w.DWORD()
        buffer = c.create_string_buffer(1024 * 1024)
        total = 0
        while True:  # finite file read before model process creation, never stop-duty polling
            if not self.api.ReadFile(self.handle, buffer, len(buffer), c.byref(count), None):
                raise ValueError("Pinned file read failed")
            if count.value == 0:
                return value.hexdigest()
            total += count.value
            if total > 256 * 1024 * 1024:
                raise ValueError("Pinned file too large")
            value.update(buffer.raw[:count.value])

    def close(self):
        if self.handle:
            if not self.api.CloseHandle(self.handle):
                raise ValueError("Native file close uncertain")
            self.handle = None
