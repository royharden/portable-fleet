"""Bounded journal actor: late storage completion is never an admission callback."""
from copy import deepcopy
from dataclasses import dataclass, field
import math
import queue
import threading
import time


@dataclass
class _Write:
    path: object
    value: object
    done: threading.Event = field(default_factory=threading.Event)
    error: object = None


class BoundedJournal:
    def __init__(self, writer, *, timeout=1.0, remaining=None):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 1:
            raise ValueError("Journal wait must be positive and at most one second")
        self._writer, self._timeout, self._remaining = writer, timeout, remaining
        self._queue, self._lock = queue.Queue(maxsize=1), threading.Lock()
        self._failed, self._closed, self._busy = None, False, False
        self._task = None
        self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()

    def _fail(self, reason):
        with self._lock:
            if self._failed is None:
                self._failed = reason

    def _work(self):
        while True:  # one blocking work queue; no status polling
            task = self._queue.get()
            if task is None:
                return
            with self._lock:
                refused = self._failed is not None or self._closed
            if refused:
                task.error = OSError("Journal closed/failed before storage began")
                task.done.set()
                if self._closed:
                    return
                continue
            try:
                self._writer(task.path, task.value)  # this thread alone calls the storage writer
            except BaseException as error:
                task.error = error
            finally:
                task.done.set()
            if self._closed:
                return

    def _lease_remaining(self):
        value = None if self._remaining is None else self._remaining()
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value)):
            raise OSError("Invalid old-lease journal budget")
        return value

    def write(self, path, value):
        # Absolute cutoff includes snapshotting, queueing, storage and return; never reset it.
        start = time.monotonic()
        remaining = self._lease_remaining()
        budget = self._timeout if remaining is None else min(self._timeout, remaining)
        if budget <= 0:
            self._fail("Old lease expired before journal write")
            raise OSError("Journal old-lease deadline reached")
        cutoff = start + budget
        with self._lock:
            if self._closed or self._failed is not None:
                raise OSError("Journal permanently closed/failed: " + str(self._failed))
            if self._busy:
                self._failed = "Concurrent journal submission refused"
                raise OSError(self._failed)
            self._busy = True
        try:
            task = _Write(path, deepcopy(value))
            with self._lock:
                self._task = task
            if time.monotonic() >= cutoff:
                self._fail("Journal snapshot exceeded deadline")
                raise OSError("Journal deadline reached before enqueue")
            try:
                self._queue.put_nowait(task)
            except queue.Full:
                task.done.set()
                self._fail("Journal queue saturated")
                raise OSError("Journal queue saturated") from None
            if not task.done.wait(max(0, cutoff - time.monotonic())):
                self._fail("Journal storage deadline reached; late completion is historical only")
                raise OSError("Journal storage deadline reached")
            old_remaining = self._lease_remaining()  # still old state: caller has not installed renewal
            if time.monotonic() >= cutoff or (old_remaining is not None and old_remaining <= 0):
                self._fail("Journal completed after old lease/deadline")
                raise OSError("Late journal completion cannot renew admission")
            with self._lock:
                failed = self._failed is not None or self._closed
            if failed:
                raise OSError("Journal failed/closed while storage was active")
            if task.error is not None:
                self._fail("Storage writer failed: " + str(task.error))
                raise OSError("Storage writer failed: " + str(task.error)) from task.error
        except BaseException:
            self._fail("Journal call failed")
            raise
        finally:
            with self._lock:
                self._busy = False

    def status(self):
        with self._lock:
            return {"failed": self._failed is not None, "reason": self._failed,
                    "closed": self._closed, "storage_pending": self._task is not None and not self._task.done.is_set()}

    def close(self):
        with self._lock:
            self._closed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass  # never wait behind a stalled/saturated storage call
        return self.status()  # intentionally no join or storage callback on the stop thread
