"""Bounded encoded output; delivery timeout is permanent uncertainty, not a retry."""
import json
import threading
import time

from .journal_worker import BoundedJournal


class BoundedOutput:
    def __init__(self, sink, *, remaining=None, timeout=1.0, max_frame=65536):
        if type(max_frame) is not int or not 1 <= max_frame <= 65536:
            raise ValueError("Output frame limit must be bounded")
        self._lock, self._failed, self._closed = threading.Lock(), None, False
        self._failure_started = None

        def write_frame(_unused, value):
            frame = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(frame) > max_frame:
                raise OSError("Output frame exceeds limit")
            offset = 0
            while offset < len(frame):  # bounded byte progress on worker thread only
                written = sink(frame[offset:])
                if type(written) is not int or not 0 < written <= len(frame) - offset:
                    raise OSError("Invalid/zero output write progress")
                offset += written

        self._actor = BoundedJournal(write_frame, remaining=remaining, timeout=timeout)

    def send(self, value):
        started = time.monotonic()
        with self._lock:
            if self._failed is not None or self._closed:
                raise OSError("Output permanently failed/closed; no fallback or resend")
        try:
            self._actor.write(None, value)
        except BaseException as error:
            with self._lock:
                if self._failed is None:
                    self._failed, self._failure_started = str(error), started
            raise

    def status(self):
        actor = self._actor.status()
        with self._lock:
            return {"failed": self._failed is not None, "reason": self._failed, "closed": self._closed,
                    "failure_started_mono": self._failure_started, "output_pending": actor["storage_pending"],
                    "delivery": "uncertain" if self._failed is not None else "writes-completed-not-recipient-admission"}

    def close(self):
        with self._lock:
            self._closed = True
        self._actor.close()  # no sink flush and no join of a blocked writer
        return self.status()
