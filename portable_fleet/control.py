"""Bounded scalar mailbox; condition notifications/deadlines, no status polling."""
from collections import deque
import math
import threading
import time

from .core import Refusal, fields, identifier


class ControlMailbox:
    def __init__(self, scope, cancellation):
        identifier(scope)
        if type(cancellation) is not threading.Event:
            raise Refusal("Fixed local cancellation Event required")
        self._scope, self._cancellation = scope, cancellation
        self._condition, self._queue, self._seen = threading.Condition(), deque(), set()
        self._terminal, self._waits = None, 0
        self.waiting = threading.Event()  # test/control observation, never admission

    def _terminate(self, reason, origin):
        if self._terminal is None:
            self._terminal = {"terminal": True, "reason": reason, "started_mono": origin}
        self._cancellation.set()  # publish under SAME lock, before notifying owner
        self._condition.notify_all()

    def terminate(self, reason, *, origin=None):
        if type(reason) is not str or len(reason) > 256:
            reason = "Invalid local cancellation reason"  # no caller __str__, especially not under lock
        origin = time.monotonic() if origin is None else origin
        if type(origin) not in (int, float) or not math.isfinite(origin) or origin < 0 or origin > time.monotonic():
            raise Refusal("Invalid local control origin")
        with self._condition:
            self._terminate(reason, origin)
            return dict(self._terminal)

    def post(self, command):
        origin = time.monotonic()
        with self._condition:
            if self._terminal is not None:
                raise Refusal("Control mailbox terminal; no replay/restart")
            try:
                if type(command) is not dict or len(command) != 4 or any(type(k) is not str for k in command):
                    raise Refusal("Plain bounded control object required")
                fields(command, {"schema", "scope", "operation", "kind"})
                if any(type(command[k]) is not str or len(command[k]) != 36 for k in ("scope", "operation")):
                    raise Refusal("Bounded canonical control IDs required")
                identifier(command["operation"])
                if (type(command["schema"]) is not int or command["schema"] != 1 or command["scope"] != self._scope
                        or type(command["kind"]) is not str or command["kind"] not in ("stop", "dispatch")
                        or command["operation"] in self._seen):
                    raise Refusal("Wrong/duplicate control")
                if len(self._seen) >= 64 or (command["kind"] == "dispatch" and len(self._queue) >= 8):
                    raise Refusal("Control capacity reached")
                self._seen.add(command["operation"])
                if command["kind"] == "stop":
                    self._terminate("Explicit stop control", origin)
                else:
                    self._queue.append({"terminal": False, "command": dict(command), "started_mono": origin})
                    self._condition.notify_all()
                return {"queued": True, "terminal": self._terminal is not None}
            except (Refusal, KeyError, TypeError, ValueError) as error:
                self._terminate("Invalid control: " + str(error), origin)
                raise

    def take(self, deadline_mono):
        if type(deadline_mono) not in (int, float) or not math.isfinite(deadline_mono):
            raise Refusal("Finite absolute control deadline required")
        with self._condition:
            while True:  # predicate loop only after notification/spurious wake/deadline
                now = time.monotonic()
                if now >= deadline_mono and (self._terminal is None or self._terminal["started_mono"] > deadline_mono):
                    self._terminal = None
                    self._terminate("Idle control deadline", deadline_mono)
                if self._terminal is not None:
                    return dict(self._terminal)  # terminal priority, independent of queue capacity
                if self._queue:
                    return self._queue.popleft()
                self._waits += 1
                self.waiting.set()
                try:
                    self._condition.wait(deadline_mono - now)
                finally:
                    self.waiting.clear()

    def status(self):
        with self._condition:
            return {"terminal": None if self._terminal is None else dict(self._terminal),
                    "queued": len(self._queue), "seen": len(self._seen), "wait_calls": self._waits,
                    "restart_admitted": False}
