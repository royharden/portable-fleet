"""Persistence-only actor; effects stay on the calling owner thread."""
from copy import deepcopy
import threading
import time

from .core import Refusal
from .journal_dispatch import JournaledDispatcher
from .journal_worker import BoundedJournal


class BoundedJournalDispatcher(JournaledDispatcher):
    def __init__(self, recipient, root, identity, *, persistence_seconds=1.0):
        self._cancelled, self._inflight = threading.Event(), False
        self._cutoff, self._binding = None, None
        # Actor validates the timeout before any filesystem setup.
        self.actor = BoundedJournal(self._persist, timeout=persistence_seconds, remaining=self._remaining)
        self._seconds = persistence_seconds
        try:
            super().__init__(recipient, root, identity)  # synchronous setup BEFORE any effect
        except BaseException:
            self.actor.close()
            recipient.close("Bounded journal initialization failed")
            raise

    def _persist(self, phase, payload):
        # This worker has storage commands only, never an adapter or chained effect.
        self.journal.persist_phase(phase, payload["request"], payload["result"])

    def _remaining(self):
        if self._cancelled.is_set():
            raise Refusal("Journal dispatch permanently cancelled")
        current = self.recipient.require_current()
        if current != self._binding:
            raise Refusal("Persistence receipt superseded")
        wall, mono = self.recipient._now()  # validate this sample too; min must not hide NaN
        return min(self._cutoff - time.monotonic(), current["expires_wall"] - wall,
                   current["expires_mono"] - mono)

    def cancel(self, reason="Explicit cancellation"):
        self._cancelled.set()
        self.dispatcher.close(reason, uncertain=self._inflight)
        self.actor.close()  # no join; an already running SQL phase may finish late

    def _active(self, head):
        self.dispatcher._open()
        if self._remaining() <= 0:
            raise Refusal("Aggregate persistence cutoff reached")
        queued = self.dispatcher.status()["queued"]
        if not queued or queued[0] != head:
            raise Refusal("Queued effect changed during persistence")

    def dispatch_next(self):
        started = time.monotonic()
        if self._cancelled.is_set() or self._inflight:
            self.cancel("Closed/concurrent journal dispatch")
            raise Refusal("Closed/concurrent journal dispatch")
        self._inflight = True
        self._cutoff = started + self._seconds  # common pre-effect cutoff includes preparation
        try:
            self.dispatcher._open()
            queued = self.dispatcher.status()["queued"]
            if not queued:
                raise Refusal("No bounded synthetic effect queued")
            head = queued[0]
            self._binding = deepcopy(head["binding"])
            request = self._request_for(head)
            self._active(head)
            for phase in ("accepted", "executing"):
                self.actor.write(phase, {"request": request, "result": None})
                self._active(head)  # completion alone never grants effect permission
            effect = self.dispatcher.dispatch_next(cutoff_mono=self._cutoff, cancellation=self._cancelled)
            result = {"state": "outcome", "operation": request["operation"],
                "variant": "synthetic-memory-counter", "effect": effect, "restart_admitted": False}
            self._cutoff = time.monotonic() + self._seconds  # bounded POST-effect confirmation, not new admission
            self.actor.write("outcome", {"request": request, "result": result})
            return result
        except BaseException as error:
            self.cancel("Bounded persistence failed: " + str(error))
            raise
        finally:
            self._inflight = False

    def close(self):
        self.cancel("Bounded journal owner closed")
        self.journal.close()  # marker stays; running SQL may still retain historical bytes
