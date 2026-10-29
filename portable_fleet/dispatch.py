"""Single-owner, call-time recipient checks for fixed synthetic memory effects.

No I/O, callbacks, durable exactly-once claims, concurrency or atomic lease/effect
guarantee. Scheduling can preempt Python after the final check. No real adapter.
"""
from copy import deepcopy
import math
import threading
import time

from .core import Refusal, fields, identifier
from .recipient import ReceiptRecipient


class SyntheticDispatcher:
    queue_limit = 8
    lifetime_limit = 64

    def __init__(self, recipient):
        if type(recipient) is not ReceiptRecipient:
            raise Refusal("Explicit local synthetic recipient required")
        self._recipient = recipient
        self._queue, self._effects, self._seen = [], [], set()
        self._total, self._closed, self._uncertain, self._reason = 0, False, False, None

    def close(self, reason, *, uncertain=False):
        if not self._closed:
            self._reason = str(reason)
        self._closed = True
        self._uncertain = self._uncertain or uncertain
        self._recipient.close("Synthetic dispatcher closed: " + self._reason)

    def _open(self):
        if self._closed:
            raise Refusal("Synthetic dispatcher closed; no retry/restart: " + self._reason)

    def enqueue(self, command):
        self._open()
        try:
            if type(command) is not dict:
                raise Refusal("Plain fixed synthetic effect object required")
            fields(command, {"schema", "operation", "scope", "kind", "value"})
            identifier(command["operation"])
            identifier(command["scope"])
            if (type(command["schema"]) is not int or command["schema"] != 1
                    or command["kind"] != "add" or type(command["value"]) is not int
                    or not 1 <= command["value"] <= 100):
                raise Refusal("Invalid fixed synthetic counter effect")
            if command["operation"] in self._seen:
                raise Refusal("Effect operation already submitted; no automatic resend")
            if len(self._queue) >= self.queue_limit or len(self._seen) >= self.lifetime_limit:
                raise Refusal("Synthetic queue/lifetime capacity reached")
            command = deepcopy(command)
            binding = self._recipient.require_current()
            if command["scope"] != binding["scope"]:
                raise Refusal("Effect scope differs from current recipient")
            self._seen.add(command["operation"])
            self._queue.append({"command": command, "binding": binding})
            return {"operation": command["operation"], "receipt_generation": binding["generation"]}
        except BaseException as error:
            self.close(str(error))
            raise

    def dispatch_next(self, *, cutoff_mono=None, cancellation=None):
        self._open()
        mutation_started = False
        try:
            if cutoff_mono is not None and (type(cutoff_mono) not in (int, float) or not math.isfinite(cutoff_mono) or cutoff_mono < 0):
                raise Refusal("Invalid local effect cutoff")
            if cancellation is not None and type(cancellation) is not threading.Event:
                raise Refusal("Fixed local cancellation event required")
            if not self._queue:
                raise Refusal("No queued synthetic effect")
            queued = self._queue[0]
            if self._recipient.require_current() != queued["binding"]:
                raise Refusal("Queued receipt superseded; no retargeting")
            # All bounded record preparation precedes final recipient validation.
            command, binding = deepcopy(queued["command"]), deepcopy(queued["binding"])
            new_total = self._total + command["value"]
            record = {"operation": command["operation"], "scope": command["scope"],
                      "receipt": binding, "value": command["value"],
                      "before_total": self._total, "after_total": new_total}
            returned = deepcopy(record)
            if self._recipient.require_current() != binding:
                raise Refusal("Recipient changed during preparation")
            if cancellation is not None and cancellation.is_set():
                raise Refusal("Synthetic effect cancelled before mutation")
            if cutoff_mono is not None and time.monotonic() >= cutoff_mono:
                raise Refusal("Synthetic effect preparation exceeded cutoff")
            mutation_started = True
            self._total = new_total  # fixed local effect; no callback/I/O after final check
            self._effects.append(record)
            self._queue.pop(0)
            return returned
        except BaseException as error:
            self.close(str(error), uncertain=mutation_started)
            raise

    def status(self):
        """In-memory historical diagnostics, never durable effect/restart authority."""
        return {"closed": self._closed, "reason": self._reason, "outcome_uncertain": self._uncertain,
                "total": self._total, "effects": deepcopy(self._effects), "queued": deepcopy(self._queue),
                "submitted": len(self._seen), "restart_admitted": False}
