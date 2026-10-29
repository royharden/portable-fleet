"""Local phase cancellation coupled to an explicitly owned synthetic job.

Owner-thread call-time enforcement, not an autonomous manager or real admission.
"""
from copy import deepcopy
import threading
import time
import math

from .bounded_dispatch import BoundedJournalDispatcher
from .core import Refusal
from .control import ControlMailbox
from .permit_guard import GuardedFamily


class OwnedPhaseDispatcher(BoundedJournalDispatcher):
    def __init__(self, guard, recipient, root, identity, *, persistence_seconds=1.0):
        if (type(guard) is not GuardedFamily or recipient._scope != guard.scope
                or recipient._account != guard.state.account):
            raise Refusal("Explicit same-scope/account owned guard required")
        self.guard, self.stop_report = guard, None
        self._owner_thread = threading.get_ident()
        try:
            super().__init__(recipient, root, identity, persistence_seconds=persistence_seconds)
            self.control = ControlMailbox(guard.scope, self._cancelled)
        except BaseException:
            guard.close()  # suspended/pre-effect owner setup; no new admission
            raise

    def _owner(self):
        if threading.get_ident() != self._owner_thread:
            raise Refusal("Guard enforcement requires the owner thread; cancel signals only")

    def cancel(self, reason="Explicit cancellation"):
        # No native guard or SQL operations on a foreign signal thread.
        terminal = self.control.terminate(reason)
        super().cancel(terminal["reason"])

    def post_control(self, command):
        try:
            result = self.control.post(command)
            if result["terminal"]:
                super().cancel("Terminal stop control")
            return result  # queue acknowledgment only, not effect/admission proof
        except BaseException as error:
            self.cancel("Control rejected: " + str(error))
            raise

    def wait_control(self, *, maximum_seconds=30.0):
        self._owner()
        started = time.monotonic()
        try:
            if type(maximum_seconds) not in (int, float) or not math.isfinite(maximum_seconds) or not 0 < maximum_seconds <= 90:
                raise Refusal("Finite idle window in (0,90] required")
            terminal = self.control.status()["terminal"]
            if terminal is not None:
                return {"kind": "stopped", "control": terminal,
                        "stop": self.stop(terminal["reason"], event_started_mono=terminal["started_mono"])}
            self._live_guard()
            current = self.recipient.require_current()
            wall, mono = self.recipient._now()
            lease_wait = min(self.guard.deadline_wait_seconds(), current["expires_wall"] - wall, current["expires_mono"] - mono)
            budget = min(maximum_seconds, lease_wait)
            deadline = started + max(0, budget)  # prep never extends this absolute wait
            control = self.control.take(deadline)
            if control["terminal"]:
                return {"kind": "stopped", "control": control, "wait_deadline_mono": deadline,
                    "deadline_kind": "lease" if lease_wait < maximum_seconds else "maximum",
                    "stop": self.stop(control["reason"], event_started_mono=control["started_mono"])}
            terminal = self.control.status()["terminal"]
            if terminal is not None or self._cancelled.is_set():
                terminal = terminal or {"reason": "Cancellation observed", "started_mono": started}
                return {"kind": "stopped", "control": terminal,
                        "stop": self.stop(terminal["reason"], event_started_mono=terminal["started_mono"])}
            self._live_guard()
            return {"kind": "dispatched", "control": control, "outcome": self.dispatch_next()}
        except BaseException as error:
            terminal = self.control.status()["terminal"]
            origin = started if terminal is None else terminal["started_mono"]
            stopped = self.stop("Idle control failed: " + str(error), event_started_mono=origin)
            if terminal is not None and isinstance(error, Exception):
                return {"kind": "stopped", "control": terminal, "stop": stopped,
                        "interrupted_check": str(error)}  # terminal signal during preflight is normal stop, not lost control
            raise

    def _live_guard(self):
        if self.stop_report is not None or self.guard.stop_result is not None or self.guard.state.closed:
            raise Refusal("Owned guard already terminal")
        self.guard.state.check(*self.guard.clock())
        if self.guard.state.permit is None or not self.guard.family.resumed:
            raise Refusal("Owned family has no active local permit")
        if not self.guard.snapshot_complete or not self.guard.pins or not all(pin.alive() for pin in self.guard.pins):
            raise Refusal("Owned member snapshot missing/ended; no counter admission")

    def activate(self, command):
        self._owner()
        started = time.monotonic()
        try:
            if self.stop_report is not None or self._cancelled.is_set():
                raise Refusal("Terminal owned coordinator; no restart")
            if command.get("kind") != "receipt":
                raise Refusal("Owned activation requires receipt")
            self.recipient.begin(command)
            reply = self.guard.receive(command)  # can resume BEFORE recipient validates reply
            self.recipient.accept(reply)
            return reply
        except BaseException as error:
            self.stop("Owned receipt chain failed: " + str(error), event_started_mono=started)
            raise

    def enqueue(self, command):
        self._owner()
        started = time.monotonic()
        try:
            self._live_guard()
            return super().enqueue(command)
        except BaseException as error:
            self.stop("Owned enqueue failed: " + str(error), event_started_mono=started)
            raise

    def _active(self, head):
        super()._active(head)
        self._live_guard()  # owner thread only, before and AFTER each SQL wait

    def dispatch_next(self):
        self._owner()
        started = time.monotonic()
        try:
            self._live_guard()
            return super().dispatch_next()
        except BaseException as error:
            self.stop("Owned phase dispatch failed: " + str(error), event_started_mono=started)
            raise

    def stop(self, reason, *, event_started_mono=None):
        self._owner()
        if self.stop_report is not None:
            return self.stop_report
        origin = time.monotonic() if event_started_mono is None else event_started_mono
        errors, family_stop = [], None
        try:
            self.control.terminate(reason, origin=origin)
        except BaseException as error:
            errors.append("control publication: " + str(error))  # never block physical stop on bad metadata
        try:
            super().cancel(reason)  # no join of the phase writer
        except BaseException as error:
            errors.append("dispatch cancellation: " + str(error))
        try:
            family_stop = self.guard.stop(reason, event_started_mono=origin)
        except BaseException as error:
            errors.append("owned stop: " + str(error))
            try:
                self.guard.family.close()  # kernel kill-on-close fallback, never fabricated exit proof
            except BaseException as close_error:
                errors.append("owned handle fallback: " + str(close_error))
        self.stop_report = {"scope": self.guard.scope, "operation_started_mono": origin,
            "family_stop": deepcopy(family_stop), "errors": errors,
            "state": "stopped" if family_stop and family_stop["state"] == "stopped" and not errors else "uncertain",
            "counter": self.dispatcher.status(), "phase_actor": self.actor.status(),
            "restart_admitted": False}
        return self.stop_report

    def close(self):
        self._owner()
        errors = []
        try:
            self.stop("Owned coordinator closed")
        except BaseException as error:
            errors.append(str(error))
        for close in (super().close, self.guard.close):
            try:
                close()
            except BaseException as error:
                errors.append(str(error))
        if errors:
            raise Refusal("Owned coordinator cleanup uncertain: " + "; ".join(errors))
