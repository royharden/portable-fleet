"""Synthetic recipient-side receipt fencing; no transport authentication or restart.

Call require_current immediately before a protected local use. Returned snapshots
are historical values, not reusable authority or fresh remote-liveness evidence.
"""
from copy import deepcopy
import math
import time

from .core import Refusal, fields, identifier
from .supervision import Observation, Supervisor


class ReceiptRecipient:
    def __init__(self, scope, account, *, clock=None, response_seconds=1.0):
        identifier(scope)
        if not isinstance(account, str) or not account:
            raise Refusal("Explicit recipient account required")
        if type(response_seconds) not in (int, float) or not math.isfinite(response_seconds) or not 0 < response_seconds <= 1:
            raise Refusal("Response deadline must be positive and at most one second")
        self._scope, self._account = scope, account
        self._clock = clock or (lambda: (time.time(), time.monotonic()))
        self._response_seconds = response_seconds
        self._closed, self._reason = False, None
        self._pending, self._current, self._generation = None, None, 0
        self._seen = set()
        self._source = Supervisor(account)
        self._anchor = self._last = None
        self._now()

    def close(self, reason):
        if not self._closed:
            self._closed, self._reason = True, str(reason)
        self._pending = self._current = None

    def _refuse(self, reason):
        self.close(reason)
        raise Refusal(self._reason)

    def _now(self):
        if self._closed:
            raise Refusal("Recipient closed: " + self._reason)
        try:
            wall, mono = self._clock()
            if not all(type(value) in (int, float) and math.isfinite(value) for value in (wall, mono)) or wall <= 0 or mono < 0:
                raise ValueError("Invalid local clocks")
            if self._anchor is not None:
                if (wall < self._last[0] or mono < self._last[1]
                        or abs((wall - self._anchor[0]) - (mono - self._anchor[1])) > 2):
                    raise ValueError("Recipient clock discontinuity")
            else:
                self._anchor = (wall, mono)
            self._last = (wall, mono)
            return wall, mono
        except Exception as error:
            self._refuse(str(error))

    def _check(self):
        wall, mono = self._now()
        bound = self._pending or self._current
        if bound is not None:
            if wall >= bound["expires_wall"] or mono >= bound["expires_mono"]:
                self._refuse("Recipient current lease expired")
            if self._pending is not None and (mono >= self._pending["response_deadline_mono"]
                                             or wall >= self._pending["response_deadline_wall"]):
                self._refuse("Recipient response deadline expired")
        return wall, mono

    def begin(self, command):
        """Register latest local request; superseding immediately suspends admission."""
        wall, mono = self._check()  # NEVER reset an expired pending/current bound
        try:
            fields(command, {"schema", "operation", "scope", "kind", "observation"})
            identifier(command["operation"])
            if (type(command["schema"]) is not int or command["schema"] != 1
                    or command["scope"] != self._scope or command["kind"] != "receipt"
                    or command["operation"] in self._seen):
                raise Refusal("Wrong/reused recipient request")
            raw = command["observation"]
            fields(raw, {"account", "sequence", "observed", "percent_left", "reset"})
            if not isinstance(raw["reset"], str) or not raw["reset"]:
                raise Refusal("Invalid observation reset identity")
            self._source.observe(Observation(**raw), wall)
            deadline_wall = min(wall + 90, raw["observed"] + 300)
            self._generation += 1
            self._seen.add(command["operation"])
            self._pending = {"command": deepcopy(command), "generation": self._generation,
                "sent_wall": wall, "sent_mono": mono,
                "expires_wall": deadline_wall, "expires_mono": mono + deadline_wall - wall,
                "response_deadline_wall": wall + self._response_seconds,
                "response_deadline_mono": mono + self._response_seconds}
            self._current = None
            return {"operation": command["operation"], "generation": self._generation}
        except (Refusal, ValueError, TypeError, KeyError, RecursionError) as error:
            self._refuse("Invalid recipient request: " + str(error))

    def accept(self, response):
        wall, mono = self._check()  # check BEFORE inspecting even a seemingly fresh reply
        try:
            fields(response, {"state", "operation", "kind", "permit", "replayed"})
            pending = self._pending
            if (pending is None or response["state"] != "active" or response["kind"] != "receipt"
                    or response["operation"] != pending["command"]["operation"]
                    or response["replayed"] is not False):
                raise Refusal("Unsolicited/replayed/superseded recipient acknowledgment")
            permit, raw = response["permit"], pending["command"]["observation"]
            fields(permit, {"schema", "scope", "issued_wall", "issued_mono", "expires_wall", "expires_mono",
                            "observation_deadline", "account", "sequence", "warning"})
            if (type(permit["schema"]) is not int or permit["schema"] != 1
                    or permit["scope"] != self._scope or permit["account"] != self._account
                    or type(permit["sequence"]) is not int or permit["sequence"] != raw["sequence"]
                    or type(permit["warning"]) is not bool or permit["warning"] != (raw["percent_left"] <= 15)):
                raise Refusal("Wrong recipient acknowledgment binding")
            if not all(type(permit[key]) in (int, float) and math.isfinite(permit[key]) for key in
                       ("issued_wall", "issued_mono", "expires_wall", "expires_mono", "observation_deadline")):
                raise Refusal("Invalid acknowledgment times")
            duration = permit["expires_wall"] - permit["issued_wall"]
            if (not 0 < duration <= 90.000001
                    or permit["issued_mono"] < 0
                    or abs(duration - (permit["expires_mono"] - permit["issued_mono"])) > .000001
                    or not pending["sent_wall"] <= permit["issued_wall"] <= wall
                    or permit["observation_deadline"] != raw["observed"] + 300
                    or permit["expires_wall"] > permit["observation_deadline"]):
                raise Refusal("Incoherent/future acknowledgment deadline")
            deadline_wall = min(pending["expires_wall"], permit["expires_wall"])
            # Foreign monotonic ORIGIN is never compared/copied. Local send anchor
            # conservatively translates the bounded wall deadline, never receipt time.
            deadline_mono = pending["sent_mono"] + deadline_wall - pending["sent_wall"]
            if wall >= deadline_wall or mono >= deadline_mono:
                raise Refusal("Acknowledgment already expired locally")
            self._check()  # pending-response/old bounds still installed after validation
            self._current = {"scope": self._scope, "account": self._account,
                "operation": response["operation"], "generation": pending["generation"],
                "expires_wall": deadline_wall, "expires_mono": deadline_mono}
            self._pending = None
            return self.require_current()
        except (Refusal, ValueError, TypeError, KeyError, RecursionError) as error:
            self._refuse("Rejected recipient acknowledgment: " + str(error))

    def require_current(self):
        self._check()
        if self._current is None or self._pending is not None:
            raise Refusal("No current recipient acknowledgment")
        return deepcopy(self._current)

    def status(self):
        """Historical diagnostic snapshot only; use require_current for live checks."""
        return {"closed": self._closed, "reason": self._reason, "generation": self._generation,
                "pending": self._pending is not None, "current": deepcopy(self._current),
                "restart_admitted": False}
