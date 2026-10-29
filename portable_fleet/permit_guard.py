"""Local receipt-to-owned-job enforcement. Synthetic provider scope, not remote admission."""
from dataclasses import asdict
from copy import deepcopy
import json
import math
from pathlib import Path
import time

from .core import Refusal, canonical, digest, fields, identifier, load
from .family import OwnedFamily, wait_owned_process
from .process_time import CreationTime
from .supervision import Observation, Supervisor, expired
from .watchdog import WindowsProcess, query_creation_time
from .journal_worker import BoundedJournal


def retain(path, value):
    """Exclusive complete record, fsynced, never overwritten or deleted."""
    import os
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def valid_clock(wall, mono):
    return all(type(value) in (int, float) and math.isfinite(value) for value in (wall, mono)) and wall > 0 and mono >= 0


class PermitState:
    def __init__(self, root, scope, account, wall, mono, *, writer=retain, commit_clock=None):
        identifier(scope)
        if not isinstance(account, str) or not account or not valid_clock(wall, mono):
            raise Refusal("Explicit account and finite local clock required")
        self.root, self.scope, self.account = Path(root), scope, account
        self.writer = writer
        self.commit_clock = commit_clock
        self.closed, self.reason, self.permit, self.replayed = False, None, None, False
        self.terminal_persisted = False
        self.closing_started_mono = None
        self.supervisor, self.operations = Supervisor(account), {}
        # Claim before constructing any process. Any previous run, even partial, refuses.
        self.root.mkdir(parents=True, exist_ok=True)
        if any(self.root.iterdir()):
            raise Refusal("Existing guard state is recovery-only, never launch admission")
        self.writer(self.root / "started.json", {"schema": 1, "scope": scope, "account": account,
                    "created_wall": wall, "created_mono": mono, "restart_admitted": False})

    def hold(self, reason, wall, mono, *, enforcement_started_mono=None):
        if self.closed:
            return
        now = time.monotonic()
        self.closing_started_mono = now if enforcement_started_mono is None else min(now, enforcement_started_mono)
        self.closed, self.reason = True, str(reason)
        self.writer(self.root / "terminal.json", {"schema": 1, "scope": self.scope, "account": self.account,
            "reason": self.reason, "wall": wall if valid_clock(wall, mono) else None,
            "mono": mono if valid_clock(wall, mono) else None, "permit": self.permit, "restart_admitted": False})
        self.terminal_persisted = True

    def check(self, wall, mono):
        if self.closed:
            raise Refusal("Terminal guard state; no replay/restart admission")
        if not valid_clock(wall, mono):
            self.hold("Invalid local clocks", wall, mono)
            raise Refusal(self.reason)
        if self.permit is not None and expired(self.permit, wall, mono, self.scope):
            self.hold("Permit expired or clock discontinuity", wall, mono)
            raise Refusal(self.reason)

    def accept(self, command, wall, mono):
        # Critical ordering: an expired old lease cannot be resurrected by a queued renewal.
        self.check(wall, mono)
        self.replayed = False
        try:
            fields(command, {"schema", "operation", "scope", "kind", "observation"})
            if type(command["schema"]) is not int or command["schema"] != 1 or command["scope"] != self.scope:
                raise Refusal("Wrong schema/scope")
            identifier(command["operation"])
            if command["kind"] not in ("receipt", "inspect", "stop"):
                raise Refusal("Unknown guard command")
            pin = digest(canonical(command))
            previous = self.operations.get(command["operation"])
            if previous:
                if previous[0] != pin:
                    raise Refusal("Operation ID payload changed")
                self.replayed = True
                return deepcopy(previous[1])
            if command["kind"] == "receipt":
                raw = command["observation"]
                fields(raw, {"account", "sequence", "observed", "percent_left", "reset"})
                if not isinstance(raw["reset"], str) or not raw["reset"]:
                    raise Refusal("Missing observation window identity")
                observation = Observation(**raw)
                self.supervisor.observe(observation, wall)
                permit = self.supervisor.permit(wall, mono, self.scope)
                duration = permit["expires_wall"] - wall
                if not 0 < duration <= 90.000001:
                    raise Refusal("Invalid derived permit duration")
            else:
                if command["observation"] is not None or self.permit is None:
                    raise Refusal("No active permit or unexpected control payload")
                permit = self.permit
            ack = {"operation": command["operation"], "kind": command["kind"], "permit": permit}
            self.writer(self.root / "commands" / (command["operation"] + ".json"),
                        {"schema": 1, "digest": pin, "command": command, "ack": ack})
            if self.commit_clock is not None:
                post_wall, post_mono = self.commit_clock()
                self.check(post_wall, post_mono)  # old permit still installed: no late-I/O resurrection
                if expired(permit, post_wall, post_mono, self.scope):
                    self.hold("Candidate permit invalid after storage/clock change", post_wall, post_mono)
                    raise Refusal(self.reason)
            self.operations[command["operation"]] = (pin, ack)
            self.permit = permit
            if command["kind"] == "stop":
                self.hold("Explicit operator stop", wall, mono)
            return deepcopy(ack)
        except (Refusal, OSError, TypeError, ValueError, RecursionError) as error:
            self.hold("Invalid/unpersisted supervisor receipt: " + str(error), wall, mono)
            raise


class GuardedFamily:
    def __init__(self, argv, cwd, environment, state_root, scope, account, *, clock=None, writer=retain):
        self.clock = clock or (lambda: (time.time(), time.monotonic()))
        self.family, self.pins, self.stop_result, self.state = None, [], None, None
        self.members, self.snapshot_complete = [], False
        self.scope = scope
        self.journal = BoundedJournal(writer, remaining=self._old_lease_remaining)
        self.writer = self.journal.write
        try:
            self.state = PermitState(state_root, scope, account, *self.clock(), writer=self.writer, commit_clock=self.clock)
            self.family = OwnedFamily(argv, cwd, environment, scope)
            self.writer(self.state.root / "launch.json", {"schema": 1, "scope": scope, "pid": self.family.pid,
                "creationTime": asdict(self.family.creation_time), "resumed": False})
        except BaseException:
            try:
                if self.state:
                    self.state.hold("Launch/admission failed", *self.clock())
            finally:
                try:
                    if self.family:
                        self.family.close()
                finally:
                    self.journal.close()
            raise

    def _old_lease_remaining(self):
        if self.state is None:
            return None
        if self.state.closed:
            return self.state.closing_started_mono + 10 - time.monotonic()
        if self.state.permit is None:
            return None
        wall, mono = self.clock()
        if not valid_clock(wall, mono):
            return 0
        return min(self.state.permit["expires_wall"] - wall, self.state.permit["expires_mono"] - mono)

    def capture_members(self):
        if self.pins:
            if not self.snapshot_complete:
                raise Refusal("Prior member snapshot incomplete; no full-family exit claim")
            return list(self.members)
        records = []
        for pid in self.family.member_ids():
            pin = WindowsProcess(pid, query_creation_time(pid))
            self.pins.append(pin)
            if not self.family.contains(pin):
                raise Refusal("Job membership changed during guard snapshot")
            records.append({"pid": pid, "creationTime": asdict(pin.creation_time)})
        if not records:
            raise Refusal("No pinned family members")
        self.writer(self.state.root / "members.json", {"schema": 1, "scope": self.scope, "members": records})
        self.members, self.snapshot_complete = records, True
        return records

    def receive(self, command):
        if self.stop_result is not None:
            return self.stop_result
        try:
            ack = self.state.accept(command, *self.clock())
            if self.state.closed:
                return self.stop(self.state.reason)
            if not self.family.resumed:
                self.state.check(*self.clock())
                self.family.resume()
            if command["kind"] == "inspect" and not self.state.replayed:
                self.capture_members()
            return {"state": "active", **ack, "replayed": self.state.replayed}
        except (Refusal, OSError, TypeError, ValueError, RecursionError) as error:
            return self.stop(str(error))

    def deadline_wait_seconds(self):
        wall, mono = self.clock()
        self.state.check(wall, mono)
        if self.state.permit is None:
            return 5.0  # finite initial-admission wait; never resume without a receipt
        return max(0.0, min(self.state.permit["expires_wall"] - wall, self.state.permit["expires_mono"] - mono))

    def stop(self, reason, *, event_started_mono=None):
        if self.stop_result is not None:
            return self.stop_result
        start, start_wall, errors, stop_ack = time.monotonic(), time.time(), [], None
        enforcement_start = self.state.closing_started_mono if self.state.closing_started_mono is not None else start
        if event_started_mono is not None:
            if type(event_started_mono) in (int, float) and math.isfinite(event_started_mono) and 0 <= event_started_mono <= start:
                enforcement_start = min(enforcement_start, event_started_mono)
            else:
                errors.append("Invalid local failure origin; no external budget claim")
        try:
            self.state.hold(reason, *self.clock(), enforcement_started_mono=enforcement_start)
        except (OSError, Refusal) as error:
            errors.append("terminal persistence: " + str(error))
        if not self.state.terminal_persisted:
            errors.append("terminal closure not durably confirmed; started claim still blocks restart")
        try:
            self.capture_members()
        except (OSError, Refusal) as error:
            errors.append("member snapshot: " + str(error))
        deadline = enforcement_start + 10  # includes first terminal write, not a fresh budget after it
        try:
            stop_ack = self.family.stop(self.scope, timeout_seconds=max(.001, min(5, deadline - time.monotonic())))
        except (OSError, Refusal) as error:
            errors.append("job stop: " + str(error))
        all_ended = bool(self.pins)
        for pin in self.pins:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            try:
                all_ended = wait_owned_process(pin, min(60000, remaining)) and all_ended
            except Refusal as error:
                all_ended = False
                errors.append("pinned wait: " + str(error))
        ended_mono, ended_wall = time.monotonic(), time.time()
        if ended_mono > deadline:
            errors.append("Total enforcement deadline missed; no bounded-stop claim")
        self.stop_result = {"state": "stopped" if stop_ack and all_ended and not errors else "uncertain",
            "scope": self.scope, "reason": self.state.reason or str(reason), "errors": errors,
            "all_pinned_ended": all_ended, "pinned_count": len(self.pins), "job_stop": stop_ack,
            "request_to_all_pins_seconds": ended_mono - enforcement_start,
            "stop_call_to_all_pins_seconds": ended_mono - start, "enforcement_started_mono": enforcement_start,
            "stop_started_wall": start_wall, "stop_started_mono": start,
            "all_pins_ended_wall": ended_wall if all_ended else None, "all_pins_ended_mono": ended_mono if all_ended else None,
            "last_permit": self.state.permit, "restart_admitted": False}
        try:
            self.writer(self.state.root / "stop.json", self.stop_result)
        except OSError as error:
            self.stop_result["state"] = "uncertain"
            self.stop_result["errors"].append("stop receipt persistence: " + str(error))
        self.stop_result["journal"] = self.journal.status()
        return self.stop_result

    def handle_output_failure(self, channel, error):
        """Stop first; unavailable diagnostics cannot escape into another transport write.

        Confirmation is local to this call. False does not mean no bytes can arrive
        later. Neither a returned report nor a late record is restart authority.
        """
        status = channel.status()
        if status.get("failed") is not True:
            raise Refusal("Output failure handler requires a locally failed channel")
        result = self.stop("Output delivery failed: " + str(error),
                           event_started_mono=status.get("failure_started_mono"))
        payload = {"schema": 1, "scope": self.scope, "output": status,
                   "stop": deepcopy(result), "restart_admitted": False}
        confirmed, diagnostic_error = False, None
        try:
            self.writer(self.state.root / "output-failure.json", payload)
            confirmed = True
        except (OSError, Refusal) as failure:
            diagnostic_error = str(failure)
        return {**payload, "diagnostic_persisted": confirmed,
                "diagnostic_error": diagnostic_error, "journal": self.journal.status()}

    def close(self):
        try:
            if self.family and self.stop_result is None:
                self.stop("Guard owner closed")
        finally:
            try:
                if self.family:
                    self.family.close()
            finally:
                for pin in self.pins:
                    pin.close()
                self.journal.close()


def recover_state(root):
    """Read-only recovery report. No process attach or admission from saved receipts."""
    root = Path(root)
    values, errors = {}, []
    for key, filename in (("started", "started.json"), ("terminal", "terminal.json"), ("stop", "stop.json")):
        try:
            values[key] = load(root / filename) if (root / filename).exists() else None
        except (OSError, ValueError, Refusal) as error:
            values[key] = None
            errors.append(filename + ": " + str(error))
    try:
        started = values["started"]
        fields(started, {"schema", "scope", "account", "created_wall", "created_mono", "restart_admitted"})
        if (type(started["schema"]) is not int or started["schema"] != 1 or started["restart_admitted"] is not False
                or not isinstance(started["account"], str) or not started["account"]
                or not valid_clock(started["created_wall"], started["created_mono"])):
            raise Refusal("Invalid run-claim metadata")
        identifier(started["scope"])
        terminal = values["terminal"]
        if terminal is not None:
            fields(terminal, {"schema", "scope", "account", "reason", "wall", "mono", "permit", "restart_admitted"})
            if (type(terminal["schema"]) is not int or terminal["schema"] != 1 or terminal["restart_admitted"] is not False
                    or terminal["scope"] != started["scope"] or terminal["account"] != started["account"]
                    or not isinstance(terminal["reason"], str) or not terminal["reason"]):
                raise Refusal("Terminal metadata conflicts with run claim")
            if terminal["permit"] is not None:
                permit = terminal["permit"]
                fields(permit, {"schema", "scope", "issued_wall", "issued_mono", "expires_wall", "expires_mono",
                                "observation_deadline", "account", "sequence", "warning"})
                duration = permit["expires_wall"] - permit["issued_wall"]
                if (type(permit["schema"]) is not int or permit["schema"] != 1
                        or permit["scope"] != started["scope"] or permit["account"] != started["account"]
                        or type(permit["sequence"]) is not int or permit["sequence"] < 1 or type(permit["warning"]) is not bool
                        or not all(type(permit[k]) in (int, float) and math.isfinite(permit[k]) for k in
                                   ("issued_wall", "issued_mono", "expires_wall", "expires_mono", "observation_deadline"))
                        or not 0 < duration <= 90.000001
                        or abs(duration - (permit["expires_mono"] - permit["issued_mono"])) > .000001
                        or permit["expires_wall"] > permit["observation_deadline"]):
                    raise Refusal("Invalid saved permit; it is never restart authority")
        stopped = values["stop"]
        if stopped is not None:
            if (not isinstance(stopped, dict) or stopped.get("scope") != started["scope"]
                    or stopped.get("restart_admitted") is not False or stopped.get("state") not in ("stopped", "uncertain")
                    or (terminal is not None and stopped.get("last_permit") != terminal["permit"])
                    or (stopped.get("state") == "stopped" and (terminal is None or stopped.get("errors")
                        or stopped.get("all_pinned_ended") is not True))):
                raise Refusal("Stop metadata conflicts with closure evidence")
    except (Refusal, KeyError, TypeError, ValueError) as error:
        errors.append("record consistency: " + str(error))
    return {"state": "held-uncertain" if errors or values["terminal"] is None else "held",
            **values, "errors": errors, "restart_admitted": False}
