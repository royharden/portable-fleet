"""Durable one-seat operation journal. Synthetic adapter is explicitly a mock."""
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import sqlite3
import time

from .core import Refusal, canonical, digest, fields, identifier
from .process_time import CreationTime


@dataclass(frozen=True)
class Identity:
    host: str
    boot: str
    sid: str
    session: int
    helper: str
    project: str
    generation: int
    run: str
    seat: str
    launch: str
    pid: int
    creation_ticks: int
    executable: str
    parent_pid: int
    parent_ticks: int
    creation_time_unit: str
    parent_time_unit: str

    def validate(self):
        for key in ("host", "helper", "project", "run", "seat", "launch"):
            identifier(getattr(self, key))
        for key in ("session", "generation", "pid", "creation_ticks", "parent_pid", "parent_ticks"):
            value = getattr(self, key)
            if type(value) is not int or value < (0 if key == "session" else 1):
                raise Refusal("Invalid process identity")
        if any(not isinstance(getattr(self, k), str) or not getattr(self, k) for k in ("boot", "sid", "executable")):
            raise Refusal("Incomplete identity")
        CreationTime(self.creation_ticks, self.creation_time_unit).filetime()
        CreationTime(self.parent_ticks, self.parent_time_unit).filetime()


@contextmanager
def exclusive(path):
    """A crash leaves a HOLD marker. Never infer that a stale lock grants authority."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise Refusal("Seat is locked; operator recovery required") from None
    try:
        os.write(fd, str(os.getpid()).encode())
        os.fsync(fd)
        yield
    finally:
        os.close(fd)
        Path(path).unlink()


class Journal:
    def __init__(self, root, *, retain_files=False):
        if type(retain_files) is not bool:
            raise Refusal("Explicit journal retention mode required")
        self.retain_files, self._owner_fd, self._owner_pid = retain_files, None, os.getpid()
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if retain_files:
            if any(self.root.iterdir()):
                raise Refusal("Existing retained journal is recovery-only; no write reopening")
            try:
                self._owner_fd = os.open(self.root / "seat.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self._owner_fd, str(self._owner_pid).encode("ascii"))
                os.fsync(self._owner_fd)
            except BaseException:
                self.close()
                raise
        try:
            with self.connect() as db:
                db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL, result TEXT)")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._owner_fd is not None:
            os.close(self._owner_fd)
            self._owner_fd = None  # retained marker is never removed, even on clean close

    def _retained_owner(self):
        if self.retain_files and (self._owner_fd is None or os.getpid() != self._owner_pid):
            raise Refusal("Retained journal owner closed/changed; read-only recovery only")

    @contextmanager
    def connect(self):
        self._retained_owner()
        db = sqlite3.connect(self.root / "operations.sqlite", timeout=1)
        try:
            if self.retain_files:
                # Set on EVERY connection, before transactions. Fresh retained root
                # excludes WAL/hot-state migration. No ATTACH/VACUUM/temp files.
                if db.execute("PRAGMA journal_mode=PERSIST").fetchone()[0].lower() != "persist":
                    raise Refusal("Retained SQLite PERSIST mode not effective")
                db.execute("PRAGMA journal_size_limit=-1")
                db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def status(self):
        return read_status(self.root)

    def persist_phase(self, phase, request, result=None):
        """Retained storage ONLY: no adapter/recipient/effect or chained phase."""
        if not self.retain_files:
            raise Refusal("Phase persistence requires retained journal mode")
        fields(request, {"schema", "operation", "identity", "kind", "expires", "text"})
        identifier(request["operation"])
        if (type(request["schema"]) is not int or request["schema"] != 1 or request["kind"] != "send"
                or type(request["expires"]) not in (int, float) or not math.isfinite(request["expires"])
                or not isinstance(request["text"], str) or not 0 < len(request["text"]) <= 8192):
            raise Refusal("Invalid fixed phase request")
        Identity(**request["identity"]).validate()  # declared synthetic schema only
        pin = digest(canonical(request))
        if phase not in ("accepted", "executing", "outcome"):
            raise Refusal("Invalid journal phase")
        if phase != "outcome" and result is not None:
            raise Refusal("Unexpected phase result")
        if phase == "outcome" and (not isinstance(result, dict) or result.get("state") != "outcome"
                                   or result.get("operation") != request["operation"]):
            raise Refusal("Outcome does not bind operation")
        with self.connect() as db:
            old = db.execute("SELECT digest,state FROM operations WHERE id=?", (request["operation"],)).fetchone()
            if phase == "accepted":
                if old or db.execute("SELECT 1 FROM operations WHERE state!='outcome'").fetchone():
                    raise Refusal("Existing/pending phase is historical; no replay")
                db.execute("INSERT INTO operations VALUES (?,?,'accepted',NULL)", (request["operation"], pin))
            else:
                prior = "accepted" if phase == "executing" else "executing"
                if old != (pin, prior):
                    raise Refusal("Wrong phase digest/prior state; no reset")
                encoded = None if result is None else json.dumps(result, allow_nan=False)
                changed = db.execute("UPDATE operations SET state=?,result=? WHERE id=? AND digest=? AND state=?",
                                     (phase, encoded, request["operation"], pin, prior)).rowcount
                if changed != 1:
                    raise Refusal("Phase transition not confirmed")

    def execute(self, request, adapter, now=None, crash_after_action=False):
        fields(request, {"schema", "operation", "identity", "kind", "expires", "text"})
        identifier(request["operation"])
        if request["schema"] != 1 or request["kind"] not in ("read", "send", "esc", "stop"):
            raise Refusal("Outside fixed operation schema")
        if type(request["expires"]) not in (int, float) or not math.isfinite(request["expires"]) or not isinstance(request["text"], str):
            raise Refusal("Invalid request types")
        text = request["text"]
        if (request["kind"] == "send" and (not text.strip() or len(text) > 8192 or any(ord(c) < 32 or ord(c) == 127 or 0xd800 <= ord(c) <= 0xdfff or ord(c) > 0xffff for c in text))) or (request["kind"] != "send" and text):
            raise Refusal("Invalid console text")
        pin = digest(canonical(request))
        self._retained_owner()
        with (nullcontext() if self.retain_files else exclusive(self.root / "seat.lock")):
            with self.connect() as db:
                old = db.execute("SELECT digest,state,result FROM operations WHERE id=?", (request["operation"],)).fetchone()
                if old:
                    if old[0] != pin:
                        raise Refusal("Changed payload for operation ID")
                    return json.loads(old[2]) if old[1] == "outcome" else {"state": "uncertain", "operation": request["operation"]}
                if request["kind"] in ("send", "esc") and db.execute("SELECT 1 FROM operations WHERE state!='outcome'").fetchone():
                    raise Refusal("Uncertain action requires operator reconciliation")
                if not (now if now is not None else time.time()) < request["expires"]:
                    raise Refusal("Expired request")
                adapter.validate(request["identity"], request["kind"])
                db.execute("INSERT INTO operations VALUES (?,?,'accepted',NULL)", (request["operation"], pin))
            with self.connect() as db:
                db.execute("UPDATE operations SET state='executing' WHERE id=?", (request["operation"],))
            # Recheck immediately before the effect; never retry an exception as a send.
            adapter.validate(request["identity"], request["kind"])
            result = adapter.act(request["kind"], text)
            if crash_after_action:
                raise RuntimeError("Injected crash after effect")
            result = {"state": "outcome", "operation": request["operation"], **result}
            with self.connect() as db:
                db.execute("UPDATE operations SET state='outcome',result=? WHERE id=?", (json.dumps(result), request["operation"]))
            return result


class SyntheticConsole:
    """Mock composer, with explicit effects separate from assistant output."""
    def __init__(self, identity):
        identity.validate()
        self.identity = identity
        self.operator = False
        self.dialog = "ready"
        self.draft = ""
        self.alive = True
        self.events = []

    def validate(self, expected, kind):
        if expected != asdict(self.identity) or not self.alive:
            raise Refusal("Identity mismatch or ended seat")
        if kind in ("send", "esc"):
            if self.operator:
                raise Refusal("Operator owns input")
            if kind == "send" and (self.dialog != "ready" or self.draft):
                raise Refusal("Unknown dialog or existing draft")
            if kind == "esc" and self.dialog != "owned-daybreak":
                raise Refusal("Esc requires recognized owned popup")

    def act(self, kind, text):
        self.events.append((kind, text))
        if kind == "stop":
            self.alive = False
        if kind == "esc":
            self.dialog = "ready"
        return {"variant": "mock", "typed": kind == "send", "submitted": kind == "send", "visible_admission": kind == "send", "assistant_response": None, "events": len(self.events)}


def read_status(root):
    path = (Path(root).resolve() / "operations.sqlite").as_uri()
    db = sqlite3.connect(path + "?mode=ro", uri=True)
    try:
        return [dict(zip(("id", "digest", "state", "result"), row)) for row in db.execute("SELECT * FROM operations ORDER BY id")]
    finally:
        db.close()
