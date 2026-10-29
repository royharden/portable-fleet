"""Runnable local vertical slice, with every console/provider result labeled synthetic."""
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time
import uuid

from .core import canonical, publish
from .seat import Identity, Journal, SyntheticConsole
from .process_time import FILETIME
from .supervision import Observation, Supervisor, expired
from .transfer import capture, restore


def main(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    uid = lambda: str(uuid.uuid4())
    seat = SyntheticConsole(Identity(uid(), "mock-boot", "mock-sid", 1, uid(), uid(), 1, uid(), uid(), uid(), 100, 1, "mock.exe", 99, 1, FILETIME, FILETIME))
    journal = Journal(root / "state")
    now = time.time()
    request = {"schema": 1, "operation": uid(), "identity": asdict(seat.identity), "kind": "send", "expires": now + 60, "text": "synthetic canary"}
    first = journal.execute(request, seat)
    replay = journal.execute(request, seat)
    supervisor = Supervisor("mock-account")
    supervisor.observe(Observation("mock-account", 1, now, 80, "mock-window"), now)
    permit = supervisor.permit(now, 1, request["identity"])
    assert expired(permit, now + 91, 92, request["identity"])
    stop = {**request, "operation": uid(), "kind": "stop", "text": ""}
    journal.execute(stop, seat)
    source = root / "authorized-fixture"
    source.mkdir()
    publish(source / "parent.jsonl", b'{"id":"fixture-parent"}\n')
    publish(source / "child.jsonl", b'{"id":"fixture-child","parent":"fixture-parent"}\n')
    pin = capture(source, ["parent.jsonl", "child.jsonl"], root / "archive-v1", {"variant": "fixture", "boundary": "closed files", "sessions": ["fixture-parent", "fixture-child"]})
    restore(root / "archive-v1", root / "restored", pin)
    result = {"variant": "synthetic", "send": first, "duplicate_identical": first == replay,
              "send_effect_count": sum(k == "send" for k, _ in seat.events), "seat_ended": not seat.alive,
              "restore_digest": pin, "remote_verified": False, "production_admitted": False}
    publish(root / "result.json", canonical(result))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
