"""Separate synthetic supervisor/helper process for kill and stale-source experiments."""
import os
from pathlib import Path
import sys
import time

from portable_fleet.core import canonical
from portable_fleet.supervision import Observation, Supervisor


def main(path, scope, observed):
    path = Path(path)
    supervisor = Supervisor("synthetic-account")
    supervisor.observe(Observation("synthetic-account", 1, observed, 80, "fixture-window"), time.time())
    while time.time() < observed + 300:
        temp = path.with_suffix(".next")
        temp.write_bytes(canonical(supervisor.permit(time.time(), time.monotonic(), scope)))
        os.replace(temp, path)
        path.with_suffix(".ready").write_text("synthetic-supervisor-running")
        time.sleep(30)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], float(sys.argv[3]))
