"""Explicit opt-in wall-clock Windows experiment; no model, task, network or shared process."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from portable_fleet.core import canonical, load, publish
from portable_fleet.supervision import Observation, Supervisor
from portable_fleet.watchdog import query_creation_time
from portable_fleet.process_time import FILETIME


def main(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    processes = []
    watchers = []
    cases = []
    sentinel = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(400)"])
    processes.append(sentinel)
    try:
        for name, duration in (("killed-helper-supervisor", 90), ("stale-observation-live-renewals", 300)):
            work = root / (name + ".work")
            code = "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\ni=0\nwhile True:\n i+=1\n p.write_text(str(i))\n time.sleep(.05)\n"
            victim = subprocess.Popen([sys.executable, "-c", code, str(work)])
            processes.append(victim)
            ticks = query_creation_time(victim.pid).value
            start_wall, start_mono = time.time(), time.monotonic()
            supervisor = Supervisor("synthetic-account")
            supervisor.observe(Observation("synthetic-account", 1, start_wall, 80, "fixture-window"), start_wall)
            scope = str(uuid.uuid4())
            permit_path = root / (name + ".permit.json")
            publish(permit_path, canonical(supervisor.permit(start_wall, start_mono, scope)))
            watcher = subprocess.Popen([sys.executable, "-m", "portable_fleet.watchdog", "--permit", str(permit_path),
                        "--scope", json.dumps(scope), "--pid", str(victim.pid), "--ticks", str(ticks),
                        "--ticks-unit", FILETIME,
                        "--receipt", str(root / (name + ".receipt.json"))])
            watchers.append(watcher)
            # This producer really writes permits, and is independent of the watchdog.
            helper = subprocess.Popen([sys.executable, str(Path(__file__).with_name("permit_fixture.py")),
                                       str(permit_path), scope, str(start_wall)])
            processes.append(helper)
            deadline = time.monotonic() + 5
            while not permit_path.with_suffix(".ready").exists():
                if helper.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("Synthetic supervisor did not start")
                time.sleep(.01)
            if duration == 90:
                last_permit = load(permit_path)
                start_wall = last_permit["issued_wall"]
                start_mono = last_permit["issued_mono"]
                helper.terminate()
                helper.wait(timeout=5)
            cases.append({"name": name, "victim": victim, "supervisor": supervisor, "scope": scope,
                          "permit": permit_path, "wall": start_wall, "mono": start_mono,
                          "duration": duration, "next_renewal": start_mono + 30, "ticks": ticks})
        while any(p.poll() is None for p in watchers):
            now = time.monotonic()
            if now - cases[0]["mono"] > 315:
                raise AssertionError("Watchdog exceeded experiment timeout")
            time.sleep(.1)
        results = []
        for case in cases:
            receipt = load(root / (case["name"] + ".receipt.json"))
            elapsed = receipt["ended_wall"] - case["wall"]
            count = int((root / (case["name"] + ".work")).read_text())
            assert receipt["ended"] and case["duration"] - .1 <= elapsed <= case["duration"] + 10 and count > 100
            assert case["victim"].wait(timeout=5) == 125
            results.append({"variant": case["name"], "elapsed": elapsed, "work_iterations": count,
                            "deadline": case["duration"] + 10, "pid": case["victim"].pid, "ticks": case["ticks"]})
        assert sentinel.poll() is None
        publish(root / "RESULT.json", canonical({"variant": "windows-single-process-fixtures", "cases": results,
                    "sentinel_survived": True, "sentinel_pid": sentinel.pid, "provider_source": "synthetic", "production_admitted": False}))
        print(json.dumps(results, indent=2), flush=True)
    finally:
        for process in watchers + processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main(sys.argv[1])
