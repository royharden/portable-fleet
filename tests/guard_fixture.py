"""Finite local guard process. Commands arrive by blocking stdin, never file polling."""
import json
from pathlib import Path
import queue
import sys
import threading
import time
import os
import mmap

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_fleet.core import Refusal
from portable_fleet.permit_guard import GuardedFamily, retain
from portable_fleet.output_channel import BoundedOutput
from family_fixture import environment, Event


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refusal("Duplicate command key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def main(output, scope, ready_name, stop_name, fault="none", crash_name=None,
         lifetime_ms="120000", maximum_runtime="115", stall_entered_name=None,
         stall_release_name=None, stall_finished_name=None, storage_entered_name=None,
         storage_release_name=None, storage_finished_name=None):
    output = Path(output)
    lifetime_ms, maximum_runtime = int(lifetime_ms), float(maximum_runtime)
    if not 1 <= lifetime_ms <= 360000 or not 1 <= maximum_runtime <= 350:
        raise Refusal("Invalid finite fixture runtime")
    if fault not in ("none", "terminal-write-fail", "guard-crash", "terminal-stall", "renewal-stall",
                     "output-pipe-backpressure", "output-broken-active", "output-broken-initial",
                     "combined-pipe-terminal-fail", "combined-pipe-terminal-stall"):
        raise Refusal("Invalid fixture fault")
    combined = fault.startswith("combined-")
    pipe_fault = fault == "output-pipe-backpressure" or combined
    receipt_writes, stall_triggered = 0, False

    def writer(path, value):
        nonlocal receipt_writes, stall_triggered
        if combined and path.name == "terminal.json":
            entered, release, finished = Event(storage_entered_name), Event(storage_release_name), Event(storage_finished_name)
            try:
                entered.set()
                if fault == "combined-pipe-terminal-fail":
                    raise OSError("Injected combined terminal writer failure")
                if not release.wait(20000):
                    raise OSError("Unreleased combined terminal stall")
                retain(path, value)  # only admitted actor writer; late bytes stay historical
            finally:
                finished.set()
                entered.close()
                release.close()
                finished.close()
            return
        if fault == "terminal-write-fail" and path.name == "terminal.json":
            raise OSError("Injected terminal persistence failure")
        if path.parent.name == "commands" and value["command"]["kind"] == "receipt":
            receipt_writes += 1
        stall = ((fault == "terminal-stall" and path.name == "terminal.json")
                 or (fault == "renewal-stall" and path.parent.name == "commands"
                     and value["command"]["kind"] == "receipt" and receipt_writes == 2))
        if stall and not stall_triggered:
            stall_triggered = True
            entered, release, finished = Event(stall_entered_name), Event(stall_release_name), Event(stall_finished_name)
            try:
                entered.set()
                if not release.wait(20000):
                    raise OSError("Unreleased injected storage stall")
                retain(path, value)
            finally:
                finished.set()
                entered.close()
                release.close()
                finished.close()
            return
        retain(path, value)

    guard = None
    incoming = queue.Queue()

    def read_commands():
        try:
            while True:  # blocking input stream, no status polling
                raw = sys.stdin.buffer.readline(65537)
                if not raw:
                    incoming.put(("closed", None))
                    return
                if len(raw) > 65536 or not raw.endswith(b"\n"):
                    incoming.put(("invalid", "Invalid/oversized command frame"))
                    return
                try:
                    incoming.put(("command", strict_json(raw)))
                except (ValueError, Refusal, RecursionError):
                    incoming.put(("invalid", "Command parse failure"))
                    return
        except OSError:
            incoming.put(("invalid", "Command stream failure"))

    output_frames = 0

    def sink(frame):
        if fault == "output-broken-initial" or (fault == "output-broken-active" and output_frames == 4):
            raise BrokenPipeError("Injected disconnected output")
        if pipe_fault and output_frames == 4:
            entered = Event(stall_entered_name)
            try:
                entered.set()
            finally:
                entered.close()
        return os.write(sys.stdout.fileno(), frame)  # no BufferedWriter lock or shutdown flush

    channel = BoundedOutput(sink, remaining=lambda: None if guard is None else guard._old_lease_remaining())

    def emit(value):
        nonlocal output_frames
        output_frames += 1
        if pipe_fault and output_frames == 4:
            value = {**value, "fixture_padding": "x" * 60000}
        channel.send(value)

    def memory_report(value):
        # Test-only volatile mapping, after stop. No filesystem bypass or delivery
        # confirmation: the parent independently checks pinned exits before reading.
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(raw) > 65532:
            raise Refusal("Oversized test memory report")
        with mmap.mmap(-1, 65536, tagname="Local\\PF-guard-report-" + scope) as memory:
            memory[4:4 + len(raw)] = raw
            memory[:4] = len(raw).to_bytes(4, "little")

    try:
        argv = [sys.executable, "-I", "-B", str(Path(__file__).with_name("family_fixture.py")),
                "root", str(output), ready_name, stop_name, str(lifetime_ms), "work"]
        guard = GuardedFamily(argv, str(output), environment(), output / "state", scope, "synthetic-account", writer=writer)
        emit({"event": "waiting", "scope": scope, "pid": guard.family.pid})
        if fault == "guard-crash":
            def crash_when_requested():
                event = Event(crash_name)
                try:
                    if event.wait(10000):
                        os._exit(73)
                finally:
                    event.close()
            threading.Thread(target=crash_when_requested, daemon=True).start()
        threading.Thread(target=read_commands, daemon=True).start()
        hard_deadline = time.monotonic() + maximum_runtime
        while guard.stop_result is None:  # command/deadline events, no status queries or sleeps
            try:
                wait = min(guard.deadline_wait_seconds(), max(0, hard_deadline - time.monotonic()))
                if wait <= 0:
                    emit(guard.stop("Finite fixture maximum or lease deadline"))
                    break
                kind, value = incoming.get(timeout=wait)
            except queue.Empty:
                emit(guard.stop("No initial receipt" if guard.state.permit is None else "Permit deadline without renewal"))
                break
            except Refusal as error:
                emit(guard.stop(str(error)))
                break
            if kind != "command":
                emit(guard.stop("Supervisor input lost" if kind == "closed" else value))
            else:
                emit(guard.receive(value))
        if stall_triggered:
            finished = Event(stall_finished_name)
            try:
                finished.wait(10000)  # bounded late-completion experiment, after family enforcement
                emit({"event": "late-storage", "closed": guard.state.closed,
                      "journal": guard.journal.status(), "restart_admitted": False})
            finally:
                finished.close()
        return 0
    except (Refusal, OSError, ValueError, TypeError, RecursionError) as error:
        if channel.status()["failed"]:
            if guard:
                report = guard.handle_output_failure(channel, error)
                if combined:
                    memory_report(report)
                finished = Event(stall_finished_name)
                try:
                    finished.set()  # independent local evidence, after stop; no transport fallback
                finally:
                    finished.close()
                if pipe_fault:
                    release = Event(stall_release_name)
                    try:
                        release.wait(10000)  # finite late-drain observation, family already stopped
                        if combined:
                            prior = guard.stop_result
                            rejected = guard.receive({"untrusted": "attempt after both failures"})
                            memory_report({**report, "after_release": {
                                "output": channel.status(), "journal": guard.journal.status(),
                                "closed": guard.state.closed, "terminal_persisted": guard.state.terminal_persisted,
                                "same_terminal_result": rejected is prior, "restart_admitted": False}})
                        else:
                            guard.writer(guard.state.root / "output-late.json", {
                                "schema": 1, "scope": scope, "output": channel.status(),
                                "closed": guard.state.closed, "restart_admitted": False})
                    finally:
                        release.close()
            return 3
        if guard:
            guard.stop("Fixture exception: " + str(error))
        emit({"event": "refused", "error": str(error), "restart_admitted": False})
        return 2
    finally:
        channel.close()
        if guard:
            guard.close()


if __name__ == "__main__":
    code = main(*sys.argv[1:])
    if code == 3:
        # main's finally has stopped/closed the owned job and actor handles. A failed
        # transport may leave daemon native I/O blocked; do not run interpreter
        # teardown or buffered flush against it. This is a finite fixture exit,
        # not a claim of graceful delivery or general process-host shutdown.
        os._exit(code)
    sys.exit(code)
