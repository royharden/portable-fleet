"""Explicit synthetic capture/restore and sequential Git handoff fixtures.

No dataset discovery, live registry reads, runtime DB capture or real-project admission.
"""
from pathlib import Path
import subprocess

from .core import Refusal, canonical, digest, fields, inventory, load, package, publish, relative, verify, within


def git(root, *args):
    import os
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    return result.stdout


def capture(root, names, destination, metadata):
    """Only exact caller-authorized files; no globs, recursion or live DB adapter."""
    if any(n.lower().endswith((".sqlite", ".db", "-wal", "-shm")) for n in names):
        raise Refusal("Live database capture needs an admitted consistent exporter")
    files = inventory(root, names)
    manifest = {"schema": 1, "files": files, "dependencies": {}}
    destination = Path(destination)
    pin = package(root, destination, manifest)
    # Re-read source to detect an evolving snapshot rather than claim consistency.
    if inventory(root, names) != files:
        raise Refusal("Source changed during capture; incomplete capture retained")
    publish(destination / "capture.json", canonical({"manifest_digest": pin, "metadata": metadata}))
    return pin


def restore(source, destination, expected_digest):
    manifest = load(Path(source) / "manifest.json")
    if verify(source, manifest) != expected_digest:
        raise Refusal("Wrong/corrupt capture")
    return package(source, destination, manifest)


def close_source(authority, project, generation, ended_launches):
    fields(ended_launches, {"variant", "all_ended", "launches"})
    if ended_launches["variant"] != "fixture" or ended_launches["all_ended"] is not True:
        raise Refusal("Only synthetic handoff is admitted")
    authority = Path(authority)
    publish(authority / "closed.json", canonical({"project": project, "generation": generation, "ended": ended_launches}))


def export_git(source, destination, authority, approved_untracked, notes_root, approved_notes):
    """HEAD only, full reachable prerequisites; separate binary index/worktree patches."""
    source, destination = Path(source), Path(destination)
    closed = load(Path(authority) / "closed.json")
    before_head = git(source, "rev-parse", "HEAD")
    if git(source, "ls-files", "-u"):
        raise Refusal("Unmerged index")
    tracked = git(source, "ls-files", "-z").decode("utf-8").rstrip("\0").split("\0")
    staged = git(source, "ls-files", "--stage").decode("utf-8")
    if any(line.startswith(("160000", "120000")) for line in staged.splitlines()):
        raise Refusal("Submodule/symlink unsupported")
    if any(not line.startswith("H ") for line in git(source, "ls-files", "-v").decode("utf-8").splitlines()):
        raise Refusal("Sparse/assume-unchanged files need an adapter")
    import re
    if any(int(flag, 16) & 0x60000000 for flag in re.findall(r"flags: ([0-9a-fA-F]+)", git(source, "ls-files", "--debug").decode("utf-8"))):
        raise Refusal("Intent-to-add/skip-worktree needs an adapter")
    if git(source, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"):
        raise Refusal("Ignored content needs an explicit exclusion adapter")
    if ".gitattributes" in tracked:
        if b"filter=lfs" in (source / ".gitattributes").read_bytes():
            raise Refusal("LFS content requires a supported adapter")
    untracked = git(source, "ls-files", "--others", "--exclude-standard", "-z").decode("utf-8").rstrip("\0")
    actual = [] if not untracked else untracked.split("\0")
    if set(actual) != set(approved_untracked):
        raise Refusal("Untracked scope differs from exact allowlist")
    existing = [n for n in tracked if (source / n).exists()]
    inventory(source, existing + actual)  # path/case/link validation before reading
    destination.mkdir(parents=True, exist_ok=False)
    bundle = destination / "base.bundle"
    git(source, "bundle", "create", str(bundle.resolve()), "HEAD")
    head = git(source, "rev-parse", "HEAD").decode().strip()
    index_patch = git(source, "diff", "--cached", "--binary", "--full-index", "HEAD", "--")
    work_patch = git(source, "diff", "--binary", "--full-index", "--")
    publish(destination / "index.patch", index_patch)
    publish(destination / "worktree.patch", work_patch)
    for name in approved_untracked:
        publish(destination / "untracked" / Path(*relative(name)), within(source, name).read_bytes())
    # Complete fixture registry/counter files are provided explicitly, not inferred.
    for name in approved_notes:
        publish(destination / "notes" / Path(*relative(name)), within(notes_root, name).read_bytes())
    names = ["base.bundle", "index.patch", "worktree.patch"] + ["untracked/" + n for n in approved_untracked] + ["notes/" + n for n in approved_notes]
    payload = {"schema": 1, "files": inventory(destination, names), "dependencies": {}}
    record = {"variant": "fixture", "closed": closed, "head": head, "manifest": payload,
              "untracked": approved_untracked, "notes": approved_notes,
              "index_patch_digest": digest(index_patch),
              "worktree": inventory(source, existing + actual), "tracked": tracked}
    if (git(source, "rev-parse", "HEAD") != before_head
            or git(source, "diff", "--cached", "--binary", "--full-index", "HEAD", "--") != index_patch
            or git(source, "diff", "--binary", "--full-index", "--") != work_patch):
        raise Refusal("Source changed during handoff; source remains closed")
    publish(destination / "handoff.json", canonical(record))
    pin = digest(canonical(record))
    publish(Path(authority) / "released.json", canonical({"packet": pin}))
    return pin


def import_git(packet, destination, expected_digest, target_authority):
    packet, destination = Path(packet), Path(destination)
    record = load(packet / "handoff.json")
    if digest(canonical(record)) != expected_digest or record["variant"] != "fixture":
        raise Refusal("Handoff digest/variant mismatch")
    verify(packet, record["manifest"])
    if destination.exists():
        raise Refusal("Target must be new")
    if Path(target_authority).exists():
        raise Refusal("Target authority must be new")
    subprocess.run(["git", "clone", "--no-checkout", str(packet / "base.bundle"), str(destination)], capture_output=True, check=True)
    git(destination, "checkout", "--detach", record["head"])
    for name, flags in (("index.patch", ["--index"]), ("worktree.patch", [])):
        if (packet / name).stat().st_size:
            git(destination, "apply", *flags, "--binary", str((packet / name).resolve()))
    for name in record["untracked"]:
        publish(destination / Path(*relative(name)), within(packet, "untracked/" + name).read_bytes())
    if digest(git(destination, "diff", "--cached", "--binary", "--full-index", "HEAD", "--")) != record["index_patch_digest"]:
        raise Refusal("Index mismatch; target HOLD")
    existing = [n for n in record["tracked"] if (destination / n).exists()]
    if inventory(destination, existing + record["untracked"]) != record["worktree"]:
        raise Refusal("Worktree mismatch; target HOLD")
    # Notes remain sealed in packet until separately admitted, never live .git/registry.
    acceptance = {"packet": expected_digest, "project": record["closed"]["project"],
                  "generation": record["closed"]["generation"] + 1, "state": "prepared-hold"}
    publish(Path(target_authority) / "acceptance.json", canonical(acceptance))
    return acceptance


def acknowledge(authority, acceptance):
    closed = load(Path(authority) / "closed.json")
    released = load(Path(authority) / "released.json")
    if acceptance["packet"] != released["packet"] or acceptance["project"] != closed["project"] or acceptance["generation"] != closed["generation"] + 1 or acceptance["state"] != "prepared-hold":
        raise Refusal("Wrong owner generation")
    publish(Path(authority) / "ack.json", canonical(acceptance))
    return digest(canonical(acceptance))


def admit_target(target_authority, ack, expected_ack_digest):
    acceptance = load(Path(target_authority) / "acceptance.json")
    if ack != acceptance or digest(canonical(ack)) != expected_ack_digest:
        raise Refusal("Missing/mismatched source acknowledgment")
    publish(Path(target_authority) / "admitted.json", canonical(ack))


def admission(authority, generation):
    """Default closed; released source can never be reopened by a stale target receipt."""
    if (Path(authority) / "closed.json").exists():
        return False
    try:
        state = load(Path(authority) / "admitted.json")
        return state["generation"] == generation
    except (OSError, ValueError, KeyError):
        return False
