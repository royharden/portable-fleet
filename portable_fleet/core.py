"""Strict profiles, immutable content and target-side paths (stdlib only)."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import uuid


class Refusal(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fields(obj, required):
    if not isinstance(obj, dict) or set(obj) != set(required):
        raise Refusal(f"Expected fields: {sorted(required)}")


def identifier(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Refusal("Expected canonical UUID") from None
    return value


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refusal("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def publish(path, data):
    """Create once. A complete same-volume temp file is linked atomically; never replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            raise Refusal(f"Existing content: {path}") from None
    finally:
        temp.unlink(missing_ok=True)


def relative(name):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise Refusal("Invalid relative path")
    parts = name.split("/")
    if any(ord(c) < 32 or c in '<>"|?*' for c in name):
        raise Refusal("Invalid Windows filename")
    if any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts):
        raise Refusal("Unsafe path component")
    if PurePosixPath(name).is_absolute():
        raise Refusal("Absolute path")
    if any(p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1,10)], *[f"LPT{i}" for i in range(1,10)]} for p in parts):
        raise Refusal("Reserved Windows path")
    return parts


def within(root, name, must_exist=True):
    root = Path(root).resolve(strict=True)
    result = root.joinpath(*relative(name))
    current = root
    for part in relative(name):
        current /= part
        if current.is_symlink() or (current.exists() and getattr(current.lstat(), "st_file_attributes", 0) & 0x400):
            raise Refusal("Links/reparse points are unsupported")
    resolved = result.resolve(strict=must_exist)
    if not resolved.is_relative_to(root):
        raise Refusal("Path escaped root")
    return resolved


def absolute_directory(value):
    if not isinstance(value, str):
        raise Refusal("One explicit root string is required; root guessing is forbidden")
    path = Path(value)
    if not path.is_absolute() or not path.is_dir():
        raise Refusal(f"Missing explicit absolute directory: {value}")
    if path.is_symlink():
        raise Refusal("Linked root")
    return path.resolve(strict=True)


def profile(path):
    obj = load(path)
    fields(obj, {"schema", "host_id", "hostname", "pj_root", "skills_root", "state_root", "projects"})
    if obj["schema"] != 1 or not isinstance(obj["hostname"], str) or not obj["hostname"]:
        raise Refusal("Invalid host profile")
    identifier(obj["host_id"])
    for key in ("pj_root", "skills_root", "state_root"):
        obj[key] = str(absolute_directory(obj[key]))
    if not isinstance(obj["projects"], list):
        raise Refusal("projects must be a list")
    seen = set()
    seen_names = set()
    seen_roots = set()
    for project in obj["projects"]:
        fields(project, {"id", "name", "root", "registry_root"})
        identifier(project["id"])
        if project["id"] in seen or not isinstance(project["name"], str):
            raise Refusal("Duplicate/invalid project")
        seen.add(project["id"])
        for key in ("root", "registry_root"):
            project[key] = str(absolute_directory(project[key]))
        if project["name"].casefold() in seen_names or project["root"].casefold() in seen_roots:
            raise Refusal("Ambiguous project name/root")
        seen_names.add(project["name"].casefold())
        seen_roots.add(project["root"].casefold())
    return obj


def select_config(explicit=None, environ=None):
    env = os.environ if environ is None else environ
    selected = explicit or env.get("FLEET_CONFIG")
    if selected is None:
        if "LOCALAPPDATA" not in env:
            raise Refusal("No named default profile")
        selected = str(Path(env["LOCALAPPDATA"]) / "AgentFleet/host.json")
    return Path(selected)  # Missing explicit input never falls back.


def command(executable, args):
    if not Path(executable).is_absolute() or not Path(executable).is_file():
        raise Refusal("Executable must be an existing absolute file")
    argv = [str(executable), *args]
    if any(not isinstance(a, str) or "\0" in a for a in argv):
        raise Refusal("Invalid argv")
    return argv


def windows_commandline(argv):
    # The single quoting routine; invoke via argv with shell=False whenever possible.
    return subprocess.list2cmdline(argv)


def inventory(root, names):
    if len({n.casefold() for n in names}) != len(names):
        raise Refusal("Case collision or duplicate")
    result = {}
    for name in sorted(names):
        path = within(root, name)
        if not path.is_file():
            raise Refusal("Expected regular file")
        data = path.read_bytes()
        result[name] = {"sha256": digest(data), "bytes": len(data)}
    return result


def make_manifest(root, names, dependencies):
    files = inventory(root, names)
    if not isinstance(dependencies, dict):
        raise Refusal("Invalid dependency map")
    for name, required in dependencies.items():
        if name not in files or not isinstance(required, list) or any(dep not in files for dep in required):
            raise Refusal("Dependency closure missing")
    return {"schema": 1, "files": files, "dependencies": dependencies}


def verify(root, manifest):
    fields(manifest, {"schema", "files", "dependencies"})
    if manifest["schema"] != 1 or make_manifest(root, list(manifest["files"]), manifest["dependencies"]) != manifest:
        raise Refusal("Manifest mismatch")
    return digest(canonical(manifest))


def package(source, destination, manifest):
    pin = verify(source, manifest)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for name in manifest["files"]:
        publish(destination.joinpath(*relative(name)), within(source, name).read_bytes())
    publish(destination / "manifest.json", canonical(manifest))
    if verify(destination, manifest) != pin:
        raise Refusal("Recipient mismatch")
    return pin


def generate_run(source, destination, manifest, config):
    """Immutable local run envelope; it grants no model or remote admission."""
    validated = profile(config)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    pin = package(source, destination / "release", manifest)
    envelope = {"schema": 1, "run": str(uuid.uuid4()), "release_digest": pin,
                "profile_digest": digest(canonical(validated)), "profile": validated,
                "environment": {"PJ_ROOT": validated["pj_root"], "SKILLS_ROOT": validated["skills_root"], "PJ_SKILLS": validated["skills_root"]},
                "admission": "closed"}
    publish(destination / "run.json", canonical(envelope))
    return envelope
