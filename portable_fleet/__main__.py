import argparse
import json
import sqlite3
from pathlib import Path
import sys

from .core import Refusal, canonical, digest, generate_run, load, package, profile, select_config, verify
from .seat import read_status


def main():
    parser = argparse.ArgumentParser(prog="python -m portable_fleet")
    sub = parser.add_subparsers(dest="action", required=True)
    doctor = sub.add_parser("doctor", help="Read-only explicit host/project profile check")
    doctor.add_argument("--config")
    status = sub.add_parser("status", help="Read-only durable operation outcomes")
    status.add_argument("state_root")
    run = sub.add_parser("generate-run")
    run.add_argument("source")
    run.add_argument("destination")
    run.add_argument("manifest")
    run.add_argument("--config", required=True)
    check = sub.add_parser("verify")
    check.add_argument("root")
    check.add_argument("manifest")
    check.add_argument("--digest", required=True)
    build = sub.add_parser("package")
    build.add_argument("source")
    build.add_argument("destination")
    build.add_argument("manifest")
    args = parser.parse_args()
    try:
        if args.action == "doctor":
            obj = profile(select_config(args.config))
            result = {"profile_digest": digest(canonical(obj)), "host": obj["hostname"], "projects": len(obj["projects"]),
                      "remote_verified": False, "production_admitted": False}
        elif args.action == "status":
            result = {"operations": read_status(args.state_root)}
        elif args.action == "generate-run":
            result = generate_run(args.source, args.destination, load(args.manifest), args.config)
        else:
            manifest = load(args.manifest)
            if args.action == "verify":
                pin = verify(args.root, manifest)
                if pin != args.digest:
                    raise Refusal("Expected manifest digest mismatch")
                result = {"verified": True, "digest": pin, "runtime_verified": False}
            else:
                result = {"digest": package(args.source, args.destination, manifest), "runtime_verified": False}
        print(json.dumps(result, indent=2))
        return 0
    except (Refusal, OSError, ValueError, sqlite3.Error) as error:
        print(json.dumps({"refused": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
