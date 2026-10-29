"""Existing operations table for synthetic dispatch; recovery NEVER replays.

Synchronous SQLite belongs only to this finite synthetic host. It is not placed
on owned-job stop duty, nor queued on a worker that could execute a late effect.
"""
from copy import deepcopy
from dataclasses import asdict
import json
import sqlite3

from .core import Refusal, canonical, fields, identifier
from .dispatch import SyntheticDispatcher
from .seat import Identity, Journal, read_status


class _CounterAdapter:
    def __init__(self, owner, queued, text):
        self.owner, self.queued, self.text = owner, deepcopy(queued), text

    def validate(self, identity, kind):
        if identity != self.owner.identity or kind != "send":
            raise Refusal("Wrong declared synthetic journal identity/kind")
        queued = self.owner.dispatcher.status()["queued"]
        if not queued or queued[0] != self.queued:
            raise Refusal("Journal request differs from exact queued effect/receipt")
        if self.owner.recipient.require_current() != self.queued["binding"]:
            raise Refusal("Journal receipt superseded/expired")

    def act(self, kind, text):
        if kind != "send" or text != self.text:
            raise Refusal("Journal text differs from exact synthetic effect")
        result = self.owner.dispatcher.dispatch_next()  # final live check AFTER journal writes
        return {"variant": "synthetic-memory-counter", "effect": result,
                "restart_admitted": False}


class JournaledDispatcher:
    def __init__(self, recipient, root, identity):
        if type(identity) is not Identity:
            raise Refusal("Declared synthetic identity required")
        identity.validate()  # schema only; no native identity/provider admission claim
        self.identity, self.recipient = asdict(identity), recipient
        self.dispatcher = SyntheticDispatcher(recipient)
        self.journal = Journal(root, retain_files=True)
        self.last_request = None

    def enqueue(self, command):
        return self.dispatcher.enqueue(command)

    def _request_for(self, head):
        request = {"schema": 1, "operation": head["command"]["operation"],
            "identity": deepcopy(self.identity), "kind": "send",
            "expires": head["binding"]["expires_wall"], "text": canonical(head).decode("utf-8")}
        self.last_request = deepcopy(request)
        return request

    def dispatch_next(self):
        try:
            queued = self.dispatcher.status()["queued"]
            if not queued:
                raise Refusal("No synthetic journal effect queued")
            head = queued[0]
            request = self._request_for(head)
            adapter = _CounterAdapter(self, head, request["text"])
            return self.journal.execute(request, adapter, now=self.recipient._clock()[0])
        except BaseException as error:
            # Includes outcome persistence failure AFTER the effect completed.
            self.dispatcher.close("Journal dispatch failed: " + str(error), uncertain=True)
            raise

    def close(self):
        self.dispatcher.close("Synthetic journal owner closed")
        self.journal.close()


def recover_operations(root):
    """Historical existing-table read only; no lock removal, repair or admission."""
    rows, errors = [], []
    try:
        rows = read_status(root)
        for row in rows:
            fields(row, {"id", "digest", "state", "result"})
            identifier(row["id"])
            if (not isinstance(row["digest"], str) or len(row["digest"]) != 64
                    or any(c not in "0123456789abcdef" for c in row["digest"])
                    or row["state"] not in ("accepted", "executing", "outcome")):
                raise Refusal("Invalid historical operation row")
            if row["state"] == "outcome":
                result = json.loads(row["result"])
                if result.get("operation") != row["id"] or result.get("state") != "outcome":
                    raise Refusal("Outcome conflicts with historical operation")
            elif row["result"] is not None:
                raise Refusal("Partial operation has unexpected result")
    except (OSError, sqlite3.Error, Refusal, KeyError, TypeError, ValueError, AttributeError) as error:
        errors.append(str(error))
    return {"state": "held-uncertain" if errors or any(r["state"] != "outcome" for r in rows) else "held",
            "operations": rows, "errors": errors, "historical_only": True, "restart_admitted": False}
