"""Declared synthetic identity only; no actual host/process/provider admission."""
from portable_fleet.seat import Identity
from portable_fleet.process_time import FILETIME
from test_permit_guard import uid


def declared_identity():
    return Identity(uid(), "synthetic-boot", "synthetic-sid", 1, uid(), uid(), 1,
                    uid(), uid(), uid(), 100, 1234, "synthetic.exe", 99, 1233, FILETIME, FILETIME)
