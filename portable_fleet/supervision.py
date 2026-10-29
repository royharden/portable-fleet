"""Fail-closed permit calculation. Provider observations must come from an admitted source."""
from dataclasses import dataclass
import math

from .core import Refusal


@dataclass(frozen=True)
class Observation:
    account: str
    sequence: int
    observed: float
    percent_left: float
    reset: str


class Supervisor:
    renewal_seconds = 30
    permit_seconds = 90
    observation_seconds = 300
    stop_budget_seconds = 10

    def __init__(self, account):
        self.account = account
        self.observation = None
        self.closed = False
        self.reason = None

    def close(self, reason):
        self.closed, self.reason = True, reason
        raise Refusal(reason)

    def observe(self, observation, now):
        if self.closed:
            raise Refusal("Admission closed; explicit restart required")
        if not isinstance(observation, Observation):
            self.close("Provider parse failure")
        if observation.account != self.account or type(observation.sequence) is not int or observation.sequence < 1:
            self.close("Invalid account/sequence")
        if not all(type(x) in (int, float) and math.isfinite(x) for x in (observation.observed, observation.percent_left, now)):
            self.close("Invalid provider numbers")
        if not 0 <= now - observation.observed < 300 or not 0 <= observation.percent_left <= 100 or not observation.reset:
            self.close("Stale/invalid observation")
        previous = self.observation
        if previous:
            if observation.sequence == previous.sequence and observation == previous:
                return  # Identical observation does not gain a new timestamp.
            if observation.sequence <= previous.sequence or observation.observed <= previous.observed or observation.reset != previous.reset or observation.percent_left > previous.percent_left:
                self.close("Unexpected reset/replay")
        if observation.percent_left <= 7:
            self.close("Reserve/zero stop")
        self.observation = observation

    def permit(self, now, monotonic, scope):
        if self.closed or self.observation is None:
            raise Refusal("No valid supervision")
        expiry = min(now + 90, self.observation.observed + 300)
        if expiry <= now:
            self.close("Observation expired")
        return {"schema": 1, "scope": scope, "issued_wall": now, "issued_mono": monotonic,
                "expires_wall": expiry, "expires_mono": monotonic + expiry - now,
                "observation_deadline": self.observation.observed + 300,
                "account": self.account, "sequence": self.observation.sequence,
                "warning": self.observation.percent_left <= 15}


def expired(permit, wall, monotonic, scope):
    """Dual clocks catch resume and backwards clock steps; scope pins boot/process."""
    try:
        if permit["schema"] != 1 or permit["scope"] != scope:
            return True
        values = [permit[k] for k in ("issued_wall", "issued_mono", "expires_wall", "expires_mono", "observation_deadline")]
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
            return True
        wall_age = wall - permit["issued_wall"]
        mono_age = monotonic - permit["issued_mono"]
        return (wall_age < 0 or mono_age < 0 or abs(wall_age - mono_age) > 2
                or permit["expires_wall"] - permit["issued_wall"] > 90.000001
                or permit["expires_mono"] - permit["issued_mono"] > 90.000001
                or permit["expires_wall"] > permit["observation_deadline"]
                or wall >= permit["expires_wall"] or monotonic >= permit["expires_mono"])
    except (KeyError, TypeError):
        return True
