"""Explicit process creation-time units; legacy receipts are never magnitude-guessed."""
from dataclasses import dataclass

from .core import Refusal, fields


FILETIME = "windows-filetime-100ns"
DOTNET_TICKS = "dotnet-datetime-100ns"
EPOCH_OFFSET = 504911232000000000
MAX_DOTNET_TICKS = 3155378975999999999
MAX_FILETIME = MAX_DOTNET_TICKS - EPOCH_OFFSET


@dataclass(frozen=True)
class CreationTime:
    value: int
    unit: str

    def filetime(self):
        if type(self.value) is not int:
            raise Refusal("Creation time must be an integer, never bool/float/string")
        if self.unit == FILETIME:
            result = self.value
        elif self.unit == DOTNET_TICKS:
            if self.value > MAX_DOTNET_TICKS:
                raise Refusal("DateTime creation time exceeds supported range")
            result = self.value - EPOCH_OFFSET
        else:
            raise Refusal("Missing/unknown creation-time unit")
        if not 0 < result <= MAX_FILETIME:
            raise Refusal("Creation time outside supported positive FILETIME range")
        return result

    @classmethod
    def from_record(cls, record):
        fields(record, {"value", "unit"})
        result = cls(record["value"], record["unit"])
        result.filetime()
        return result


def legacy_dotnet_creation_time(value):
    """Explicit opt-in adapter for known historical .NET receipts, not auto-detection."""
    stamp = CreationTime(value, DOTNET_TICKS)
    return CreationTime(stamp.filetime(), FILETIME)
