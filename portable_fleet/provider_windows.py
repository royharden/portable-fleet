"""Noncredential native AGY profile context for the bounded usage bridge.

Call this I/O-bearing reader before effects or through ProviderUsageBridge's
bounded context worker. Never put it directly on native deadline stop duty.
Account identity remains operator-attested; this does not inspect auth stores.
"""
import ctypes as c
from ctypes import wintypes as w
from dataclasses import replace
import json
from pathlib import Path

from .core import Refusal, canonical, digest
from .native_io import identity
from .provider_usage import ProfileScope

DEFAULT_ROUTE = "owner-agy-profile:no-api:no-vertex:no-custom-endpoint"
FALSE_FLAGS = ("useG1Credits", "allowNonWorkspaceAccess", "disableSlashCommands")
DENY_RULES = ("command(*)", "read_file(*)", "write_file(*)", "read_url(*)", "execute_url(*)", "mcp(*)")


def native_boot():
    api = c.WinDLL("ntdll")
    api.NtQuerySystemInformation.argtypes = [w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
    api.NtQuerySystemInformation.restype = c.c_long
    buffer, returned = c.create_string_buffer(48), w.ULONG()
    if api.NtQuerySystemInformation(3, buffer, len(buffer), c.byref(returned)) != 0 or returned.value != 48:
        raise Refusal("Native boot identity unavailable")
    return "windows-boot-filetime:" + str(int.from_bytes(buffer.raw[:8], "little", signed=True))


def scope_settings_fingerprint(settings):
    if type(settings) is not dict:
        raise Refusal("Nonsecret settings object required")
    forbidden = ("modelprovider", "gcp", "custommodelsconfig", "custommodels", "vertex",
                 "apikey", "endpoint", "baseurl", "proxy", "auth")

    def check_keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise Refusal("Settings keys must be strings")
                folded = key.casefold().replace("_", "").replace("-", "")
                if any(part in folded for part in forbidden):
                    raise Refusal("Unsupported explicit provider or authentication routing configuration")
                check_keys(item)
        elif isinstance(value, list):
            for item in value:
                check_keys(item)

    try:
        check_keys(settings)
    except RecursionError:
        raise Refusal("Settings nesting exceeds the bounded context contract") from None
    for flag in FALSE_FLAGS:
        if type(settings.get(flag, False)) is not bool or settings.get(flag, False):
            raise Refusal("Unqualified nonsecret policy flag")
    if settings.get("toolPermission") != "strict":
        raise Refusal("Strict policy missing")
    permissions = settings.get("permissions")
    if (type(permissions) is not dict or type(permissions.get("deny")) is not list
            or not all(rule in permissions["deny"] for rule in DENY_RULES)):
        raise Refusal("Six recognized native deny rules required; ignored rules do not count")
    return digest(canonical({"toolPermission": "strict",
                             "recognized_denies": {rule: True for rule in DENY_RULES},
                             "flags": {name: False for name in FALSE_FLAGS},
                             "unsupported_routing_key_presence": "absent throughout settings",
                             "pinned_supported_route": "default authenticated owner AGY profile only"}))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate settings key")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("Nonfinite settings constant")


class DefaultProfileContext:
    """Recheck a caller-attested default profile; never discover another account."""
    def __init__(self, expected: ProfileScope):
        self.expected = expected.validate()
        if expected.configuration_sha256 == "0" * 64:
            raise Refusal("Native context requires a sealed nonsecret configuration fingerprint")
        if expected.routing != DEFAULT_ROUTE:
            raise Refusal("Only the qualified default authenticated route is supported")

    def __call__(self):
        expected = self.expected
        current = identity()
        if (current["host"].casefold() != expected.host.casefold()
                or current["sid"] != expected.sid or current["session"] != expected.session
                or native_boot() != expected.boot):
            raise Refusal("Native host/boot/SID/session changed")
        root = (Path.home() / ".gemini/antigravity-cli").resolve(strict=True)
        if str(root).replace("\\", "/").casefold() != str(Path(expected.profile_root)).replace("\\", "/").casefold():
            raise Refusal("Default authenticated profile changed")
        path = root / "settings.json"  # approved nonsecret configuration only
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise Refusal("Oversized nonsecret settings")
        try:
            settings = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique, parse_constant=_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise Refusal("Malformed nonsecret settings") from None
        pin = scope_settings_fingerprint(settings)
        if expected.configuration_sha256 and expected.configuration_sha256 != pin:
            raise Refusal("Attested profile policy/routing changed")
        return replace(expected, configuration_sha256=pin).validate()
