"""Bounded AGY /usage-to-GuardedFamily bridge for an operator-attested profile.

The trusted local coordinator supplies fresh native acquisition evidence, not saved
JSON. Logical profile identity is operator-attested, never provider-issued. Age is
client refresh-start age under the pinned CLI's documented live-refresh contract;
there is no claim of a provider timestamp or hostile same-user isolation.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
import ntpath
import re
import uuid
import time

from .core import Refusal, canonical, digest, identifier
from .journal_worker import BoundedJournal


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def windows_path(value):
    if not text(value) or not re.match(r"^[A-Za-z]:[\\/]", value) or '..' in value.replace('\\', '/').split('/'):
        raise Refusal('Explicit canonical Windows path required')
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True)
class ProfileScope:
    logical_account: str
    attested_by: str
    attestation_ref: str
    generation: int
    host: str
    boot: str
    sid: str
    session: int
    profile_root: str
    routing: str
    model: str = 'gemini-3.8-flash-low'
    configuration_sha256: str = '0' * 64  # synthetic callers must label their scope accordingly

    def validate(self):
        if any(not text(getattr(self, name)) for name in ('logical_account', 'attested_by', 'attestation_ref', 'host', 'boot', 'sid')):
            raise Refusal('Explicit operator-attested logical profile required')
        if type(self.generation) is not int or self.generation < 1 or type(self.session) is not int or self.session != 1:
            raise Refusal('Positive attestation generation and native desktop session1 required')
        windows_path(self.profile_root)
        if not isinstance(self.configuration_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', self.configuration_sha256):
            raise Refusal('Explicit nonsecret configuration fingerprint required')
        if self.routing != 'owner-agy-profile:no-api:no-vertex:no-custom-endpoint' or self.model != 'gemini-3.8-flash-low':
            raise Refusal('Unqualified routing/model mapping')
        return self


@dataclass(frozen=True)
class FetchReceipt:
    """Trusted coordinator boundary; raw JSON alone is never acquisition evidence.

    Coordinator must retain exact child/native job handles through acquisition,
    collect actual SID/session/boot and nonsecret profile/routing configuration,
    pin the binary, record start before resume and confirm owned stop. External
    login switches/unmanaged seats/same-user compromise are explicitly excluded.
    """
    operation: str
    scope: ProfileScope
    pid: int
    creation_filetime: int
    job_scope: str
    binary_sha256: str
    argv: tuple
    started_wall: float
    started_mono: float
    ended_wall: float
    ended_mono: float
    exit_code: int
    owned_stop_confirmed: bool
    raw: bytes


BUCKETS = {
    'Gemini Models': {'gemini-weekly', 'gemini-5h'},
    'Claude and GPT models': {'3p-weekly', '3p-5h'},
    'Gemini 4 Argon': {'gemini-argon-wtu-weekly'},
}
USAGE = {'input_tokens', 'output_tokens', 'thinking_tokens', 'cache_read_tokens', 'total_tokens'}


def parse_usage(raw, earliest_wall):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refusal('Duplicate usage JSON key')
            value[key] = item
        return value

    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise Refusal('Bounded raw usage bytes required')
    try:
        body = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
        if (type(body) is not dict or set(body) != {'conversation_id', 'status', 'response', 'duration_seconds', 'num_turns', 'usage', 'command'}
                or body['status'] != 'SUCCESS' or body['conversation_id'] != ''
                or type(body['num_turns']) is not int or body['num_turns'] != 0
                or not number(body['duration_seconds']) or body['duration_seconds'] < 0
                or not isinstance(body['response'], str) or type(body['usage']) is not dict or set(body['usage']) != USAGE
                or any(type(v) is not int or v != 0 for v in body['usage'].values())
                or type(body['command']) is not dict or set(body['command']) != {'name', 'data'} or body['command']['name'] != 'usage'):
            raise Refusal('Invalid/failed/nonbuiltin usage envelope')
        data = body['command']['data']
        if type(data) is not dict or set(data) != {'description', 'groups'} or not isinstance(data['description'], str) or type(data['groups']) is not list or len(data['groups']) != len(BUCKETS):
            raise Refusal('Unknown usage data schema')
        values, resets, groups = {}, {}, set()
        for group in data['groups']:
            if type(group) is not dict or not {'name', 'buckets'} <= set(group) <= {'name', 'description', 'buckets'}:
                raise Refusal('Unknown quota group schema')
            name = group['name']
            if name not in BUCKETS or name in groups or type(group['buckets']) is not list:
                raise Refusal('Missing/duplicate/unknown quota group')
            groups.add(name)
            local = set()
            for bucket in group['buckets']:
                if type(bucket) is not dict or not {'id', 'name', 'window', 'remaining_fraction', 'reset_time'} <= set(bucket) <= {'id', 'name', 'description', 'window', 'remaining_fraction', 'reset_time'}:
                    raise Refusal('Unknown quota bucket schema')
                key, value, reset = bucket['id'], bucket['remaining_fraction'], bucket['reset_time']
                if key not in BUCKETS[name] or key in local or not number(value) or not 0 <= value <= 1:
                    raise Refusal('Invalid/missing quota fraction or bucket')
                if bucket['window'] != ('5h' if key.endswith('-5h') else 'weekly') or not text(bucket['name']):
                    raise Refusal('Unknown bucket window')
                if not isinstance(reset, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', reset):
                    raise Refusal('Explicit UTC reset_time required')
                epoch = datetime.strptime(reset, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
                if epoch <= earliest_wall:
                    raise Refusal('Elapsed reset window')
                local.add(key)
                values[key], resets[key] = value, reset
            if local != BUCKETS[name]:
                raise Refusal('Incomplete quota buckets')
        return {'percent_left': 100 * min(values['gemini-weekly'], values['gemini-5h']),
                'reset': digest(canonical(resets)), 'buckets': values, 'reset_times': resets,
                'raw_sha256': digest(raw), 'backend_observed_at': None}
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise Refusal('Usage parse/schema failure: ' + str(exc)) from exc


class ProviderUsageBridge:
    """Single-owner bridge; existing GuardedFamily owns leases, journaling and stop.

    Constructor/restart never consumes saved evidence. Coordinator must keep its
    guard owner alive, service its existing finite permit deadline and call stop
    on source failure. Heartbeats renew the lease, never the acquisition age.
    """
    def __init__(self, guard, scope, binary, binary_sha256, current_scope):
        if getattr(guard, '_provider_usage_claimed', False) or guard.state.closed or guard.state.permit is not None:
            raise Refusal('Guard already claimed/active/closed; source restart is not admission')
        self.guard, self.scope = guard, scope.validate()
        self.binary, self.binary_sha256 = windows_path(binary), binary_sha256
        if not re.fullmatch(r'[a-f0-9]{64}', binary_sha256) or not callable(current_scope):
            raise Refusal('Explicit pinned acquisition source required')
        if guard.state.account != scope.logical_account:
            raise Refusal('Guard/logical profile account mismatch')
        self.current_scope = current_scope
        self._context_result = None
        def acquire_context(_path, ticket):
            value = self.current_scope()
            self._context_result = (ticket, value)
        self.context_worker = BoundedJournal(acquire_context, timeout=1.0, remaining=guard._old_lease_remaining)
        guard._provider_usage_claimed = True
        self.operations, self.identities, self.jobs = set(), set(), set()
        self.sequence, self.last, self.observation, self.closed = 0, None, None, False
        self.reset_wall = self.reset_mono = None

    def _fail(self, reason, *, event_started_mono=None):
        self.closed = True
        self.context_worker.close()  # never join a blocked scope/configuration reader
        self.guard.stop('Provider source closed: ' + str(reason), event_started_mono=event_started_mono)
        raise Refusal(str(reason))

    def _context(self):
        if self.closed or self.guard.state.closed:
            raise Refusal('Closed source/guard; explicit new generation and new guard required')
        started = time.monotonic()
        try:
            ticket = str(uuid.uuid4())
            self.context_worker.write(None, ticket)
            if self._context_result is None or self._context_result[0] != ticket:
                raise Refusal('Missing/mismatched bounded context response')
            context = self._context_result[1]
            if type(context) is not ProfileScope or context.validate() != self.scope:
                raise Refusal('Profile/routing/native scope/generation changed')
        except (Refusal, OSError, ValueError, TypeError, RecursionError) as exc:
            self._fail(exc, event_started_mono=started)

    def _time(self, start_wall, start_mono, end_wall, end_mono):
        wall, mono = self.guard.clock()
        if not all(number(x) for x in (start_wall, start_mono, end_wall, end_mono, wall, mono)):
            raise Refusal('Invalid source clocks')
        if not 0 < start_wall <= end_wall <= wall or not 0 <= start_mono <= end_mono <= mono:
            raise Refusal('Backwards/future source clocks')
        if end_mono-start_mono >= 20 or mono-start_mono >= 300 or abs((end_wall-start_wall)-(end_mono-start_mono)) > 2 or abs((wall-start_wall)-(mono-start_mono)) > 2:
            raise Refusal('Stale/stalled acquisition or clock discontinuity')
        # Existing Supervisor consumes wall-shaped numbers. Project the original
        # monotonic age conservatively; this is a client origin, not backend time.
        return min(start_wall, wall-(mono-start_mono))

    def accept_fetch(self, receipt):
        self._context()
        try:
            if type(receipt) is not FetchReceipt or receipt.scope != self.scope:
                raise Refusal('Wrong acquisition/profile scope')
            identifier(receipt.operation)
            identifier(receipt.job_scope)
            if receipt.operation in self.operations or receipt.job_scope in self.jobs or (receipt.pid, receipt.creation_filetime) in self.identities:
                raise Refusal('Acquisition operation/process/job replay')
            if (type(receipt.pid) is not int or receipt.pid <= 0 or type(receipt.creation_filetime) is not int or receipt.creation_filetime <= 0
                    or receipt.binary_sha256 != self.binary_sha256 or type(receipt.argv) is not tuple or len(receipt.argv) != 5
                    or windows_path(receipt.argv[0]) != self.binary or receipt.argv[1:] != ('--print', '/usage', '--output-format', 'json')
                    or receipt.owned_stop_confirmed is not True or type(receipt.exit_code) is not int or receipt.exit_code != 0):
                raise Refusal('Unpinned/failed/nonliteral acquisition')
            origin = self._time(receipt.started_wall, receipt.started_mono, receipt.ended_wall, receipt.ended_mono)
            if self.last and receipt.started_mono <= self.last.started_mono:
                raise Refusal('Reordered acquisition start')
            parsed = parse_usage(receipt.raw, self.guard.clock()[0])
            reset_wall = min(datetime.strptime(parsed['reset_times'][key], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
                             for key in ('gemini-weekly', 'gemini-5h'))
            now_wall, now_mono = self.guard.clock()
            reset_mono = now_mono + reset_wall - now_wall
            if reset_mono <= now_mono:
                raise Refusal('Relevant quota reset boundary reached')
            self.sequence += 1
            observation = dict(account=self.scope.logical_account, sequence=self.sequence, observed=origin,
                               percent_left=parsed['percent_left'], reset=parsed['reset'])
            response = self.guard.receive(dict(schema=1, operation=receipt.operation, scope=self.guard.scope, kind='receipt', observation=observation))
            if response.get('state') != 'active':
                raise Refusal('Guard refused observation: ' + str(response))
            self.operations.add(receipt.operation)
            self.jobs.add(receipt.job_scope)
            self.identities.add((receipt.pid, receipt.creation_filetime))
            self.last, self.observation = receipt, observation
            self.reset_wall, self.reset_mono = reset_wall, reset_mono
            return {'guard': response, 'acquisition': {'operation': receipt.operation, 'client_refresh_started_mono': receipt.started_mono,
                    'client_refresh_started_wall': receipt.started_wall, 'guard_client_age_origin_wall': origin,
                    'deadline_mono': receipt.started_mono+300, 'backend_observed_at': None,
                    'quota_reset_deadline_mono': reset_mono,
                    'logical_profile': asdict(self.scope), 'sequence': self.sequence, **parsed}}
        except (Refusal, OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
            self._fail(exc)

    def renew(self):
        self._context()
        if self.last is None:
            self._fail('No accepted acquisition')
        try:
            self._time(self.last.started_wall, self.last.started_mono, self.last.ended_wall, self.last.ended_mono)
            wall, mono = self.guard.clock()
            if wall >= self.reset_wall or mono >= self.reset_mono:
                raise Refusal('Relevant quota reset boundary reached; explicit new generation required')
            response = self.guard.receive(dict(schema=1, operation=str(uuid.uuid4()), scope=self.guard.scope, kind='receipt', observation=dict(self.observation)))
            if response.get('state') != 'active':
                raise Refusal('Guard refused renewal')
            return response
        except (Refusal, OSError, ValueError, TypeError, RecursionError) as exc:
            self._fail(exc)

    def source_failed(self, reason):
        self._fail(reason)

    def close(self):
        self.closed = True
        self.context_worker.close()  # intentionally no join on untrusted/pending I/O
        return self.guard.stop('Provider bridge owner closed')

    def deadline_wait_seconds(self):
        self._context()
        try:
            remaining = self.guard.deadline_wait_seconds()
            if self.last:
                wall, mono = self.guard.clock()
                remaining = min(remaining, self.last.started_mono+300-mono, self.reset_mono-mono, self.reset_wall-wall)
            if remaining <= 0:
                raise Refusal('Source/permit/reset deadline reached')
            return remaining
        except (Refusal, OSError, ValueError, TypeError, RecursionError) as exc:
            self._fail(exc)
