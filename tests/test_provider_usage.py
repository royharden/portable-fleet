"""Provider bridge regressions use real PermitState, never a parallel lease model."""
from dataclasses import replace
import json
import os
from pathlib import Path
import unittest
import uuid
from datetime import datetime, timezone
import threading

from portable_fleet.core import Refusal
from portable_fleet.permit_guard import PermitState
from portable_fleet.provider_usage import FetchReceipt, ProfileScope, ProviderUsageBridge, parse_usage

WALL=1793220000.0
PIN='1111111111111111111111111111111111111111111111111111111111111111'
BINARY='C:/owned/agy.exe'

def uid():return str(uuid.uuid4())

def scope():
    return ProfileScope('operator-attested AGY owner profile','Fixture Owner','fixture contract',1,'fixture-host','native-boot-token','S-1-5-21-test',1,'C:/FleetFixture/profile/.gemini/antigravity-cli','owner-agy-profile:no-api:no-vertex:no-custom-endpoint')

def body():
    groups=[]
    for group,ids in (('Gemini Models',('gemini-weekly','gemini-5h')),('Claude and GPT models',('3p-weekly','3p-5h')),('Gemini 4 Argon',('gemini-argon-wtu-weekly',))):
        groups.append(dict(name=group,buckets=[dict(id=key,name=key,window='5h' if key.endswith('-5h') else 'weekly',remaining_fraction=.8,reset_time='2026-11-04T23:32:44Z')for key in ids]))
    return dict(conversation_id='',status='SUCCESS',response='rounded display deliberately ignored',duration_seconds=0,num_turns=0,usage={k:0 for k in ('input_tokens','output_tokens','thinking_tokens','cache_read_tokens','total_tokens')},command=dict(name='usage',data=dict(description='',groups=groups)))

def raw(value=None):return json.dumps(body()if value is None else value).encode()

def receipt(context=None,**changes):
    return replace(FetchReceipt(uid(),context or scope(),101,134377045292288430,uid(),PIN,(BINARY,'--print','/usage','--output-format','json'),WALL,100.0,WALL+1,101.0,0,True,raw()),**changes)

class StateGuard:
    """Native process boundary omitted explicitly; real state/permit algorithms retained."""
    def __init__(self,root,context):
        self.times=[WALL+2,102.0]
        self.scope=uid()
        self.clock=lambda:tuple(self.times)
        self.state=PermitState(root,self.scope,context.logical_account,*self.clock())
        self.stop_calls=[]
    def receive(self,command):
        try:
            ack=self.state.accept(command,*self.clock())
            return dict(state='active',**ack)
        except (ValueError,OSError)as exc:
            return self.stop(str(exc))
    def stop(self,reason,**_kwargs):
        self.stop_calls.append(reason)
        self.state.hold(reason,*self.clock())
        return dict(state='stopped')
    def deadline_wait_seconds(self):
        self.state.check(*self.clock())
        return self.state.permit['expires_mono']-self.times[1] if self.state.permit else 5
    def _old_lease_remaining(self):
        permit=self.state.permit
        return None if permit is None else min(permit['expires_wall']-self.times[0],permit['expires_mono']-self.times[1])

class ProviderUsageTests(unittest.TestCase):
    def setUp(self):
        root=os.environ.get('PF_PROVIDER_TEST_ROOT')
        if not root:self.skipTest('Set PF_PROVIDER_TEST_ROOT to owned retained output')
        self.root=Path(root)/('case-'+uid())
        self.context=scope()
        self.guard=StateGuard(self.root,self.context)
        self.current=self.context
        self.bridge=ProviderUsageBridge(self.guard,self.context,BINARY,PIN,lambda:self.current)
    def accept(self,**changes):return self.bridge.accept_fetch(receipt(self.context,**changes))
    def test_conservative_fraction_and_refresh_start_age(self):
        result=self.accept()
        self.assertEqual(result['acquisition']['percent_left'],80)
        self.assertEqual(result['acquisition']['backend_observed_at'],None)
        self.assertEqual(self.guard.state.permit['observation_deadline'],WALL+300)
        self.assertEqual(self.guard.state.permit['expires_mono'],192)
        self.assertEqual(result['acquisition']['deadline_mono'],400)
    def test_heartbeats_do_not_reage_last_fetch_and_stale_closes(self):
        self.accept()
        for offset in range(30,300,30):
            self.guard.times[:]=[WALL+offset,100+offset]
            self.bridge.renew()
            self.assertLessEqual(self.guard.state.permit['expires_mono'],400)
            self.assertEqual(self.guard.state.permit['observation_deadline'],WALL+300)
        self.guard.times[:]=[WALL+300,400]
        with self.assertRaises(Refusal):self.bridge.renew()
        self.assertTrue(self.guard.state.closed)
    def test_identical_values_fresh_process_accepted_not_value_replay(self):
        first=receipt(self.context)
        self.bridge.accept_fetch(first)
        self.guard.times[:]=[WALL+30,130]
        result=self.bridge.accept_fetch(replace(first,operation=uid(),job_scope=uid(),pid=102,creation_filetime=first.creation_filetime+1,started_wall=WALL+29,started_mono=129,ended_wall=WALL+30,ended_mono=130))
        self.assertEqual(result['acquisition']['sequence'],2)
        self.assertEqual(result['acquisition']['deadline_mono'],429)
    def test_saved_receipt_replay_closes(self):
        first=receipt(self.context)
        self.bridge.accept_fetch(first)
        with self.assertRaises(Refusal):self.bridge.accept_fetch(first)
        self.assertTrue(self.guard.state.closed)
    def test_new_operation_cannot_reuse_process_identity(self):
        first=receipt(self.context)
        self.bridge.accept_fetch(first)
        with self.assertRaises(Refusal):self.bridge.accept_fetch(replace(first,operation=uid(),job_scope=uid()))
        self.assertTrue(self.guard.state.closed)
    def test_context_changes_close_without_new_receipt(self):
        for field,value in (('logical_account','other'),('host','other'),('boot','newboot'),('sid','other'),('session',0),('profile_root','C:/other'),('generation',2),('routing','API'),('attestation_ref','new'),('configuration_sha256','1'*64)):
            with self.subTest(field=field):
                guard=StateGuard(self.root/field,self.context)
                current=[self.context]
                bridge=ProviderUsageBridge(guard,self.context,BINARY,PIN,lambda:current[0])
                bridge.accept_fetch(receipt(self.context))
                current[0]=replace(self.context,**{field:value})
                with self.assertRaises(Refusal):bridge.renew()
                self.assertTrue(guard.state.closed)
    def test_failed_or_unpinned_acquisition_closes(self):
        for field,value in (('exit_code',1),('exit_code',False),('owned_stop_confirmed',False),('binary_sha256','0'*64),('argv',(BINARY,'--print','hello','--output-format','json')),('pid',True),('creation_filetime',0),('scope',replace(self.context,generation=2))):
            with self.subTest(field=field):
                guard=StateGuard(self.root/(field+uid()),self.context)
                bridge=ProviderUsageBridge(guard,self.context,BINARY,PIN,lambda:self.context)
                with self.assertRaises(Refusal):bridge.accept_fetch(receipt(self.context,**{field:value}))
                self.assertTrue(guard.state.closed)
    def test_acquisition_latency_and_clock_discontinuities_close(self):
        for index,changes in enumerate((dict(started_mono=0),dict(started_wall=WALL+5),dict(ended_mono=121),dict(started_wall=WALL-10),dict(started_mono=float('nan')))):
            guard=StateGuard(self.root/str(index),self.context)
            bridge=ProviderUsageBridge(guard,self.context,BINARY,PIN,lambda:self.context)
            with self.assertRaises(Refusal):bridge.accept_fetch(receipt(self.context,**changes))
            self.assertTrue(guard.state.closed)
    def test_zero_and_reset_change_use_existing_supervisor_close(self):
        for kind in ('zero','reset','increase'):
            guard=StateGuard(self.root/kind,self.context)
            bridge=ProviderUsageBridge(guard,self.context,BINARY,PIN,lambda:self.context)
            bridge.accept_fetch(receipt(self.context))
            guard.times[:]=[WALL+10,110]
            value=body()
            bucket=value['command']['data']['groups'][0]['buckets'][0]
            if kind=='zero':bucket['remaining_fraction']=0
            elif kind=='reset':bucket['reset_time']='2026-11-05T23:32:44Z'
            else:
                for item in value['command']['data']['groups'][0]['buckets']:item['remaining_fraction']=.9
            with self.assertRaises(Refusal):bridge.accept_fetch(receipt(self.context,pid=102,started_wall=WALL+9,started_mono=109,ended_wall=WALL+10,ended_mono=110,raw=raw(value)))
            self.assertTrue(guard.state.closed)
    def test_error_json_and_parse_failure_stop_not_previous_success(self):
        self.accept()
        with self.assertRaises(Refusal):self.bridge.accept_fetch(receipt(self.context,pid=102,raw=b'{"status":"ERROR"}'))
        self.assertTrue(self.guard.state.closed)
    def test_source_loss_closes_and_restart_refused(self):
        self.accept()
        with self.assertRaises(Refusal):self.bridge.source_failed('controlled source loss')
        with self.assertRaises(Refusal):self.bridge.renew()
        with self.assertRaises(Refusal):ProviderUsageBridge(self.guard,self.context,BINARY,PIN,lambda:self.context)
        with self.assertRaises(Refusal):PermitState(self.root,uid(),self.context.logical_account,*self.guard.clock())
    def test_supervisor_loss_lease_remains_at_most_ninety_seconds(self):
        self.accept()
        self.guard.times[:]=[WALL+92,192]
        with self.assertRaises(Refusal):self.guard.deadline_wait_seconds()
        self.assertTrue(self.guard.state.closed)
    def test_parser_strictness_missing_duplicate_nonfinite_boolean_fraction(self):
        cases=[]
        for value in (float('nan'),float('inf'),True,-.1,1.1):
            data=body();data['command']['data']['groups'][0]['buckets'][0]['remaining_fraction']=value;cases.append(raw(data))
        data=body();data['command']['data']['groups'][0]['buckets'].pop();cases.append(raw(data))
        data=body();data['command']['data']['groups'].append(data['command']['data']['groups'][0]);cases.append(raw(data))
        data=body();data['command']['data']['groups'][0]['buckets'][0]['reset_time']='tomorrow';cases.append(raw(data))
        cases.extend((b'\xff',b'{"status":"SUCCESS","status":"ERROR"}',raw().replace(b'"num_turns": 0',b'"num_turns": false')))
        for value in cases:
            with self.subTest(raw=value[:90]),self.assertRaises(Refusal):parse_usage(value,WALL)
    def test_fraction_uses_minimum_relevant_bucket_not_rounding(self):
        data=body();data['command']['data']['groups'][0]['buckets'][0]['remaining_fraction']=.07001
        self.assertAlmostEqual(parse_usage(raw(data),WALL)['percent_left'],7.001)
    def test_deep_nested_json_after_success_closes_and_stops(self):
        self.accept()
        nested=b'['*2000+b'0'+b']'*2000
        with self.assertRaises(Refusal):self.bridge.accept_fetch(receipt(self.context,pid=102,raw=nested))
        self.assertTrue(self.guard.state.closed)
        self.assertTrue(self.guard.stop_calls)
    def test_known_reset_caps_wait_and_refuses_renewal(self):
        value=body()
        value['command']['data']['groups'][0]['buckets'][0]['reset_time']=datetime.fromtimestamp(WALL+60,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.accept(raw=raw(value))
        self.assertEqual(self.bridge.deadline_wait_seconds(),58)
        self.guard.times[:]=[WALL+60,160]
        with self.assertRaises(Refusal):self.bridge.renew()
        self.assertTrue(self.guard.state.closed)
    def test_reset_deadline_method_stops_without_a_renewal(self):
        value=body()
        value['command']['data']['groups'][0]['buckets'][0]['reset_time']=datetime.fromtimestamp(WALL+60,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.accept(raw=raw(value))
        self.guard.times[:]=[WALL+60,160]
        with self.assertRaises(Refusal):self.bridge.deadline_wait_seconds()
        self.assertTrue(self.guard.state.closed)
    def test_blocked_context_reader_cannot_delay_stop_or_late_renewal(self):
        self.accept()
        entered,release,finished=threading.Event(),threading.Event(),threading.Event()
        def blocked():
            entered.set()
            try:
                if not release.wait(10):raise OSError('test context reader never released')
                return self.context
            finally:finished.set()
        self.bridge.current_scope=blocked
        try:
            with self.assertRaises(Refusal):self.bridge.renew()
            self.assertTrue(entered.is_set())
            self.assertTrue(self.guard.state.closed)
            self.assertTrue(self.guard.stop_calls)
            self.assertFalse(finished.is_set())
            self.assertTrue(self.bridge.context_worker.status()['storage_pending'])
        finally:release.set()
        self.assertTrue(finished.wait(2))
        with self.assertRaises(Refusal):self.bridge.renew()

if __name__=='__main__':unittest.main()
