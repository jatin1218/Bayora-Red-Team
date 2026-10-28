import copy
import json
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from bayora.models import Contract, CATEGORIES
from bayora.catalog import make_scenario
from bayora.defense import Observation, assess, detector_controls
from bayora.integrity import validity, canary_result
from bayora.evidence import Chain, digest, verify, redact
from bayora.store import Store
from bayora.runner import run_claimed, verify_report, compare
from bayora.worker import execute

@pytest.mark.parametrize('field,value',[
 ('target','https://example.com'),('target','http://169.254.169.254'),
 ('max_attempts',21),('trials',0),('trials',5),('concurrency',2),
 ('raw_artifacts',True),('max_cost_usd',1),('wall_seconds',0),
 ('categories',[]),('categories',['prompt_injection','prompt_injection']),
 ('categories',['unknown']),('required_checks',[]),('max_attempts',2),
 ('expires_at','2020-01-01T00:00:00+00:00'),('expires_at','2099-01-01T00:00:00'),
 ('max_total_bytes','100000'),('extra_field','bad')])
def test_contract_rejects(field,value):
    d=Contract().as_dict();d[field]=value
    with pytest.raises(ValidationError):
        Contract.from_dict(d)


def test_frozen_contract():
    c=Contract()
    with pytest.raises(ValidationError):
        c.target='demo://vulnerable'

@pytest.mark.parametrize('target,outcome',[('safe','BLOCKED'),('vulnerable','BYPASSED'),('ambiguous','INCONCLUSIVE')])
def test_full_loop(tmp_path,target,outcome):
    store=Store(tmp_path/'db')
    c=Contract(target='demo://'+target)
    rid=store.enqueue(c)
    assert store.claim(rid)==rid
    report=run_claimed(store,rid)
    assert report['outcomes']=={outcome:15}
    assert report['harness_integrity']=='UNVERIFIED'
    assert report['harness_checks']['cleanup']=='PASS'
    assert report['canary']['status']=='NOT TESTED'
    assert verify_report(report)
    assert 'BAYORA_SYNTH_' not in json.dumps(report)
    assert store.get(rid)['state']=='COMPLETED'


def test_validity_all_states():
    required=('isolation','evidence')
    assert validity({'isolation':'PASS','evidence':'PASS'},required)=='VALID'
    assert validity({'isolation':'PASS'},required)=='UNVERIFIED'
    assert validity({'isolation':'UNKNOWN','evidence':'FAIL'},required)=='INVALID'


def test_defense_refusal_is_not_enough():
    s=make_scenario('sensitive_data')
    assert assess(s,Observation('I cannot help')).outcome=='INCONCLUSIVE'
    assert assess(s,Observation('I cannot help: '+s.marker,'blocked')).outcome=='BYPASSED'
    assert assess(s,Observation(s.marker,error='timeout')).outcome=='INCONCLUSIVE'
    assert detector_controls()


def test_tool_observability():
    s=make_scenario('tool_misuse')
    assert assess(s,Observation('blocked','blocked')).outcome=='INCONCLUSIVE'
    obs=Observation('',tools=[{'name':'mock_send_email','authorized':False,'status':'attempted'}],traces_available=True)
    assert assess(s,obs).outcome=='PARTIAL'


def test_canary_requires_controls_and_applicability():
    assert canary_result(applicable=False,positive_control=True,signal=False)['status']=='NOT TESTED'
    assert canary_result(applicable=True,positive_control=False,signal=False)['status']=='UNVERIFIED'
    assert canary_result(applicable=True,positive_control=True,signal=True)['status']=='SIGNAL OBSERVED'
    assert canary_result(applicable=True,positive_control=True,signal=False)['status']=='NO SIGNAL OBSERVED'


def test_redaction_before_hash():
    chain=Chain('run')
    event=chain.add('run_started',{'api_key':'sensitive-value','nested':{'text':'Bearer confidential'},'contract_hash':'abc'})
    assert 'sensitive-value' not in json.dumps(event)
    assert 'confidential' not in json.dumps(event)
    assert event['hash']==digest({k:v for k,v in event.items() if k!='hash'})


def test_chain_tamper_reorder_truncate():
    chain=Chain('run')
    chain.add('run_started',{'contract_hash':'abc'});chain.add('attack_observed',{'outcome':'BYPASSED'});chain.add('run_finished',{})
    manifest=chain.manifest('abc')
    assert verify(chain.events,manifest)
    changed=copy.deepcopy(chain.events);changed[1]['payload']['outcome']='BLOCKED'
    assert not verify(changed,manifest)
    assert not verify(chain.events[:-1],manifest)
    assert not verify(list(reversed(chain.events)),manifest)
    assert not verify([],manifest)


def make_report(tmp_path,target='vulnerable'):
    store=Store(tmp_path/'db')
    rid=store.enqueue(Contract(target='demo://'+target));store.claim(rid)
    return run_claimed(store,rid)


def test_projection_tamper(tmp_path):
    report=make_report(tmp_path)
    for field,value in [('harness_integrity','VALID'),('target_metadata',{}),('metrics',{}),('findings',[])]:
        changed=copy.deepcopy(report);changed[field]=value
        assert not verify_report(changed)


def test_replay(tmp_path):
    baseline=make_report(tmp_path)
    replay=make_report(tmp_path)
    assert compare(baseline,replay)['status']=='REPRODUCED'
    safe=make_report(tmp_path,'safe')
    assert compare(baseline,safe)['status']=='INCONCLUSIVE'
    assert compare(safe,safe)['status']=='INCONCLUSIVE'


def test_queued_cancel_and_scope(tmp_path):
    store=Store(tmp_path/'db')
    rid=store.enqueue(Contract())
    with pytest.raises(KeyError):
        store.cancel(rid,'another-project')
    store.cancel(rid,'demo')
    assert store.claim() is None
    assert store.get(rid)['state']=='CANCELLED'


def test_concurrency_one(tmp_path):
    a,b=Store(tmp_path/'db'),Store(tmp_path/'db')
    r1=a.enqueue(Contract());r2=b.enqueue(Contract())
    assert a.claim()==r1
    assert b.claim() is None
    a.finish(r1,'FAILED',{})
    assert b.claim()==r2


def test_budget_is_invalid(tmp_path):
    store=Store(tmp_path/'db')
    rid=store.enqueue(Contract(max_total_bytes=100))
    store.claim(rid);r=run_claimed(store,rid)
    assert r['harness_integrity']=='INVALID'
    assert r['harness_checks']['budgets']=='FAIL'
    assert r['metrics']['attempts']==0
    assert verify_report(r)


def test_output_cap():
    r=execute(Contract(per_attempt_output_bytes=32))
    assert not r['budget_ok']


def test_expiry_rechecked(tmp_path):
    store=Store(tmp_path/'db');rid=store.enqueue(Contract())
    c=store.get(rid)['contract'];c['expires_at']='2000-01-01T00:00:00+00:00'
    with store.connect() as db:
        db.execute('UPDATE jobs SET contract=? WHERE id=?',(json.dumps(c),rid))
    store.claim(rid);r=run_claimed(store,rid)
    assert r['state']=='FAILED' and r['metrics']['attempts']==0
    assert r['harness_checks']['contract']=='FAIL'


def test_running_cancel(tmp_path,monkeypatch):
    store=Store(tmp_path/'db');rid=store.enqueue(Contract());store.claim(rid)
    store.cancel(rid,'demo')
    r=run_claimed(store,rid)
    assert r['state']=='CANCELLED'
    assert r['harness_checks']['cleanup']=='PASS'
    assert r['harness_integrity']=='UNVERIFIED'


def test_timeout_kills_child(tmp_path,monkeypatch):
    import subprocess,sys
    import bayora.runner as runner
    original=subprocess.Popen
    def slow(*args,**kwargs):
        return original([sys.executable,'-c','import time; time.sleep(10)'],**kwargs)
    monkeypatch.setattr(runner.subprocess,'Popen',slow)
    store=Store(tmp_path/'db');rid=store.enqueue(Contract(wall_seconds=1));store.claim(rid)
    r=run_claimed(store,rid)
    assert r['state']=='TIMED_OUT'
    assert r['harness_checks']['cleanup']=='PASS'
    assert r['harness_integrity']=='INVALID'
