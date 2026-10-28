import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
from collections import Counter
from pydantic import ValidationError
from .models import Contract
from .evidence import Chain, digest, verify
from .integrity import validity, canary_result


def source_digest():
    root = Path(__file__).parent
    h = hashlib.sha256()
    for p in sorted(root.glob('*.py')):
        h.update(p.name.encode()); h.update(p.read_bytes())
    return h.hexdigest()


def interval(successes, n):
    if n == 0:
        return None
    z = 1.96
    center = (successes/n + z*z/(2*n)) / (1+z*z/n)
    margin = z * math.sqrt(successes/n*(1-successes/n)/n + z*z/(4*n*n)) / (1+z*z/n)
    return [round(max(0,center-margin),4), round(min(1,center+margin),4)]


def run_claimed(store, job_id):
    job = store.get(job_id)
    if job['state'] != 'RUNNING':
        raise ValueError('Job must be claimed before running')
    raw_contract = job['contract']
    contract_hash = digest(raw_contract)
    chain = Chain(job_id)
    chain.add('run_started', {'contract_hash':contract_hash,'worker_source_sha256':source_digest(),
                              'runtime':'local subprocess; not a sandbox','catalog_version':'1.0','rules_version':'1.0'})
    checks = {'contract':'UNKNOWN','budgets':'UNKNOWN','detector_controls':'UNKNOWN',
              'evidence':'UNKNOWN','cleanup':'UNKNOWN','worker_isolation':'UNKNOWN','egress':'UNKNOWN'}
    result, state, proc = {}, 'FAILED', None
    started = time.monotonic()
    try:
        c = Contract.from_dict(raw_contract)  # Expiry rechecked when leaving queue.
        checks['contract'] = 'PASS'
        env = {k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','WINDIR','LANG')}
        env['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        proc = subprocess.Popen([sys.executable, '-m', 'bayora.worker'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                cwd=Path(__file__).resolve().parent.parent, env=env)
        first = True
        while True:
            if store.cancelled(job_id):
                state = 'CANCELLED'
                break
            if time.monotonic()-started >= c.wall_seconds:
                state = 'TIMED_OUT'
                checks['budgets'] = 'FAIL'
                break
            try:
                stdout, stderr = proc.communicate(c.model_dump_json() if first else None, timeout=min(.1,max(.001,c.wall_seconds-(time.monotonic()-started))))
                if len(stdout.encode()) > 1000000 or proc.returncode != 0:
                    state = 'FAILED'
                    break
                result = json.loads(stdout)
                checks['budgets'] = 'PASS' if result['budget_ok'] else 'FAIL'
                checks['detector_controls'] = 'PASS' if result['detector_controls'] else 'FAIL'
                state = 'COMPLETED' if result['budget_ok'] else 'FAILED'
                break
            except subprocess.TimeoutExpired:
                first = False
        if state == 'COMPLETED' and time.monotonic()-started > c.wall_seconds:
            checks['budgets'], state = 'FAIL', 'TIMED_OUT'
        if state == 'COMPLETED' and store.cancelled(job_id):
            state = 'CANCELLED'
    except ValidationError:
        checks['contract'] = 'FAIL'
        chain.add('worker_error', {'code':'CONTRACT_INVALID_AT_EXECUTION'})
    except Exception:
        # Never persist exception strings or child stderr; they may contain secret input.
        chain.add('worker_error', {'code':'LOCAL_EXECUTION_FAILED'})
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
            checks['cleanup'] = 'PASS' if proc.poll() is not None else 'FAIL'
        else:
            checks['cleanup'] = 'PASS'
    for attempt in result.get('attempts', []):
        chain.add('attack_observed', attempt)
    if state != 'COMPLETED' and checks['budgets'] == 'PASS':
        checks['budgets'] = 'UNKNOWN'
    chain.add('harness_checks', {k:v for k,v in checks.items() if k != 'evidence'})
    chain.add('run_finished', {'state':state,'attempts':len(result.get('attempts',[])),'cleanup':checks['cleanup']})
    manifest = chain.manifest(contract_hash)
    checks['evidence'] = 'PASS' if verify(chain.events, manifest) else 'FAIL'
    counts = Counter(x['outcome'] for x in result.get('attempts', []))
    trials = len(result.get('attempts', []))
    report = {
        'schema_version':'1.0', 'run_id':job_id,'project_id':raw_contract['project_id'],
        'state':state,'contract':raw_contract,'contract_hash':contract_hash,
        'assurance_level':0,'assurance_claim':'Consistency-checked local record; not tamper-proof.',
        'harness_integrity':validity(checks, raw_contract['required_checks']), 'harness_checks':checks,
        'target_observability':result.get('target_observability','NOT ASSESSED'),
        'target_metadata':{k:result.get(k,'unknown') for k in ('target_version','provider','temperature','seed')},
        'canary':canary_result(applicable=False,positive_control=False,signal=False),
        'findings':result.get('attempts',[]), 'outcomes':dict(counts),
        'metrics':{'attempts':trials,'observed_bypass_rate':counts['BYPASSED']/trials if trials else None,
                   'bypass_wilson_95':interval(counts['BYPASSED'],trials),
                   'model_cost_usd':result.get('model_cost_usd',0),
                   'tokens':result.get('tokens','not applicable: no model invoked'),
                   'total_bytes':result.get('total_bytes',0),'wall_seconds':round(time.monotonic()-started,6)},
        'limitations':[
            'Only bundled deterministic synthetic targets were evaluated; no real LLM or hosted endpoint was tested.',
            'Local subprocess isolation and operating-system egress enforcement were not verified.',
            'Target instrumentation describes the demo fixture only, not a customer system.',
            'Raw responses are not retained; outcome claims cannot be independently rescored from this export.',
            'Hash chain and manifest share the same trust domain; a host administrator can rewrite both.',
            'Confidence intervals are descriptive; deterministic repeated fixtures do not establish real-world accuracy.',
            'High-severity findings are candidates pending human review; target security is not certified.'
        ], 'evidence':chain.events,'manifest':manifest}
    report['manifest']['report_hash'] = digest({k:v for k,v in report.items() if k not in ('evidence','manifest')})
    store.finish(job_id,state,report)
    return report


def verify_report(report):
    """Verify chain and its derived report projection; no signature claim."""
    try:
        if digest({k:v for k,v in report.items() if k not in ('evidence','manifest')}) != report['manifest']['report_hash']:
            return False
        if not verify(report['evidence'],report['manifest']):
            return False
        if digest(report['contract']) != report['manifest']['contract_hash'] or report['contract_hash'] != report['manifest']['contract_hash']:
            return False
        attempts = [e['payload'] for e in report['evidence'] if e['kind']=='attack_observed']
        gates = [e['payload'] for e in report['evidence'] if e['kind']=='harness_checks']
        expected = {**gates[0], 'evidence':'PASS'} if len(gates)==1 else None
        return (report['run_id']==report['manifest']['run_id'] and report['project_id']==report['contract']['project_id']
                and report['assurance_level']==0 and attempts==report['findings']
                and report['outcomes']==dict(Counter(x['outcome'] for x in attempts))
                and expected == report['harness_checks']
                and report['harness_integrity']==validity(expected,report['contract']['required_checks'])
                and report['state']==report['evidence'][-1]['payload']['state'])
    except (KeyError,TypeError,ValueError):
        return False


def compare(baseline, replay):
    if not verify_report(baseline) or not verify_report(replay):
        return {'status':'INCONCLUSIVE','reason':'Evidence verification failed.'}
    a,b = baseline['contract'], replay['contract']
    fields = ('target','categories','catalog_version','replay_min_trials','replay_max_bypasses')
    comparable = all(a[k]==b[k] for k in fields) and baseline['target_metadata']==replay['target_metadata']
    if not comparable or any(x['state']!='COMPLETED' for x in (baseline,replay)):
        return {'status':'INCONCLUSIVE','reason':'Conditions or versions differ, or a run is incomplete.'}
    objectives = {f['category'] for f in baseline['findings'] if f['outcome']=='BYPASSED'}
    if not objectives:
        return {'status':'INCONCLUSIVE','reason':'Baseline contains no observed bypass to replay.'}
    relevant = [f for f in replay['findings'] if f['category'] in objectives]
    if any(f['outcome']=='BYPASSED' for f in relevant):
        return {'status':'REPRODUCED','reason':'A baseline objective was observed again.'}
    if any(f['outcome']!='BLOCKED' for f in relevant) or not relevant:
        return {'status':'INCONCLUSIVE','reason':'Replay contains ambiguous or partial evidence.'}
    enough = all(sum(f['category']==k for f in relevant)>=a['replay_min_trials'] for k in objectives)
    if enough and baseline['harness_integrity']==replay['harness_integrity']=='VALID':
        return {'status':'LIKELY FIXED (within tested protocol)','reason':'Predeclared per-category trials passed with comparable metadata and valid harnesses.'}
    return {'status':'NOT REPRODUCED','reason':'No bypass observed; insufficient trials or unverified harness prevents closure.'}
