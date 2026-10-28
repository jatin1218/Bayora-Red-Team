import hashlib
import json
import re
from datetime import datetime, timezone

SENSITIVE_KEY = re.compile(r'(secret|password|authorization|token|api.?key)', re.I)

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def redact(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if SENSITIVE_KEY.search(k) else redact(v) for k,v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'BAYORA_SYNTH_[a-f0-9]+', '[SYNTHETIC_MARKER]', value)
        value = re.sub(r'(?i)bearer\s+\S+', 'Bearer [REDACTED]', value)
        return value
    return value

class Chain:
    def __init__(self, run_id):
        self.run_id, self.events = run_id, []

    def add(self, kind, payload):
        event = {'schema_version':'1.0', 'run_id':self.run_id, 'seq':len(self.events),
                 'timestamp':utcnow(), 'kind':kind, 'payload':redact(payload),
                 'previous_hash':self.events[-1]['hash'] if self.events else '0'*64}
        event['hash'] = digest(event)
        self.events.append(event)
        return event

    def manifest(self, contract_hash):
        return {'run_id':self.run_id, 'event_count':len(self.events),
                'root_hash':self.events[-1]['hash'] if self.events else '0'*64,
                'contract_hash':contract_hash, 'assurance_level':0}


def verify(events, manifest):
    """Checks local consistency, including truncation against the local manifest."""
    try:
        if not events or manifest['assurance_level'] != 0 or len(events) != manifest['event_count']:
            return False
        previous = '0'*64
        for seq, event in enumerate(events):
            if set(event) != {'schema_version','run_id','seq','timestamp','kind','payload','previous_hash','hash'}:
                return False
            if event['schema_version'] != '1.0' or event['seq'] != seq or event['run_id'] != manifest['run_id'] or event['previous_hash'] != previous:
                return False
            if digest({k:v for k,v in event.items() if k != 'hash'}) != event['hash']:
                return False
            previous = event['hash']
        return (previous == manifest['root_hash'] and events[0]['kind'] == 'run_started'
                and events[0]['payload']['contract_hash'] == manifest['contract_hash']
                and events[-1]['kind'] == 'run_finished')
    except (KeyError, TypeError, ValueError):
        return False
