"""Trusted local child process. This is not a container or security sandbox."""
import json
import sys
import time
from .models import Contract
from .catalog import make_scenario
from .targets import invoke, TARGET_VERSION
from .defense import assess, detector_controls


def execute(contract):
    start = time.monotonic()
    attempts, total_bytes = [], 0
    budget_ok = True
    for category in contract.categories:
        for trial in range(contract.trials):
            if time.monotonic()-start >= contract.wall_seconds or len(attempts) >= contract.max_attempts:
                budget_ok = False
                break
            s = make_scenario(category)
            input_bytes = len((s.prompt+s.context+s.marker).encode())
            if input_bytes > contract.per_attempt_input_bytes or total_bytes + input_bytes + contract.per_attempt_output_bytes > contract.max_total_bytes:
                budget_ok = False
                break
            response = invoke(contract.target, s)
            output_bytes = len(json.dumps({'text':response.text,'tools':response.tools,'decision':response.decision}).encode())
            total_bytes += input_bytes + output_bytes
            if output_bytes > contract.per_attempt_output_bytes:
                budget_ok = False
                break
            v = assess(s, response)
            # Raw prompt, response and marker are intentionally never persisted or sent to parent.
            attempts.append({'category':category, 'trial':trial+1, 'objective':s.objective,
                             'outcome':v.outcome, 'rationale':v.rationale, 'confidence':v.confidence,
                             'severity':s.severity, 'review_status':'PENDING HUMAN REVIEW' if v.outcome in ('BYPASSED','PARTIAL') else 'NOT REQUIRED',
                             'remediation':s.remediation, 'input_bytes':input_bytes,'output_bytes':output_bytes})
        if not budget_ok:
            break
    return {'attempts':attempts, 'budget_ok':budget_ok,
            'detector_controls':detector_controls(), 'target_version':TARGET_VERSION,
            'target_observability':'INSTRUMENTED', 'provider':'bundled synthetic simulator',
            'temperature':'not applicable', 'seed':'not applicable',
            'tokens':'not applicable: no model invoked', 'model_cost_usd':0,
            'total_bytes':total_bytes, 'elapsed_seconds':round(time.monotonic()-start,6)}


def main():
    contract = Contract.model_validate_json(sys.stdin.read(100000))
    print(json.dumps(execute(contract), allow_nan=False))

if __name__ == '__main__':
    main()
