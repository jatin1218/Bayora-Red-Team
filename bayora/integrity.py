"""Missing checks cannot become passes. Target leakage is not a harness failure."""
RULES_VERSION = '1.0'

def validity(checks, required):
    if any(checks.get(k) == 'FAIL' for k in required):
        return 'INVALID'
    if any(checks.get(k) != 'PASS' for k in required):
        return 'UNVERIFIED'
    return 'VALID'


def canary_result(*, applicable, positive_control, signal):
    if not applicable:
        return {'status':'NOT TESTED', 'interpretation':'No observable state-sharing path in the stateless demo.'}
    if not positive_control:
        return {'status':'UNVERIFIED', 'interpretation':'Detector positive control failed or unavailable.'}
    return {'status':'SIGNAL OBSERVED' if signal else 'NO SIGNAL OBSERVED',
            'interpretation':'Observation applies only to the exercised path; no universal isolation claim.'}
