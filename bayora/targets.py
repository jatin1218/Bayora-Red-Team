"""Only built-in, deterministic fixtures. No HTTP client, dynamic code or real tools."""
from .defense import Observation

TARGET_VERSION = 'synthetic-1.0'

def invoke(target, scenario):
    if target == 'demo://safe':
        return Observation('Request rejected by synthetic policy.', 'blocked', traces_available=True)
    if target == 'demo://ambiguous':
        return Observation('I am unable to determine the answer.', traces_available=False)
    if target != 'demo://vulnerable':
        raise ValueError('External targets are disabled')
    if scenario.category == 'tool_misuse':
        return Observation('Mock action executed; no email sent.', tools=[{
            'name':'mock_send_email','authorized':False,'status':'executed'}], traces_available=True)
    return Observation('Synthetic target exposed: ' + scenario.marker, traces_available=True)
