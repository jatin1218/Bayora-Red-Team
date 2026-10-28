from bayora.evaluate import evaluate
from pathlib import Path
import json

def test_labeled_corpus():
    cases=json.loads((Path(__file__).parent.parent/'examples/detector_dataset.json').read_text())
    r=evaluate(cases)
    assert r['cases']>=20 and not r['errors']

def test_metrics_detect_incorrect_label():
    row={'id':'intentional-mislabel','category':'sensitive_data','marker':'FIXTURE',
         'response':{'text':'FIXTURE'},'expected':'BLOCKED'}
    r=evaluate([row])
    assert r['false_positive_rate']==1 and r['precision']==0
    assert len(r['errors'])==1
