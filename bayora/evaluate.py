"""Small labeled detector regression corpus; not an independent accuracy benchmark."""
import argparse
from collections import Counter
import json
from pathlib import Path
from .catalog import Scenario
from .defense import Observation, assess


def evaluate(cases):
    matrix=Counter();per_category={};errors=[]
    for row in cases:
        scenario=Scenario(row['category'],'Fixture objective','', '',row['marker'],'high','Review fixture')
        predicted=assess(scenario,Observation(**row['response'])).outcome
        matrix[(row['expected'],predicted)]+=1
        item=per_category.setdefault(row['category'],{'correct':0,'total':0})
        item['total']+=1;item['correct']+=int(predicted==row['expected'])
        if predicted!=row['expected']:
            errors.append({'id':row['id'],'expected':row['expected'],'predicted':predicted})
    positive={'BYPASSED','PARTIAL'}
    tp=sum(v for (actual,pred),v in matrix.items() if actual in positive and pred in positive)
    fp=sum(v for (actual,pred),v in matrix.items() if actual not in positive and pred in positive)
    tn=sum(v for (actual,pred),v in matrix.items() if actual not in positive and pred not in positive)
    fn=sum(v for (actual,pred),v in matrix.items() if actual in positive and pred not in positive)
    ratio=lambda n,d: n/d if d else None
    return {'scope':'Authored deterministic fixture regression only; not real-model detection accuracy.',
            'cases':len(cases),'exact_accuracy':ratio(sum(v for (a,p),v in matrix.items() if a==p),len(cases)),
            'positive_class':['BYPASSED','PARTIAL'],'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
            'false_positive_rate':ratio(fp,fp+tn),'false_negative_rate':ratio(fn,fn+tp),
            'inter_reviewer_disagreement':'not measured: independent review required',
            'per_category':per_category,
            'confusion_matrix':[{'expected':a,'predicted':p,'count':v} for (a,p),v in sorted(matrix.items())],
            'errors':errors}


def main():
    p=argparse.ArgumentParser();p.add_argument('dataset');p.add_argument('--out')
    a=p.parse_args();report=evaluate(json.loads(Path(a.dataset).read_text()))
    data=json.dumps(report,indent=2)+'\n'
    if a.out:
        Path(a.out).write_text(data)
    print(data)
    return 1 if report['errors'] else 0

if __name__=='__main__':
    raise SystemExit(main())
