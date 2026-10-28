import argparse
import json
from pathlib import Path
import sys
import time
from .models import Contract
from .store import Store
from .runner import run_claimed, verify_report, compare
from .reporting import export


def main(argv=None):
    parser=argparse.ArgumentParser(description='BAYORA synthetic red-team prototype')
    parser.add_argument('--db',default='data/bayora.sqlite3')
    sub=parser.add_subparsers(dest='command',required=True)
    demo=sub.add_parser('demo',help='Run the bundled target in an ephemeral local subprocess')
    demo.add_argument('--target',choices=['safe','vulnerable','ambiguous'],default='safe')
    demo.add_argument('--trials',type=int,default=3)
    demo.add_argument('--out',default='output/latest')
    contract=sub.add_parser('contract',help='Print a fresh sample contract')
    contract.add_argument('--target',choices=['safe','vulnerable','ambiguous'],default='safe')
    run=sub.add_parser('run',help='Execute a JSON contract')
    run.add_argument('contract');run.add_argument('--out',default='output/latest')
    worker=sub.add_parser('worker',help='Service the local database queue, one run at a time')
    worker.add_argument('--once',action='store_true')
    check=sub.add_parser('verify');check.add_argument('report')
    replay=sub.add_parser('compare');replay.add_argument('baseline');replay.add_argument('replay')
    recover=sub.add_parser('recover',help='Mark abandoned RUNNING rows failed after stopping all workers')
    recover.add_argument('--workers-stopped',action='store_true',required=True)
    args=parser.parse_args(argv)
    if args.command=='contract':
        print(Contract(target='demo://'+args.target).model_dump_json(indent=2));return 0
    if args.command=='verify':
        ok=verify_report(json.loads(Path(args.report).read_text()))
        print(json.dumps({'consistent':ok,'assurance_level':0}));return 0 if ok else 1
    if args.command=='compare':
        print(json.dumps(compare(*[json.loads(Path(p).read_text()) for p in (args.baseline,args.replay)]),indent=2));return 0
    store=Store(args.db)
    if args.command=='recover':
        print(json.dumps({'abandoned_runs_failed':store.recover()}));return 0
    if args.command=='worker':
        try:
            while True:
                job_id=store.claim()
                if job_id:
                    report=run_claimed(store,job_id)
                    print(json.dumps({'run_id':job_id,'state':report['state']}),flush=True)
                elif args.once:
                    return 0
                else:
                    time.sleep(.25)
                if args.once:
                    return 0
        except KeyboardInterrupt:
            return 130
    c=Contract(target='demo://'+args.target,trials=args.trials) if args.command=='demo' else Contract.model_validate_json(Path(args.contract).read_text())
    job_id=store.enqueue(c)
    if store.claim(job_id) is None:
        print(json.dumps({'run_id':job_id,'state':'QUEUED','message':'Another run is active; process with worker command.'}));return 2
    report=run_claimed(store,job_id)
    export(report,args.out)
    print(json.dumps({'run_id':job_id,'state':report['state'],'harness_integrity':report['harness_integrity'],
                      'outcomes':report['outcomes'],'report':str(Path(args.out)/'report.html')},indent=2))
    return 0 if report['state']=='COMPLETED' else 1

if __name__=='__main__':
    sys.exit(main())
