"""Local-only development control plane. Never starts child processes itself."""
import hmac
import json
import os
from dataclasses import dataclass
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .models import Contract
from .store import Store
from .runner import verify_report

@dataclass(frozen=True)
class Principal:
    project: str
    role: str


def create_app(db_path=None, credentials=None, environment=None):
    if (environment or os.getenv('BAYORA_ENV')) != 'development':
        raise RuntimeError('Demo API requires explicit BAYORA_ENV=development; production auth is not implemented')
    configured = credentials if credentials is not None else json.loads(os.getenv('BAYORA_DEV_TOKENS','[]'))
    if not configured or any(set(x)!= {'token','project','role'} or len(x['token'])<32 or x['role'] not in ('tester','auditor') for x in configured):
        raise RuntimeError('Configure project-scoped development tokens of at least 32 characters')
    if len({x['token'] for x in configured}) != len(configured):
        raise RuntimeError('Duplicate tokens are forbidden')
    store = Store(db_path or os.getenv('BAYORA_DB','data/bayora.sqlite3'))
    app = FastAPI(title='BAYORA synthetic red-team demo',version='0.1.0',
                  description='Local development only. External targets disabled. Start a separate queue worker.')
    bearer = HTTPBearer(auto_error=False)

    def principal(auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if auth is not None and auth.scheme.lower()=='bearer':
            for item in configured:
                if hmac.compare_digest(auth.credentials.encode(),item['token'].encode()):
                    return Principal(item['project'],item['role'])
        raise HTTPException(401,'Authentication required')

    def tester(p: Principal = Depends(principal)):
        if p.role != 'tester':
            raise HTTPException(403,'Tester role required')
        return p

    def get_run(run_id,p):
        try:
            return store.get(run_id,p.project)
        except KeyError:
            raise HTTPException(404,'Run not found')

    @app.get('/health')
    def health():
        return {'status':'ok','mode':'synthetic-demo'}

    @app.get('/api/v1/targets')
    def targets(p: Principal = Depends(principal)):
        return {'targets':['demo://safe','demo://vulnerable','demo://ambiguous'],'external_targets_enabled':False}

    @app.post('/api/v1/contracts/validate')
    def validate(contract: Contract,p: Principal = Depends(tester)):
        if contract.project_id != p.project:
            raise HTTPException(403,'Project scope mismatch')
        return {'valid':True,'contract':contract.as_dict()}

    @app.post('/api/v1/test-runs',status_code=202)
    def create_run(contract: Contract,p: Principal = Depends(tester)):
        if contract.project_id != p.project:
            raise HTTPException(403,'Project scope mismatch')
        return {'run_id':store.enqueue(contract),'state':'QUEUED'}

    @app.get('/api/v1/test-runs')
    def runs(p: Principal = Depends(principal)):
        return store.list(p.project)

    @app.get('/api/v1/test-runs/{run_id}')
    def read_run(run_id: str,p: Principal = Depends(principal)):
        return get_run(run_id,p)

    @app.post('/api/v1/test-runs/{run_id}/cancel')
    def cancel(run_id: str,p: Principal = Depends(tester)):
        get_run(run_id,p)
        return store.cancel(run_id,p.project)

    @app.get('/api/v1/test-runs/{run_id}/events')
    def events(run_id: str,p: Principal = Depends(principal)):
        r=get_run(run_id,p)
        return r['result']['evidence'] if r['result'] else []

    @app.get('/api/v1/passports/{run_id}')
    @app.get('/api/v1/reports/{run_id}/export')
    def passport(run_id: str,p: Principal = Depends(principal)):
        result=get_run(run_id,p)['result']
        if result is None:
            raise HTTPException(409,'No report available')
        if not verify_report(result):
            raise HTTPException(409,'Evidence or report projection is inconsistent')
        return result

    @app.post('/api/v1/evidence/{run_id}/verify')
    def verification(run_id: str,p: Principal = Depends(principal)):
        result=get_run(run_id,p)['result']
        return {'consistent':verify_report(result) if result else False,'assurance_level':0}

    return app
