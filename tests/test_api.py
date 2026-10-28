import pytest
from fastapi.testclient import TestClient
from bayora.api import create_app
from bayora.models import Contract
from bayora.store import Store
from bayora.runner import run_claimed

TOKENS=[{'token':'a'*40,'project':'demo','role':'tester'},
        {'token':'b'*40,'project':'other','role':'tester'},
        {'token':'c'*40,'project':'demo','role':'auditor'}]

@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path/'db',TOKENS,'development'))

def auth(letter='a'):
    return {'Authorization':'Bearer '+letter*40}


def test_fail_closed(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(tmp_path/'db',TOKENS,'production')
    with pytest.raises(RuntimeError):
        create_app(tmp_path/'db',[], 'development')


def test_auth_and_roles(client):
    assert client.get('/health').status_code==200
    assert client.get('/api/v1/test-runs').status_code==401
    assert client.post('/api/v1/test-runs',headers=auth('c'),json=Contract().as_dict()).status_code==403
    assert client.post('/api/v1/test-runs',headers=auth('b'),json=Contract().as_dict()).status_code==403
    assert client.get('/api/v1/test-runs',headers=auth('c')).status_code==200


def test_queue_and_project_isolation(client):
    r=client.post('/api/v1/test-runs',headers=auth(),json=Contract().as_dict())
    assert r.status_code==202,r.text
    rid=r.json()['run_id']
    assert client.get('/api/v1/test-runs',headers=auth('b')).json()==[]
    paths=[f'/api/v1/test-runs/{rid}',f'/api/v1/test-runs/{rid}/events',f'/api/v1/passports/{rid}',f'/api/v1/reports/{rid}/export']
    for path in paths:
        assert client.get(path,headers=auth('b')).status_code==404
    assert client.post(f'/api/v1/test-runs/{rid}/cancel',headers=auth('b')).status_code==404
    assert client.post(f'/api/v1/evidence/{rid}/verify',headers=auth('b')).status_code==404
    assert client.post(f'/api/v1/test-runs/{rid}/cancel',headers=auth()).json()['state']=='CANCELLED'


def test_export_and_verify(tmp_path):
    app=create_app(tmp_path/'db',TOKENS,'development');client=TestClient(app)
    rid=client.post('/api/v1/test-runs',headers=auth(),json=Contract().as_dict()).json()['run_id']
    store=Store(tmp_path/'db');store.claim(rid);run_claimed(store,rid)
    assert client.post(f'/api/v1/evidence/{rid}/verify',headers=auth('c')).json()['consistent']
    r=client.get(f'/api/v1/passports/{rid}',headers=auth('c'))
    assert r.status_code==200 and r.json()['harness_integrity']=='UNVERIFIED'


def test_external_target_rejected(client):
    c=Contract().as_dict();c['target']='https://example.com'
    assert client.post('/api/v1/test-runs',headers=auth(),json=c).status_code==422
