import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.main import Settings, create_app

KEY = 'test-only-signing-key-with-at-least-32-bytes'
CFG = Settings(allow_local=True, signing_key=KEY, google_client_id='google-client')
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)

class GoogleKeys:
    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=PRIVATE.public_key())

@pytest.fixture
def client():
    return TestClient(create_app(CFG, GoogleKeys()))

def google_token(**overrides):
    now = int(time.time())
    claims = dict(sub='google-user', iss='https://accounts.google.com', aud='google-client', iat=now, exp=now+300)
    claims.update(overrides)
    return jwt.encode(claims, PRIVATE, algorithm='RS256')

def access_token(**overrides):
    now = int(time.time())
    claims = dict(sub='local:demo', iss=CFG.issuer, aud=CFG.audience, iat=now, exp=now+300, token_use='access', scope='demo:read')
    claims.update(overrides)
    return jwt.encode(claims, KEY, algorithm='HS256')

def test_local_flow(client):
    assert client.get('/').status_code == 200
    assert client.get('/healthz').json() == {'status': 'ok'}
    assert client.get('/api/session').json()['local_login_allowed']
    login = client.post('/api/login', json={'username':'demo','password':'demo'})
    assert login.status_code == 200
    token = client.post('/api/token', json={'id_token':login.json()['id_token']})
    assert token.status_code == 200
    response = client.get('/api/resource', headers={'Authorization':'Bearer '+token.json()['access_token']})
    assert response.status_code == 200
    assert response.json()['message'] == '認可に成功しました'
    assert response.headers['cache-control'] == 'no-store'

@pytest.mark.parametrize('overrides', [{}, {'iss':'accounts.google.com'}])
def test_google_flow(client, overrides):
    headers = {CFG.id_header:google_token(**overrides)}
    assert client.get('/api/session', headers=headers).json()['authenticated']
    token = client.post('/api/token', json={}, headers=headers)
    assert token.status_code == 200
    r = client.get('/api/resource', headers={'Authorization':'Bearer '+token.json()['access_token']})
    assert r.json()['user'] == 'google:google-user'

@pytest.mark.parametrize('overrides', [{'aud':'other'}, {'iss':'evil'}, {'exp':0}])
def test_google_invalid(client, overrides):
    headers = {CFG.id_header:google_token(**overrides)}
    assert client.post('/api/token', json={}, headers=headers).status_code == 401

@pytest.mark.parametrize('token', ['invalid', ''])
def test_no_fallback_for_bad_proxy_header(client, token):
    headers = {CFG.id_header:token}
    assert client.get('/api/session', headers=headers).status_code == 401
    assert client.post('/api/login', json={'username':'demo','password':'demo'}, headers=headers).status_code == 401
    assert client.post('/api/token', json={}, headers=headers).status_code == 401

@pytest.mark.parametrize('overrides', [{'aud':'other'}, {'iss':'evil'}, {'exp':0}, {'token_use':'id'}])
def test_access_rejected(client, overrides):
    r = client.get('/api/resource', headers={'Authorization':'Bearer '+access_token(**overrides)})
    assert r.status_code == 401

def test_scope_and_missing_token(client):
    assert client.get('/api/resource').status_code == 401
    assert client.get('/api/resource', headers={'Authorization':'Bearer '+access_token(scope='other')}).status_code == 403
    bad = jwt.encode({'sub':'demo'}, 'different-key-with-at-least-32-bytes', algorithm='HS256')
    assert client.get('/api/resource', headers={'Authorization':'Bearer '+bad}).status_code == 401
    assert client.post('/api/token', json={'id_token':access_token()}).status_code == 401
    assert client.post('/api/login', json={'username':'demo','password':'wrong'}).status_code == 401

def test_sso_only():
    client = TestClient(create_app(Settings(signing_key=KEY, google_client_id='google-client'), GoogleKeys()))
    assert not client.get('/api/session').json()['local_login_allowed']
    assert client.post('/api/login', json={'username':'demo','password':'demo'}).status_code == 403
    local = TestClient(create_app(CFG, GoogleKeys())).post('/api/login', json={'username':'demo','password':'demo'}).json()['id_token']
    assert client.post('/api/token', json={'id_token':local}).status_code == 401

def test_invalid_signing_key():
    with pytest.raises(ValueError):
        create_app(Settings(signing_key='short', allow_local=True))
