from datetime import UTC, datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import AUTH_HEADERS, EMAIL, PASSWORD, sign_in, test_settings as settings_for_test
from riskengine.api import create_app
from riskengine.auth import hash_password, verify_password
from riskengine.config import Settings
from riskengine.models import AuthSession


def test_login_cookie_logout_and_legacy_bearer_rejection(client):
    cookie = client.cookies.get('riskengine-session')
    assert cookie and len(cookie) >= 32
    assert client.get('/api/auth/me').json() == {'email': EMAIL}
    logout = client.post('/api/auth/logout')
    assert logout.status_code == 204
    assert client.get('/api/audits').status_code == 401
    assert client.get('/api/audits', headers={'Cookie': f'riskengine-session={cookie}'}).status_code == 401
    assert client.get('/api/audits', headers={'Authorization': 'Bearer old-shared-key'}).status_code == 401
    sign_in(client)
    assert client.cookies.get('riskengine-session') != cookie


def test_login_rejects_wrong_credentials_with_same_message(client):
    for body in ({'email': EMAIL, 'password': 'incorrect'}, {'email': 'other@example.test', 'password': PASSWORD}):
        r = client.post('/api/auth/login', json=body)
        assert r.status_code == 401
        assert r.json()['error']['message'] == 'Correo o contraseña incorrectos.'
        assert 'set-cookie' not in r.headers


def test_csrf_cannot_write_or_login_from_other_origins(client):
    for headers in ({'Origin': 'https://attacker.test'}, {'Origin': 'http://testserver.attacker.test'}, {'X-RiskEngine-Request': ''}, {'Origin': ''}):
        assert client.post('/api/audits', headers=headers, json={'name': 'blocked', 'scope': 'blocked'}).status_code == 403
        assert client.post('/api/auth/login', headers=headers, json={'email': EMAIL, 'password': PASSWORD}).status_code == 403
    assert client.get('/api/audits').json()['total'] == 0


def test_sessions_are_hashed_expire_and_survive_app_recreation(client):
    cookie = client.cookies.get('riskengine-session')
    engine = client.app.state.repository.engine
    with TestClient(create_app(settings_for_test(), engine), headers=AUTH_HEADERS) as restarted:
        assert restarted.get('/api/audits', headers={'Cookie': f'riskengine-session={cookie}'}).status_code == 200
    with client.app.state.repository.session() as db, db.begin():
        row = db.scalars(select(AuthSession)).one()
        assert row.token_hash != cookie and len(row.token_hash) == 64
        row.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert client.get('/api/audits').status_code == 401


def test_rotation_revokes_old_session(client):
    engine = client.app.state.repository.engine
    settings = Settings('', EMAIL, hash_password('another-synthetic-password'), allowed_origins=('http://testserver',))
    with TestClient(create_app(settings, engine), headers=AUTH_HEADERS) as rotated:
        rotated.cookies.update(client.cookies)
        assert rotated.get('/api/audits').status_code == 401


def test_login_rotates_current_session(client):
    old = client.cookies.get('riskengine-session')
    sign_in(client)
    assert client.get('/api/audits', headers={'Cookie': f'riskengine-session={old}'}).status_code == 401
    assert client.get('/api/audits').status_code == 200


def test_login_is_rate_limited(client):
    for _ in range(9):
        assert client.post('/api/auth/login', json={'email': EMAIL, 'password': 'incorrect'}).status_code == 401
    r = client.post('/api/auth/login', json={'email': EMAIL, 'password': PASSWORD})
    assert r.status_code == 429


def test_production_cookie_is_secure_host_only_and_httponly(client):
    engine = client.app.state.repository.engine
    with TestClient(create_app(settings_for_test(secure_cookie=True), engine), base_url='https://testserver', headers=AUTH_HEADERS) as secure:
        response = secure.post('/api/auth/login', json={'email': EMAIL, 'password': PASSWORD})
        header = response.headers['set-cookie'].lower()
        assert '__host-riskengine-session=' in header
        assert 'httponly' in header and 'secure' in header and 'samesite=strict' in header
        assert 'domain=' not in header and 'path=/' in header
        assert response.headers['cache-control'] == 'no-store'
        assert secure.get('/api/auth/me').status_code == 200


def test_password_hash_is_salted_and_never_plaintext():
    first = hash_password('synthetic')
    second = hash_password('synthetic')
    assert first != second and 'synthetic' not in first
    assert verify_password('synthetic', first)
    assert not verify_password('wrong', first)
    assert not verify_password('synthetic', 'invalid')


def test_unconfigured_login_is_closed(client):
    with TestClient(create_app(Settings('', allowed_origins=('http://testserver',)), client.app.state.repository.engine), headers=AUTH_HEADERS) as closed:
        assert closed.post('/api/auth/login', json={'email': EMAIL, 'password': PASSWORD}).status_code == 503


def test_plain_environment_password_is_hashed_and_sessions_survive_restart(client):
    from riskengine.models import PersonalAccount
    engine = client.app.state.repository.engine
    settings = Settings('', EMAIL, admin_password='synthetic-env-password', allowed_origins=('http://testserver',))
    app = create_app(settings, engine)
    with TestClient(app, headers=AUTH_HEADERS) as first:
        assert first.post('/api/auth/login', json={'email': EMAIL, 'password': 'synthetic-env-password'}).status_code == 200
        cookie = first.cookies.get('riskengine-session')
        with client.app.state.repository.session() as db:
            account = db.get(PersonalAccount, 'owner')
            assert account.password_hash != 'synthetic-env-password'
            assert verify_password('synthetic-env-password', account.password_hash)
    with TestClient(create_app(settings, engine), headers=AUTH_HEADERS) as restarted:
        assert restarted.get('/api/auth/me', headers={'Cookie': f'riskengine-session={cookie}'}).status_code == 200
    changed = Settings('', EMAIL, admin_password='changed-env-password', allowed_origins=('http://testserver',))
    with TestClient(create_app(changed, engine), headers=AUTH_HEADERS) as rotated:
        assert rotated.get('/api/auth/me', headers={'Cookie': f'riskengine-session={cookie}'}).status_code == 401
        assert rotated.post('/api/auth/login', json={'email': EMAIL, 'password': 'synthetic-env-password'}).status_code == 401
        assert rotated.post('/api/auth/login', json={'email': EMAIL, 'password': 'changed-env-password'}).status_code == 200
