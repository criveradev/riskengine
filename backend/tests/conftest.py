from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from riskengine.api import create_app
from riskengine.config import Settings
from riskengine.database import make_engine
from riskengine.models import Base
from riskengine.auth import hash_password

EMAIL = 'owner@example.test'
PASSWORD = 'synthetic-password-for-tests'
PASSWORD_HASH = hash_password(PASSWORD)
AUTH_HEADERS = {'Origin': 'http://testserver', 'X-RiskEngine-Request': '1'}


def test_settings(url='', **kwargs):
    return Settings(url, EMAIL, PASSWORD_HASH, allowed_origins=('http://testserver',), **kwargs)


def sign_in(client):
    response = client.post('/api/auth/login', json={'email': EMAIL, 'password': PASSWORD})
    assert response.status_code == 200, response.text

FIXTURE = Path(__file__).parent / "fixtures/synthetic-greenbone.xml"


@pytest.fixture
def client(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    app = create_app(test_settings(), engine)
    with TestClient(app, headers=AUTH_HEADERS) as client:
        sign_in(client)
        yield client
    engine.dispose()


@pytest.fixture
def imported(client):
    audit = client.post("/api/audits", json={"name": "Prueba", "scope": "Laboratorio sintético"}).json()
    response = client.post(f"/api/audits/{audit['id']}/imports", files={"file": ("test.xml", FIXTURE.read_bytes(), "application/xml")})
    assert response.status_code == 201, response.text
    return audit["id"], response.json()["id"]


def confirm_synthetic_references(client, audit):
    for finding in client.get(f"/api/audits/{audit}/findings").json()["items"]:
        for cve in finding["cves"]:
            response = client.post(f"/api/audits/{audit}/findings/{finding['id']}/cves/{cve}/reviews", json={
                "status": "applicable", "reviewer": "Synthetic fixture", "rationale": "Explicit applicability for isolated test"})
            assert response.status_code == 201, response.text
