from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from riskengine.api import create_app
from riskengine.config import Settings
from riskengine.database import make_engine
from riskengine.models import Base

TOKEN = "test-token-only-not-for-use-outside-tests-1234"
FIXTURE = Path(__file__).parent / "fixtures/synthetic-greenbone.xml"


@pytest.fixture
def client(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    app = create_app(Settings("", TOKEN), engine)
    with TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"}) as client:
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
