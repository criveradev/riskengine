from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
import pytest
from riskengine.domain import AppError
from riskengine.models import Asset, Audit, Finding, Import, Result, Run
from riskengine.parser import parse_report

XML = (Path(__file__).parent / "fixtures/synthetic-greenbone.xml").read_bytes()


def test_xml_import_retains_missing_cve_and_computes_only_explicit_31(client, imported):
    audit, report = imported
    page = client.get(f"/api/audits/{audit}/findings?import_id={report}").json()
    assert page["total"] == 3
    assert sorted(f["cvss"] for f in page["items"] if f["cvss"] is not None) == [7.5, 9.8]
    assert any(not f["cves"] and f["cvss"] is None for f in page["items"])


def test_reimport_is_idempotent_and_paginated(client, imported):
    audit, report = imported
    response = client.post(f"/api/audits/{audit}/imports", files={"file": ("same.xml", XML)})
    assert response.status_code == 200 and response.json()["reused"]
    assert response.json()["id"] == report
    page = client.get(f"/api/audits/{audit}/findings?limit=1&offset=1").json()
    assert len(page["items"]) == 1 and page["total"] == 3


def test_concurrent_reimport_keeps_one_import(client):
    audit = client.post("/api/audits", json={"name": "Concurrente", "scope": "Solo prueba"}).json()["id"]
    def upload(_):
        return client.post(f"/api/audits/{audit}/imports", files={"file": ("test.xml", XML)})
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(upload, range(2)))
    assert sorted(response.status_code for response in responses) == [200, 201]
    assert client.get(f"/api/audits/{audit}/imports").json()["total"] == 1
    assert client.get(f"/api/audits/{audit}/findings").json()["total"] == 3


@pytest.mark.parametrize("content", [b'<report>', b'<anything><results/></anything>', b'<!DOCTYPE report [<!ENTITY x SYSTEM "file:///etc/passwd">]><report><results>&x;</results></report>', XML.replace(b'synthetic-result-3', b'synthetic-result-1'), XML.replace(b'<host>192.0.2.20</host>', b'<host/>')])
def test_invalid_xml_never_leaves_partial_findings(client, content):
    audit = client.post("/api/audits", json={"name": "Prueba", "scope": "Prueba"}).json()["id"]
    response = client.post(f"/api/audits/{audit}/imports", files={"file": ("bad.xml", content)})
    assert response.status_code == 422
    assert client.get(f"/api/audits/{audit}/findings").json()["total"] == 0
    assert client.get(f"/api/audits/{audit}/imports").json()["total"] == 0


def test_empty_valid_report_is_preserved(client):
    audit = client.post("/api/audits", json={"name": "Vacía", "scope": "Prueba"}).json()["id"]
    response = client.post(f"/api/audits/{audit}/imports", files={"file": ("empty.xml", b'<report><results/></report>')})
    assert response.status_code == 201 and response.json()["finding_count"] == 0


def test_plain_scanner_severity_does_not_invent_cvss_version():
    parsed = parse_report(b'<report><results><result id="a"><host>192.0.2.1</host><name>X</name><severity>9.8</severity><nvt><cvss_base>9.8</cvss_base></nvt></result></results></report>')
    assert parsed.findings[0].severity == 9.8 and parsed.findings[0].cvss is None


def test_foreign_audit_asset_blocked_by_database(client, imported):
    audit, report = imported
    repo = client.app.state.repository
    with repo.session() as session, session.begin():
        other = Audit(name="Otra", scope="Otra")
        session.add(other); session.flush()
        asset = Asset(audit_id=other.id, identifier="192.0.2.99")
        session.add(asset); session.flush()
        asset_id = asset.id
    with pytest.raises(IntegrityError):
        with repo.session() as session, session.begin():
            session.add(Finding(audit_id=audit, import_id=report, asset_id=asset_id, external_id="invalid", name="invalid", oid="", port="", description=""))
