from conftest import confirm_synthetic_references
from datetime import date, timedelta
from uuid import uuid4
from sqlalchemy import select
from riskengine.models import Evidence


def request(report, **weights):
    return {"import_id": report, "weights": {"cvss": 0, "epss": 0, "kev": 0, "criticality": 0, "exposure": 0, **weights}, "acknowledge_experimental": True, "max_evidence_age_days": 1}


def test_run_persists_snapshots_and_missing_inputs(client, imported):
    audit, report = imported
    run = client.post(f"/api/audits/{audit}/runs", json=request(report, cvss=1))
    assert run.status_code == 201, run.text
    page = client.get(f"/api/audits/{audit}/runs/{run.json()['id']}/results").json()
    assert [row['score'] for row in page['items']] == [98, 75, None]
    assert page['items'][-1]['status'] == 'missing_data'
    export = client.get(f"/api/audits/{audit}/runs/{run.json()['id']}/export")
    assert 'attachment' in export.headers['content-disposition']
    assert export.json()['total'] == 3


def test_changing_context_does_not_rewrite_old_result(client, imported):
    audit, report = imported
    assets = client.get(f"/api/audits/{audit}/assets").json()['items']
    for asset in assets:
        assert client.patch(f"/api/audits/{audit}/assets/{asset['id']}", json={'criticality': 1}).status_code == 200
    run = client.post(f"/api/audits/{audit}/runs", json=request(report, criticality=1)).json()
    before = client.get(f"/api/audits/{audit}/runs/{run['id']}/results").json()
    client.patch(f"/api/audits/{audit}/assets/{assets[0]['id']}", json={'criticality': 5})
    after = client.get(f"/api/audits/{audit}/runs/{run['id']}/results").json()
    assert before == after and all(row['score'] == 0 for row in after['items'])


def test_stale_evidence_is_missing_and_zero_is_known(client, imported):
    audit, report = imported
    confirm_synthetic_references(client, audit)
    repo = client.app.state.repository
    cves = repo.cves(audit)
    repo.save_evidence([{'cve': cve, 'source': 'epss', 'state': 'known', 'value': 0.0, 'data_date': (date.today() - timedelta(days=5)).isoformat(), 'provenance': 'test-only'} for cve in cves])
    old_run = client.post(f"/api/audits/{audit}/runs", json=request(report, epss=1)).json()
    old = client.get(f"/api/audits/{audit}/runs/{old_run['id']}/results").json()
    assert all(row['score'] is None for row in old['items'])
    repo.save_evidence([{'cve': cve, 'source': 'epss', 'state': 'known', 'value': 0.0, 'data_date': date.today().isoformat(), 'provenance': 'test-only'} for cve in cves])
    new_run = client.post(f"/api/audits/{audit}/runs", json=request(report, epss=1)).json()
    new = client.get(f"/api/audits/{audit}/runs/{new_run['id']}/results").json()
    assert [row['score'] for row in new['items']] == [0, 0, None]
    assert client.get(f"/api/audits/{audit}/runs/{old_run['id']}/results").json() == old


def test_weight_validation_and_cross_audit_scope(client, imported):
    audit, report = imported
    assert client.post(f"/api/audits/{audit}/runs", json=request(report, cvss=.5)).status_code == 422
    other = client.post('/api/audits', json={'name': 'Otra', 'scope': 'Otra'}).json()['id']
    assert client.post(f"/api/audits/{other}/runs", json=request(report, cvss=1)).status_code == 404
    assert client.patch(f"/api/audits/{audit}/assets/{uuid4()}", json={'criticality': 5}).status_code == 404
    assert client.post(f"/api/audits/{audit}/runs", json={**request(report, cvss=1), 'acknowledge_experimental': False}).status_code == 422


def test_unauthenticated_requests_cannot_read_or_upload(client, imported):
    audit, _ = imported
    assert client.get('/api/audits', headers={'Cookie': ''}).status_code == 401
    assert client.post(f'/api/audits/{audit}/imports', headers={'Cookie': ''}, files={'file': ('a.xml', b'not-xml')}).status_code == 401


def test_tracking_status_is_validated(client, imported):
    audit, report = imported
    finding = client.get(f'/api/audits/{audit}/findings').json()['items'][0]
    assert client.patch(f'/api/audits/{audit}/findings/{finding["id"]}', json={'status': 'resolved'}).status_code == 200
    assert client.patch(f'/api/audits/{audit}/findings/{finding["id"]}', json={'status': 'ignored'}).status_code == 422
