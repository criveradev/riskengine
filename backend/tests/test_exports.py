import csv
import io

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from test_runs import request
from riskengine.exports import csv_cell, render_pdf
from riskengine.models import Finding


def test_exports_preserve_saved_results_and_unknown_values(client, imported):
    audit, report = imported
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    url = f"/api/audits/{audit}/runs/{run['id']}/export"
    original = client.get(url).json()
    response = client.get(url, params={'format': 'csv'})
    assert response.status_code == 200
    assert response.headers['content-type'].startswith('text/csv')
    assert f"riskengine-{run['id']}.csv" in response.headers['content-disposition']
    rows = list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig'))))
    assert [row['indice'] for row in rows] == ['98.0', '75.0', '']
    assert [row['hallazgo'] for row in rows] == [item['snapshot']['finding']['name'] for item in original['items']]
    assert rows[-1]['estado'] == 'missing_data'

    pdf = client.get(url, params={'format': 'pdf'})
    assert pdf.status_code == 200
    assert pdf.headers['content-type'] == 'application/pdf'
    assert f"riskengine-{run['id']}.pdf" in pdf.headers['content-disposition']
    assert pdf.content.startswith(b'%PDF-') and pdf.content.rstrip().endswith(b'%%EOF')

    asset = client.get(f'/api/audits/{audit}/assets').json()['items'][0]
    assert client.patch(f"/api/audits/{audit}/assets/{asset['id']}", json={'criticality': 5}).status_code == 200
    assert client.get(url).json() == original
    assert client.get(url, params={'format': 'csv'}).content == response.content


@pytest.mark.parametrize('format', ['json', 'pdf', 'csv'])
def test_exports_require_access_and_the_correct_audit(client, imported, format):
    audit, report = imported
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    url = f"/api/audits/{audit}/runs/{run['id']}/export?format={format}"
    assert client.get(url, headers={'Authorization': ''}).status_code == 401
    other = client.post('/api/audits', json={'name': 'Otra', 'scope': 'Prueba sintética'}).json()['id']
    assert client.get(url.replace(audit, other)).status_code == 404


def test_unsupported_export_format_is_rejected(client, imported):
    audit, report = imported
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    assert client.get(f"/api/audits/{audit}/runs/{run['id']}/export?format=xml").status_code == 422


@pytest.mark.parametrize('text', ['=1+1', '+SUM(1,2)', '-1+1', '@SUM(1,2)', '  =1+1', '\t=1+1'])
def test_csv_neutralizes_formula_text(text):
    assert csv_cell(text) == "'" + text


def test_imported_formula_name_is_safe_in_csv(client, imported):
    audit, report = imported
    with client.app.state.repository.session() as session, session.begin():
        finding = session.scalar(select(Finding).where(Finding.import_id == report))
        finding.name = '=HYPERLINK("https://example.invalid","test")'
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    response = client.get(f"/api/audits/{audit}/runs/{run['id']}/export?format=csv")
    names = [row['hallazgo'] for row in csv.DictReader(io.StringIO(response.content.decode('utf-8-sig')))]
    assert '\'=HYPERLINK("https://example.invalid","test")' in names


def test_pdf_handles_long_imported_names(client, imported):
    audit, report = imported
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    payload = client.get(f"/api/audits/{audit}/runs/{run['id']}/results").json()
    payload['items'][0]['snapshot']['finding']['name'] = '<dato importado> & ' + 'Texto largo sin truncar. ' * 300
    assert render_pdf(payload).startswith(b'%PDF-')


def test_pdf_keeps_evidence_and_citations_on_the_finding_page(client, imported):
    audit, report = imported
    run = client.post(f'/api/audits/{audit}/runs', json=request(report, cvss=1)).json()
    payload = client.get(f'/api/audits/{audit}/runs/{run["id"]}/results').json()
    payload['items'] = payload['items'][:1]
    payload['total'] = 1
    snapshot = payload['items'][0]['snapshot']
    snapshot['finding']['name'] = 'Comprobación de exportación de evidencias y fuentes externas'
    snapshot['finding']['cves'] = [f'CVE-2020-{1000 + i}' for i in range(4)]
    sources = {
        'epss': 'https://api.first.org/data/v1/epss',
        'kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    }
    snapshot['evidence'] = [
        {'cve': cve, 'source': source, 'admissible': True,
         'entry': {'value': False if source == 'kev' else 0.1,
                   'data_date': '2026-10-16', 'fetched_at': '2026-10-19T20:48:00+00:00',
                   'provenance': url}}
        for cve in snapshot['finding']['cves'] for source, url in sources.items()
    ]

    pages = [page.extract_text() for page in PdfReader(io.BytesIO(render_pdf(payload))).pages]
    detail_pages = [text for text in pages if 'FICHA 01 / HALLAZGO' in text]
    assert len(detail_pages) == 1
    detail = detail_pages[0]
    assert '98.00 / 100 puntos' in detail
    for cve in snapshot['finding']['cves']:
        assert detail.count(cve) == 3  # Identifier plus one row per source.
    for url in sources.values():
        assert url in detail
    assert not any('CISA / KEV' in text and 'FICHA' not in text for text in pages)
