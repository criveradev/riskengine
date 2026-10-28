import pytest
from riskengine.detector import detector_information
from riskengine.domain import AppError

XML = b'''<report><results><result id="detector-test"><host>192.0.2.1</host><name>Synthetic detector</name><port>21/tcp</port><description/><nvt oid="test-oid"><name>Detector name</name><family>FTP</family><tags>summary=General description|affected=Example 1.0|insight=Contains x=y|impact=General impact|solution=Tag solution|vuldetect=</tags><solution>Vendor solution</solution><refs><ref type="url" id="https://example.org/advisory"/><ref type="url" id="javascript:alert(1)"/><ref type="url" id="https://user:password@example.org"/><ref type="cve" id="CVE-2011-2523"/></refs></nvt><scan_nvt_version>2026-10-20</scan_nvt_version></result></results></report>'''


def test_existing_import_detector_is_read_only_and_scoped(client):
    audit = client.post('/api/audits', json={'name':'Detector','scope':'Synthetic'}).json()['id']
    report = client.post(f'/api/audits/{audit}/imports', files={'file':('test.xml', XML)}).json()
    findings_url = f'/api/audits/{audit}/findings'
    before = client.get(findings_url).json()
    finding = before['items'][0]
    response = client.get(f"{findings_url}/{finding['id']}/detector")
    assert response.status_code == 200
    data = response.json()
    assert data['source']['sha256'] == report['sha256']
    assert data['source']['filename'] == 'test.xml'
    assert data['detector']['summary'] == 'General description'
    assert data['detector']['solution'] == 'Vendor solution'
    assert data['detector']['insight'] == 'Contains x=y'
    assert data['detector']['references'] == ['https://example.org/advisory']
    assert data['detector']['detection'] == ''
    assert finding['description'] == ''
    assert client.get(findings_url).json() == before
    other = client.post('/api/audits', json={'name':'Other','scope':'Synthetic'}).json()['id']
    assert client.get(f"/api/audits/{other}/findings/{finding['id']}/detector").status_code == 404
    assert client.get(f"{findings_url}/{finding['id']}/detector", headers={'Authorization':'Bearer invalid'}).status_code == 401


def test_absent_metadata_and_missing_result():
    data = detector_information(b'<report><results><result id="x"/></results></report>', 'x')
    assert data['summary'] == '' and data['references'] == []
    with pytest.raises(AppError):
        detector_information(XML, 'not-present')


def test_detector_rejects_entities():
    with pytest.raises(AppError):
        detector_information(b'<!DOCTYPE report [<!ENTITY x SYSTEM "file:///etc/passwd">]><report><results>&x;</results></report>', 'x')
