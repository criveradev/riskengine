from conftest import confirm_synthetic_references
import csv
import io
from datetime import date
from pypdf import PdfReader
from conftest import FIXTURE
from test_runs import request
from riskengine.profiles import PROFILES
from riskengine.parser import parse_report

LEGACY = 'AV:N/AC:L/Au:N/C:C/I:C/A:C'


def legacy_report():
    return f'<report><results><result id="legacy"><host>192.0.2.1</host><name>Legacy</name><severity>10</severity><nvt><severities><severity type="cvss_base_v2"><value>{LEGACY}</value></severity></severities></nvt></result></results></report>'.encode()


def test_preserves_legacy_severity_and_explains_version_in_exports(client):
    audit = client.post('/api/audits', json={'name':'Pilot','scope':'Synthetic'}).json()['id']
    report = client.post(f'/api/audits/{audit}/imports', files={'file':('legacy.xml',legacy_report())}).json()['id']
    finding = client.get(f'/api/audits/{audit}/findings').json()['items'][0]
    assert finding['severity'] == 10 and finding['cvss'] is None
    assert finding['original_vectors'] == [LEGACY]
    assert finding['cvss_admission']['code'] == 'unsupported_version'
    run = client.post(f'/api/audits/{audit}/runs',json=request(report,cvss=1)).json()
    assert run['configuration']['profile_id'] == 'cvss-only-v1'
    url=f'/api/audits/{audit}/runs/{run["id"]}/export'
    row=list(csv.DictReader(io.StringIO(client.get(url+'?format=csv').content.decode('utf-8-sig'))))[0]
    assert row['indice']=='' and row['posicion']=='' and row['severidad_original']=='10.0'
    assert '2.0' in row['admision_cvss'] and 'no admitido' in row['explicacion']
    pages=PdfReader(io.BytesIO(client.get(url+'?format=pdf').content)).pages
    assert 'únicamente por CVSS' in pages[0].extract_text()
    text=' '.join(p.extract_text() for p in pages)
    assert 'CVSS original 2.0 no admitido' in text


def test_preserves_original_vectors_for_all_versions():
    for vector in (LEGACY, 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'):
        parsed=parse_report(legacy_report().replace(LEGACY.encode(),vector.encode())).findings[0]
        assert parsed.cvss is None and parsed.original_vectors == (vector,)


def test_comparison_uses_frozen_inputs_and_reports_common_coverage(client, imported):
    audit, report=imported
    confirm_synthetic_references(client, audit)
    repo=client.app.state.repository
    for asset in repo.assets(audit,100,0)['items']:
        repo.update_asset(audit,asset['id'],{'criticality':1,'exposure':1})
    repo.save_evidence([{'cve':cve,'source':source,'state':'known','value':.5 if source=='epss' else True,'data_date':date.today().isoformat(),'provenance':'synthetic'} for cve in repo.cves(audit) for source in ('epss','kev')])
    run=client.post(f'/api/audits/{audit}/runs',json=request(report,cvss=1)).json()
    url=f'/api/audits/{audit}/runs/{run["id"]}/comparison'
    first=client.get(url)
    assert first.status_code==200
    data=first.json()
    assert data['total']==3 and data['common_count']==2
    assert data['coverage']=={'cvss-only-v1':2,'equal-weights-v1':2,'roc-autores-v1':2}
    high=next(row for row in data['items'] if row['scores']['cvss-only-v1']['score']==98)
    assert high['scores']['roc-autores-v1']['score']==62.92
    assert high['scores']['equal-weights-v1']['score']==49.6
    for asset in repo.assets(audit,100,0)['items']:
        repo.update_asset(audit,asset['id'],{'criticality':5,'exposure':5})
    repo.save_evidence([{'cve':cve,'source':'epss','state':'error','provenance':'synthetic'} for cve in repo.cves(audit)])
    assert client.get(url).json()==data
    assert repo.runs(audit,100,0)['total']==1
    assert client.get(url,headers={'Cookie':''}).status_code==401
    other=client.post('/api/audits',json={'name':'Other','scope':'Synthetic'}).json()['id']
    assert client.get(url.replace(audit,other)).status_code==404


def test_profile_recognition_does_not_relabel_modified_roc(client, imported):
    audit,report=imported
    weights=PROFILES['roc-autores-v1']['weights'].copy()
    run=client.post(f'/api/audits/{audit}/runs',json=request(report,**weights)).json()
    assert run['configuration']['profile_id']=='roc-autores-v1'
    weights.update(cvss=.05,epss=.25)
    run=client.post(f'/api/audits/{audit}/runs',json=request(report,**weights)).json()
    assert run['configuration']['profile_id']=='custom'


def test_migration_backfills_vectors_without_changing_saved_snapshots(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    url=f'sqlite:///{tmp_path / "upgrade.db"}'
    monkeypatch.setenv('DATABASE_URL',url)
    cfg=Config(str(Path(__file__).parents[1]/'alembic.ini'))
    command.upgrade(cfg,'394376e43314')
    engine=create_engine(url)
    with engine.begin() as con:
        con.execute(text("INSERT INTO audits (id,name,scope,created_at) VALUES ('a','a','a','2026-10-20')"))
        con.execute(text("INSERT INTO imports (id,audit_id,sha256,filename,content,report_metadata,created_at) VALUES ('i','a','hash','test.xml',:xml,'{}','2026-10-20')"),{'xml':legacy_report()})
        con.execute(text("INSERT INTO assets (id,audit_id,identifier) VALUES ('asset','a','192.0.2.1')"))
        con.execute(text("INSERT INTO findings (id,audit_id,import_id,asset_id,external_id,name,oid,port,description,severity,status) VALUES ('f','a','i','asset','legacy','Legacy','','','',10,'open')"))
        con.execute(text("INSERT INTO runs (id,audit_id,version,configuration,created_at) VALUES ('r','a','v1','{}','2026-10-20')"))
        con.execute(text("INSERT INTO results (id,audit_id,run_id,finding_id,status,explanation,snapshot) VALUES ('res','a','r','f','missing_data','old','{}')"))
    command.upgrade(cfg,'head')
    with engine.connect() as con:
        assert json.loads(con.execute(text('SELECT original_vectors FROM findings')).scalar_one())==[LEGACY]
        assert con.execute(text('SELECT position FROM findings')).scalar_one()==1
        assert con.execute(text('SELECT snapshot FROM results')).scalar_one()=='{}'
    engine.dispose()
