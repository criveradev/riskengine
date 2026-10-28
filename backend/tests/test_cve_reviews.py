from datetime import datetime, UTC
from sqlalchemy import select, func
from riskengine.models import CVEReview
from test_runs import request


def test_applicability_gates_evidence_and_preserves_history(client, imported):
    audit, report = imported
    repo = client.app.state.repository
    finding = next(f for f in repo.findings(audit)["items"] if f["cves"])
    url = f"/api/audits/{audit}/findings/{finding['id']}/cves/{finding['cves'][0]}/reviews"
    today = datetime.now(UTC).date().isoformat()
    repo.save_evidence([{"cve":cve,"source":source,"state":"known","value":.5 if source=="epss" else True,"data_date":today,"provenance":"test"} for cve in repo.cves(audit) for source in ("epss","kev")])
    def run():
        created=client.post(f"/api/audits/{audit}/runs",json=request(report,epss=.5,kev=.5))
        assert created.status_code==201
        endpoint=f"/api/audits/{audit}/runs/{created.json()['id']}/results"
        page=client.get(endpoint).json()
        return endpoint, page, next(row for row in page['items'] if row['finding_id']==finding['id'])
    old_url, old, pending=run()
    assert pending['score'] is None and 'Aplicabilidad' in pending['explanation']
    for cve in finding['cves']:
        response=client.post(url.replace(finding['cves'][0],cve),json={'status':'applicable','reviewer':'Test','rationale':'Verified synthetic case'})
        assert response.status_code==201
    approved_url, approved, scored=run()
    assert scored['score']==75
    assert scored['snapshot']['finding']['cve_reviews'][0]['reviewer']=='Test'
    assert client.post(url,json={'status':'not_applicable','reviewer':'Second','rationale':'Different synthetic product'}).status_code==201
    # Any unresolved reference blocks even a known-true KEV from another CVE.
    assert client.post(url,json={'status':'pending','reviewer':'Second','rationale':'Need version confirmation'}).status_code==201
    _,_,pending_again=run()
    assert pending_again['score'] is None
    assert pending_again['snapshot']['inputs']['kev'] is None
    assert client.get(old_url).json()==old
    assert client.get(approved_url).json()==approved
    with repo.session() as session:
        assert session.scalar(select(func.count()).select_from(CVEReview))==len(finding['cves'])+2


def test_review_scope_authentication_and_validation(client, imported):
    audit,_=imported
    finding=next(f for f in client.app.state.repository.findings(audit)['items'] if f['cves'])
    url=f"/api/audits/{audit}/findings/{finding['id']}/cves/{finding['cves'][0]}/reviews"
    body={'status':'applicable','reviewer':'Tester','rationale':'Evidence'}
    assert client.post(url,json=body,headers={'Authorization':''}).status_code==401
    other=client.post('/api/audits',json={'name':'Other','scope':'Other'}).json()['id']
    assert client.post(url.replace(audit,other),json=body).status_code==404
    assert client.post(url.replace(finding['cves'][0],'CVE-2099-9999'),json=body).status_code==404
    for invalid in ({'reviewer':' '},{'rationale':' '},{'status':'confirmed'},{'rationale':'x'*3001}):
        assert client.post(url,json={**body,**invalid}).status_code==422


def test_excluded_references_do_not_influence_aggregation(client, imported):
    audit,report=imported
    repo=client.app.state.repository
    from conftest import FIXTURE
    xml=FIXTURE.read_bytes().replace(b'<ref type="cve" id="CVE-2021-44228"/>', b'<ref type="cve" id="CVE-2021-44228"/><ref type="cve" id="CVE-2023-44487"/>')
    report=client.post(f'/api/audits/{audit}/imports',files={'file':('multi.xml',xml)}).json()['id']
    finding=next(f for f in repo.findings(audit,report)['items'] if len(f['cves'])>1)
    today=datetime.now(UTC).date().isoformat()
    for index,cve in enumerate(finding['cves']):
        repo.review_cve(audit,finding['id'],cve,{'status':'applicable' if index==0 else 'not_applicable','reviewer':'Test','rationale':'Controlled fixture'})
        repo.save_evidence([{'cve':cve,'source':'epss','state':'known','value':.1 if index==0 else .99,'data_date':today,'provenance':'test'}])
    def score():
        run=client.post(f'/api/audits/{audit}/runs',json=request(report,epss=1)).json()
        return next(row for row in client.get(f"/api/audits/{audit}/runs/{run['id']}/results").json()['items'] if row['finding_id']==finding['id'])
    assert score()['score']==10
    repo.review_cve(audit,finding['id'],finding['cves'][1],{'status':'pending','reviewer':'Test','rationale':'Version unresolved'})
    assert score()['score'] is None
    repo.review_cve(audit,finding['id'],finding['cves'][1],{'status':'not_applicable','reviewer':'Test','rationale':'Different product'})
    repo.review_cve(audit,finding['id'],finding['cves'][0],{'status':'not_applicable','reviewer':'Test','rationale':'No applicable references'})
    row=score()
    assert row['score'] is None and 'No hay CVE' in row['explanation']
