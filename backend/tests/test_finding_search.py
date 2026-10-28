def test_search_fields_scope_and_literal_wildcards(client, imported):
    audit, report = imported
    url = f'/api/audits/{audit}/findings'
    original = client.get(url, params={'import_id': report}).json()
    assert original['total'] == 3
    sample = original['items'][0]
    for query in [sample['name'].upper(), sample['host'], sample['port']]:
        if query:
            data = client.get(url, params={'import_id': report, 'q': query}).json()
            assert sample['id'] in [row['id'] for row in data['items']]
    cve_item = next(row for row in original['items'] if row['cves'])
    data = client.get(url, params={'q': cve_item['cves'][0].lower()}).json()
    assert cve_item['id'] in [row['id'] for row in data['items']]
    for query in ['%', '_', "' OR 1=1 --", 'not-existing-search']:
        assert client.get(url, params={'q': query}).json() == {'items': [], 'total': 0}
    other = client.post('/api/audits', json={'name': 'Other', 'scope': 'isolated'}).json()['id']
    assert client.get(f'/api/audits/{other}/findings', params={'q': sample['host']}).json()['total'] == 0
    assert client.get(f'/api/audits/{other}/findings', params={'import_id': report}).status_code == 404


def test_sort_pagination_and_validation(client, imported):
    audit, report = imported
    url = f'/api/audits/{audit}/findings'
    for order in ['name', 'cvss_desc', 'cvss_asc', 'host']:
        params = {'import_id': report, 'sort': order}
        full = client.get(url, params=params).json()
        pages = [client.get(url, params={**params, 'limit': 1, 'offset': i}).json() for i in range(3)]
        assert all(p['total'] == 3 for p in pages)
        assert [p['items'][0]['id'] for p in pages] == [r['id'] for r in full['items']]
        if order.startswith('cvss'):
            scores = [r['cvss'] for r in full['items']]
            known = [s for s in scores if s is not None]
            assert scores == sorted(known, reverse=order == 'cvss_desc') + [None] * (len(scores)-len(known))
    assert client.get(url, params={'sort': 'invalid'}).status_code == 422
    assert client.get(url, params={'q': 'x'*201}).status_code == 422


def test_original_order_matches_xml_with_pagination_and_reimport(client, imported):
    from conftest import FIXTURE
    from riskengine.parser import parse_report
    audit, report = imported
    expected = [finding.external_id for finding in parse_report(FIXTURE.read_bytes()).findings]
    url = f'/api/audits/{audit}/findings'
    params = {'import_id': report, 'sort': 'original', 'limit': 1}
    actual = [client.get(url, params={**params, 'offset': i}).json()['items'][0]['external_id']
              for i in range(len(expected))]
    assert actual == expected
    response = client.post(f'/api/audits/{audit}/imports', files={'file': ('again.xml', FIXTURE.read_bytes())})
    assert response.json()['reused'] is True
    assert [row['external_id'] for row in client.get(url, params={'import_id': report}).json()['items']] == expected
