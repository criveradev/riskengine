from datetime import date
import httpx
import pytest
from riskengine import enrichment

CVES = ['CVE-2021-44228', 'CVE-2023-44487']


def test_zero_epss_and_kev_absence_are_known_only_with_valid_snapshot(monkeypatch):
    def get_json(url, params=None):
        if url == enrichment.EPSS_URL:
            return {'status': 'OK', 'data': [{'cve': cve, 'epss': '0.0', 'date': date.today().isoformat()} for cve in CVES]}
        return {'count': 1, 'dateReleased': date.today().isoformat() + 'T00:00:00Z', 'vulnerabilities': [{'cveID': CVES[0]}]}
    monkeypatch.setattr(enrichment, 'get_json', get_json)
    result = enrichment.fetch_evidence(CVES)
    assert len(result) == 4
    assert [row['value'] for row in result if row['source'] == 'epss'] == [0, 0]
    assert [row['value'] for row in result if row['source'] == 'kev'] == [True, False]
    assert all(row['state'] == 'known' for row in result)


def test_failed_sources_never_create_zero_values(monkeypatch):
    def get_json(url, params=None):
        raise httpx.ConnectError('test-only')
    monkeypatch.setattr(enrichment, 'get_json', get_json)
    result = enrichment.fetch_evidence(CVES)
    assert len(result) == 4 and all(row['state'] == 'error' and row['value'] is None for row in result)


def test_partial_kev_catalog_is_not_treated_as_negative(monkeypatch):
    def get_json(url, params=None):
        if url == enrichment.EPSS_URL:
            return {'status': 'OK', 'data': []}
        return {'count': 2, 'dateReleased': date.today().isoformat() + 'T00:00:00Z', 'vulnerabilities': [{'cveID': CVES[0]}]}
    monkeypatch.setattr(enrichment, 'get_json', get_json)
    result = enrichment.fetch_evidence(CVES)
    assert all(row['state'] == 'not_found' and row['value'] is None for row in result if row['source'] == 'epss')
    assert all(row['state'] == 'error' and row['value'] is None for row in result if row['source'] == 'kev')


def test_no_cves_does_not_request_any_source(monkeypatch):
    def get_json(url, params=None):
        raise AssertionError('Unexpected network request')
    monkeypatch.setattr(enrichment, 'get_json', get_json)
    assert enrichment.fetch_evidence([]) == []
