from datetime import date, datetime, UTC
import json
import logging
import math
import httpx

from .parser import CVE_PATTERN

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_RESPONSE_BYTES = 15 * 1024 * 1024
logger = logging.getLogger("riskengine.enrichment")


def get_json(url, params=None):
    with httpx.Client(timeout=httpx.Timeout(10, connect=5), follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", url, params=params) as response:
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Upstream response limit")
            return json.loads(body)


def fetch_evidence(cves: list[str]) -> list[dict]:
    """Fixed upstreams only: scanner targets and arbitrary URLs are not accepted."""
    entries = []
    fetched_at = datetime.now(UTC).isoformat()
    def record(cve, source, state, value=None, data_date=None):
        return {"cve": cve, "source": source, "state": state, "value": value, "data_date": data_date,
                "fetched_at": fetched_at, "provenance": EPSS_URL if source == "epss" else KEV_URL}
    for start in range(0, len(cves), 100):
        batch = cves[start:start + 100]
        try:
            payload = get_json(EPSS_URL, {"cve": ",".join(batch), "limit": 100})
            if payload.get("status") != "OK" or not isinstance(payload.get("data"), list):
                raise ValueError("Invalid EPSS envelope")
            known = {}
            for row in payload["data"]:
                cve, value, data_date = row["cve"], float(row["epss"]), date.fromisoformat(row["date"])
                if cve not in batch or cve in known or not math.isfinite(value) or not 0 <= value <= 1 or data_date > datetime.now(UTC).date():
                    raise ValueError("Invalid EPSS value")
                known[cve] = record(cve, "epss", "known", value, data_date.isoformat())
            entries.extend(known.get(cve, record(cve, "epss", "not_found")) for cve in batch)
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
            logger.warning(json.dumps({"event": "source_unavailable", "source": "epss", "cve_count": len(batch)}))
            entries.extend(record(cve, "epss", "error") for cve in batch)
    if cves:
        try:
            payload = get_json(KEV_URL)
            rows = payload["vulnerabilities"]
            data_date = datetime.fromisoformat(payload["dateReleased"].replace("Z", "+00:00")).date()
            if not isinstance(rows, list) or type(payload["count"]) is not int or payload["count"] != len(rows) or data_date > datetime.now(UTC).date():
                raise ValueError("Incomplete KEV catalog")
            known = set()
            for row in rows:
                cve = row["cveID"]
                if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve) or cve in known:
                    raise ValueError("Invalid KEV catalog")
                known.add(cve)
            entries.extend(record(cve, "kev", "known", cve in known, data_date.isoformat()) for cve in cves)
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
            logger.warning(json.dumps({"event": "source_unavailable", "source": "kev", "cve_count": len(cves)}))
            entries.extend(record(cve, "kev", "error") for cve in cves)
    return entries
