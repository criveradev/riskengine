from collections import Counter
from dataclasses import asdict
from datetime import date, datetime, UTC
from time import perf_counter
from .contracts import RunCreate
from .domain import AppError, EngineInput, EngineResult, MODEL_VERSION, prioritize
from .enrichment import fetch_evidence
from .parser import parse_report
from .diagnostics import cvss_admission
from .profiles import identify_profile


class Services:
    def __init__(self, repository):
        self.repository = repository

    def import_report(self, audit_id, filename, content):
        start = perf_counter()
        parsed = parse_report(content)
        parsed_at = perf_counter()
        result = self.repository.save_import(audit_id, filename, content, parsed)
        result["timings_ms"] = {"parse": round((parsed_at - start) * 1000, 3), "persist": round((perf_counter() - parsed_at) * 1000, 3)}
        return result

    def enrich(self, audit_id):
        cves = self.repository.cves(audit_id)
        if len(cves) > 500:
            raise AppError("enrichment_limit", "Este incremento permite enriquecer hasta 500 CVE únicos por auditoría.", 413)
        entries = fetch_evidence(cves)
        self.repository.save_evidence(entries)
        return {"unique_cves": len(cves), "sources": {source: dict(Counter(entry["state"] for entry in entries if entry["source"] == source)) for source in ("epss", "kev")}}

    def create_run(self, audit_id, request: RunCreate):
        findings = self.repository.findings(audit_id, str(request.import_id), limit=10_000)["items"]
        if not findings:
            raise AppError("empty_scope", "La importación no tiene hallazgos para priorizar.")
        cves = {cve for item in findings for cve in item["cves"]}
        evidence = self.repository.latest_evidence(cves)
        cut_off = datetime.now(UTC)
        results = []
        for finding in findings:
            used = []
            by_source = {"epss": [], "kev": []}
            reviews = finding["cve_reviews"]
            review_complete = bool(reviews) and all(review["status"] != "pending" for review in reviews)
            applicable = [review["cve"] for review in reviews if review["status"] == "applicable"]
            for cve in applicable if review_complete else []:
                for source in by_source:
                    entry = evidence.get((cve, source))
                    admissible = False
                    if entry and entry["state"] == "known" and entry["data_date"]:
                        age = (cut_off.date() - date.fromisoformat(entry["data_date"][:10])).days
                        admissible = 0 <= age <= request.max_evidence_age_days
                    used.append({"cve": cve, "source": source, "entry": entry, "admissible": admissible})
                    by_source[source].append(entry["value"] if admissible else None)
            epss_values, kev_values = by_source["epss"], by_source["kev"]
            epss = max(epss_values) if epss_values and all(value is not None for value in epss_values) else None
            kev = True if any(value is True for value in kev_values) else (False if kev_values and all(value is False for value in kev_values) else None)
            inputs = EngineInput(finding["cvss"], epss, kev, finding["criticality"], finding["exposure"])
            output = prioritize(inputs, request.weights)
            if ("epss" in output.missing or "kev" in output.missing) and (not review_complete or not applicable):
                reason = "Aplicabilidad CVE pendiente de revisión." if reviews and not review_complete else "No hay CVE confirmados como aplicables para calcular EPSS/KEV."
                output = EngineResult(output.status, output.score, reason + " " + output.explanation, output.missing, output.contributions)
            if "cvss" in output.missing:
                reason = cvss_admission(finding)["message"]
                output = EngineResult(output.status, output.score, reason + " " + output.explanation, output.missing, output.contributions)
            if finding["severity"] is not None and finding["severity"] < 0:
                output = EngineResult("missing_data", None, "El escáner marcó este resultado con severidad especial negativa; requiere revisión.", (), {})
            snapshot = {"finding": finding, "inputs": asdict(inputs), "evidence": used, "missing": list(output.missing), "contributions": output.contributions}
            results.append((finding["id"], output, snapshot))
        configuration = {**request.model_dump(mode="json"), "cut_off": cut_off.isoformat(),
                         "profile_id": identify_profile(request.weights), "scope": "one_import", "formula": "100 * sum(weight * normalized_input)",
                         "normalization": {"cvss": "base_3.1 / 10", "epss": "raw_probability", "kev": "known_bool_as_0_or_1", "criticality": "(level-1)/4", "exposure": "(level-1)/4"},
                         "applicability_policy": "all_references_reviewed; applicable_only; unresolved_or_empty_is_unknown",
                         "aggregation": {"epss": "max_only_if_all_cves_known", "kev": "any_true_else_all_false_else_unknown"},
                         "missing_policy": "required_if_weight_positive; no_automatic_fallback", "academic_status": "experimental_not_validated"}
        return self.repository.save_run(audit_id, MODEL_VERSION, configuration, results)
