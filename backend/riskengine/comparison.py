"""Compare preset scores on one immutable snapshot, without fetching new evidence."""
from .domain import EngineInput, prioritize
from .profiles import PROFILES


def compare_snapshot(payload):
    rows = []
    coverage = dict.fromkeys(PROFILES, 0)
    for result in payload["items"]:
        snapshot = result["snapshot"]
        finding = snapshot["finding"]
        inputs = EngineInput(**snapshot["inputs"])
        scores = {}
        for identifier, profile in PROFILES.items():
            calculated = prioritize(inputs, profile["weights"])
            special = finding.get("severity") is not None and finding["severity"] < 0
            score = None if special else calculated.score
            scores[identifier] = {"score": score, "missing": list(calculated.missing), "scanner_review_required": special}
            coverage[identifier] += score is not None
        rows.append({"finding_id": result["finding_id"], "name": finding["name"], "host": finding["host"],
                     "port": finding["port"], "scores": scores,
                     "common": all(value["score"] is not None for value in scores.values())})
    rows.sort(key=lambda row: row["finding_id"])
    return {"source_run_id": payload["run"]["id"], "configuration": payload["run"]["configuration"],
            "profiles": PROFILES, "total": len(rows), "coverage": coverage,
            "common_count": sum(row["common"] for row in rows), "items": rows,
            "interpretation": "Comparación aritmética sobre las mismas entradas congeladas. No acredita superioridad sin referencia independiente. Los pendientes no tienen prioridad baja."}
