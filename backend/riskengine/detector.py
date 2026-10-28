from typing import TypedDict
from urllib.parse import urlsplit

from .domain import AppError
from .parser import _read_results


class DetectorInfo(TypedDict):
    name: str
    oid: str
    family: str
    version: str
    summary: str
    affected: str
    insight: str
    impact: str
    detection: str
    solution: str
    references: list[str]


def detector_information(content: bytes, external_id: str) -> DetectorInfo:
    """Read detector documentation without treating it as observed scan evidence."""
    _, results = _read_results(content)
    result = next((row for row in results if row.get("id") == external_id), None)
    if result is None:
        raise AppError("source_result_missing", "El hallazgo no aparece en el XML guardado.", 409)
    nvt = result.find("nvt")
    tags = dict((key.strip(), value.strip()) for part in result.findtext("nvt/tags", "").split("|") if "=" in part for key, value in [part.split("=", 1)])
    references = []
    for ref in result.findall("nvt/refs/ref"):
        value = ref.get("id", "").strip()
        if ref.get("type", "").lower() != "url":
            continue
        try:
            url = urlsplit(value)
            valid = url.scheme in {"https", "http"} and bool(url.hostname) and not url.username and not url.password
        except ValueError:
            valid = False
        if valid and value not in references:
            references.append(value)
    return {
        "name": result.findtext("nvt/name", "").strip(),
        "oid": nvt.get("oid", "") if nvt is not None else "",
        "family": result.findtext("nvt/family", "").strip(),
        "version": result.findtext("scan_nvt_version", "").strip(),
        "summary": tags.get("summary", ""), "affected": tags.get("affected", ""),
        "insight": tags.get("insight", ""), "impact": tags.get("impact", ""),
        "detection": tags.get("vuldetect", ""),
        "solution": result.findtext("nvt/solution", "").strip() or tags.get("solution", ""),
        "references": references,
    }
