from dataclasses import dataclass
import math
import re
from xml.etree.ElementTree import ParseError

from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from .domain import AppError

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z")
MAX_NODES, MAX_DEPTH, MAX_RESULTS = 100_000, 48, 10_000


@dataclass(frozen=True)
class ParsedFinding:
    external_id: str
    host: str
    name: str
    oid: str
    port: str
    description: str
    severity: float | None
    cvss: float | None
    vector: str | None
    cves: tuple[str, ...]
    original_vectors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedReport:
    findings: tuple[ParsedFinding, ...]
    metadata: dict[str, str]


def _read_results(content: bytes):
    try:
        root = ElementTree.fromstring(content, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise AppError("invalid_xml", "El XML está mal formado o contiene construcciones no permitidas.") from exc
    count = 0
    stack = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise AppError("xml_limits", "El XML supera los límites de estructura admitidos.")
        if "}" in element.tag:
            raise AppError("unsupported_xml", "Esta variante con espacios de nombres todavía no está admitida.")
        stack.extend((child, depth + 1) for child in element)
    if root.tag not in {"report", "get_reports_response"}:
        raise AppError("unsupported_xml", "Se espera un reporte XML de Greenbone.")
    if root.tag == "get_reports_response" and root.get("status") != "200":
        raise AppError("scanner_error", "La respuesta del escáner no contiene un reporte exitoso.")
    containers = root.findall(".//results")
    if len(containers) != 1:
        raise AppError("unsupported_xml", "Se requiere exactamente un bloque de resultados de un reporte.")
    results = containers[0].findall("result")
    if any(child.tag != "result" for child in containers[0]):
        raise AppError("unsupported_xml", "El bloque de resultados contiene una estructura no admitida.")
    if len(results) > MAX_RESULTS:
        raise AppError("too_many_results", "El reporte supera 10.000 resultados por importación.")
    return root, results


def parse_report(content: bytes) -> ParsedReport:
    root, results = _read_results(content)
    findings, seen = [], set()
    for index, result in enumerate(results, start=1):
        external_id = (result.get("id") or "").strip()
        host, name = result.findtext("host", "").strip(), result.findtext("name", "").strip()
        if not external_id or not host or not name or max(len(external_id), len(host)) > 255:
            raise AppError("missing_field", f"Resultado {index}: faltan ID, host o nombre válidos.")
        if external_id in seen:
            raise AppError("duplicate_result", f"Resultado {index}: ID repetido dentro del reporte.")
        seen.add(external_id)
        cves = set()
        for ref in result.findall("nvt/refs/ref"):
            if ref.get("type", "").lower() == "cve":
                value = ref.get("id", "").strip().upper()
                if not CVE_PATTERN.fullmatch(value) or len(value) > 32:
                    raise AppError("invalid_cve", f"Resultado {index}: referencia CVE inválida.")
                cves.add(value)
        legacy_cves = result.findtext("nvt/cve", "").strip()
        if legacy_cves and legacy_cves.upper() not in {"NOCVE", "NONE"}:
            for value in re.split(r"[,\s]+", legacy_cves.upper()):
                if not CVE_PATTERN.fullmatch(value) or len(value) > 32:
                    raise AppError("invalid_cve", f"Resultado {index}: referencia CVE inválida.")
                cves.add(value)
        if len(cves) > 100:
            raise AppError("cve_limit", f"Resultado {index}: supera 100 CVE asociados.")
        # Only an explicit 3.1 vector establishes a comparable Base score.
        vectors = [item.text.strip() for item in result.findall("nvt/severities/severity/value") if item.text]
        tags = dict(part.split("=", 1) for part in result.findtext("nvt/tags", "").split("|") if "=" in part)
        vectors.extend(value.strip() for key, value in tags.items() if key.strip() in {"cvss_base_vector", "cvss3_base_vector"})
        candidates = []
        for vector in vectors:
            if vector.startswith("CVSS:3.1/"):
                try:
                    candidates.append((float(CVSS3(vector).base_score), vector))
                except CVSS3Error as exc:
                    raise AppError("invalid_cvss", f"Resultado {index}: vector CVSS 3.1 inválido.") from exc
        best = max(candidates, default=(None, None), key=lambda candidate: candidate[0])
        raw = result.findtext("severity", "").strip()
        try:
            severity = float(raw) if raw else None
        except ValueError as exc:
            raise AppError("invalid_severity", f"Resultado {index}: severidad inválida.") from exc
        if severity is not None and (not math.isfinite(severity) or not -3 <= severity <= 10):
            raise AppError("invalid_severity", f"Resultado {index}: severidad fuera de rango.")
        nvt = result.find("nvt")
        findings.append(ParsedFinding(external_id, host, name, nvt.get("oid", "") if nvt is not None else "", result.findtext("port", ""), result.findtext("description", ""), severity, best[0], best[1], tuple(sorted(cves)), tuple(sorted(set(vectors)))))
    if len({cve for finding in findings for cve in finding.cves}) > 10_000:
        raise AppError("cve_limit", "El reporte supera 10.000 CVE únicos.")
    return ParsedReport(tuple(findings), {
        "scanner_version": root.findtext(".//gmp/version", "no indicada"),
        "filters": root.findtext(".//filters/term", "no indicados"),
        "scope_warning": "Solo se importan los resultados incluidos en el archivo; el escaneo puede estar filtrado o paginado.",
        "compatibility": "Adaptador inicial pendiente de contrastar con el XML real de T07.",
    })
