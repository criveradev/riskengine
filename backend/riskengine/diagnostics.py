"""Explain admission without confusing scanner severity with model inputs."""

def cvss_admission(finding):
    if finding.get("cvss") is not None:
        return {"code": "admitted", "message": "CVSS Base 3.1 admitido por el modelo."}
    versions = set()
    for vector in finding.get("original_vectors") or []:
        if vector.startswith("CVSS:"):
            versions.add(vector.split("/", 1)[0].removeprefix("CVSS:"))
        elif vector.startswith("AV:"):
            versions.add("2.0")
    if versions:
        return {"code": "unsupported_version", "message": "CVSS original " + ", ".join(sorted(versions)) + " no admitido: este perfil requiere un vector Base 3.1 válido."}
    if finding.get("severity") is not None:
        return {"code": "unversioned_severity", "message": "Severidad original disponible, pero sin vector Base 3.1 admisible; no se infiere la versión desde la puntuación."}
    return {"code": "missing_cvss", "message": "Sin severidad original ni vector Base 3.1 admisible."}
