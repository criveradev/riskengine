# Revisión de aplicabilidad CVE

Versión del motor: weighted-context-experimental-v0.2.

En Hallazgos, abre «Revisar aplicabilidad de CVE». Registra cada referencia como pendiente, aplicable o no aplicable, con responsable declarado y justificación basada en producto, versión, configuración y fuente. El token compartido autentica el acceso; el nombre escrito no equivale a identidad verificada.

Las referencias originales del XML se conservan. Cada decisión se agrega al historial de la base de datos; la interfaz muestra la última. Una nueva ejecución congela las decisiones utilizadas junto con sus entradas y evidencias.

EPSS y KEV solo se agregan sobre referencias aplicables después de revisar todas las referencias del hallazgo. Si existe alguna pendiente o ninguna aplicable, ambas entradas son desconocidas. No se convierten en cero. Los perfiles con peso positivo para esas entradas quedan pendientes; CVSS solo sigue funcionando cuando existe un CVSS 3.1 admitido. La evidencia técnica local permanece visible incluso sin CVE aplicable.

La consulta de fuentes puede seguir recuperando datos para referencias sin revisar, pero esos datos no se utilizan hasta resolver su aplicabilidad. Una revisión no modifica la vigencia de la fuente ni transforma evidencias ausentes en conocidas.

Las ejecuciones históricas y sus comparaciones siguen usando sus datos congelados y su política original. No constituyen una revisión retroactiva de aplicabilidad. Genera una nueva ejecución para utilizar las decisiones.

API: POST /api/audits/{audit_id}/findings/{finding_id}/cves/{cve}/reviews. Cuerpo: status (pending, applicable o not_applicable), reviewer (1–160 caracteres) y rationale (1–3000). Devuelve 201, 404 si la referencia no pertenece al hallazgo/auditoría, 422 si los datos no son válidos y 401 sin autenticación.

La migración c2d3e4f50612 agrega cve_reviews. No marca referencias existentes como confirmadas y no modifica resultados anteriores. Requiere reiniciar el backend y cargar la interfaz compilada actualizada.
