# Información del detector

En Hallazgos, el desplegable «Información del detector» recupera documentación del detector desde el XML original guardado. Funciona también para importaciones existentes; no requiere reimportar ni migrar la base de datos.

La sección «Evidencia del hallazgo», dentro del nombre del hallazgo, mantiene exclusivamente la descripción del resultado del escáner. Un resumen general del detector nunca sustituye esa evidencia ni cambia decisiones de aplicabilidad, puntuaciones o ejecuciones históricas.

Se presentan nombre, OID, familia, versión del detector, resumen, productos afectados, detalles técnicos, impacto, método de detección, solución y referencias web. Los campos ausentes se identifican como no informados. Los textos se muestran en su idioma original.

`GET /api/audits/{audit_id}/findings/{finding_id}/detector` requiere la autenticación existente y verifica que el hallazgo pertenezca a la auditoría. Devuelve `detector` y `source` (nombre y SHA-256 del archivo). Devuelve 404 ante hallazgos ajenos o inexistentes y 409 si el resultado ya no aparece en el XML guardado.

La lectura se realiza al abrir el desplegable; la respuesta queda en memoria mientras el componente está montado. Se analiza el XML completo con los límites y protección contra entidades del importador. No se realizan consultas externas. Los enlaces admitidos utilizan HTTP/HTTPS sin credenciales; los textos se renderizan como texto, no HTML.

Validación del cambio: pruebas de extracción, autorización, aislamiento por auditoría, campos ausentes, XML inseguro, carga diferida, reintento y representación segura. También se contrastó la recuperación con los dos resultados de vsftpd del XML real archivado.
