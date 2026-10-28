# Verificación del incremento 0.1

## Correcciones verificadas — 28 de octubre de 2026

- Entorno `backend/.venv` reparado para usar el intérprete Python 3.14 disponible; `python -m pip check` no detecta dependencias incompatibles.
- Backend: **65 pruebas aprobadas**, incluidas regresiones de orden original, paginación, reimportación y recuperación de posiciones en reportes existentes. Persisten avisos de obsolescencia de Starlette y configuración Alembic.
- Frontend: **17 pruebas aprobadas**; TypeScript y compilación Vite correctos tras extraer controles reutilizables y manejo de operaciones.
- Nueva migración `d3e4f5061723`: aplicada a la base SQLite local después de crear un respaldo privado `backend/vulnrisk-before-position-20261028T194628171607.db`. `alembic check` no detecta diferencias con los modelos. Se compararon todas las columnas previas de las tablas de datos contra el respaldo: se conservan los datos y snapshots existentes.
- Las consultas de hallazgos recuperan desde SQL únicamente la revisión más reciente por hallazgo y CVE, conservando el historial persistente.
- README actualizado al motor v0.2, revisión de aplicabilidad, perfiles y endpoints actuales.
- Esta revisión no verifica Docker/PostgreSQL, consultas reales a fuentes externas ni compatibilidad con un XML real.

Registro original: 16 de octubre de 2026. Última revisión: 19 de octubre de 2026. Desarrollo local de un primer incremento del MVP, no evaluación académica.

## Recuperación del diseño y las exportaciones - 19 de octubre de 2026

Se recuperaron del historial el tema oscuro inspirado en el portfolio y las exportaciones PDF/CSV, conservando JSON y las correcciones de la primera revisión. Estos cambios habían sido aplicados a una copia anterior en Downloads y no estaban incluidos en la carpeta RiskEngine actual. No se añadió exportación XML, conforme a la aclaración del usuario.

| Comprobación | Resultado observado |
|---|---|
| Suite backend | **49 pruebas aprobadas**. Incluye formatos, autorización, alcance de auditoría, snapshots, protección de celdas CSV y textos largos en PDF. |
| Suite de interfaz | **11 pruebas aprobadas**. Incluye botones PDF/CSV/JSON, contenido binario, errores de descarga y las regresiones anteriores. |
| TypeScript y compilación Vite | **Correctos**; tema oscuro compilado en `frontend/dist`. |
| PDF sintético | **5 páginas renderizadas y revisadas visualmente**: resumen, tres fichas y método. Índices comprobados: 98, 75 y pendiente. |
| Navegador | Acceso a una instancia temporal, apertura de auditoría sintética, selección de ejecución y presencia de los tres botones comprobados. No se utilizó la base de trabajo. |
| Datos existentes | No se modificaron `.env`, las auditorías ni la base de trabajo. |

Para activar el backend actualizado hay que reiniciar su proceso. Después se recarga Firefox con `⌘ + Shift + R`; las ejecuciones ya guardadas admiten los nuevos formatos sin recalcular.

## Correcciones iniciales del 19 de octubre de 2026

Se corrigieron la inclusión de `backend/.venv` en el empaquetado, la mezcla de selección y hallazgos ante errores de carga en la interfaz, y las instrucciones del entorno Python. El entorno de desarrollo usa `backend/.venv`; se conservaron el nombre del paquete y el bloque de autor del README.

| Comprobación | Resultado observado |
|---|---|
| Suite backend con pytest | **36 pruebas aprobadas**, incluidas dos nuevas de empaquetado. |
| Pruebas de interfaz con Vitest y DOM simulado | **4 pruebas aprobadas**: cambios exitosos, fallos al cargar reportes o auditorías y auditorías vacías. Las consultas API están controladas. |
| TypeScript estricto y compilación Vite | **Correctos**, con la interfaz compilada en `frontend/dist`. |
| Dependencias Python: `pip check` | **Sin incompatibilidades detectadas**. |
| Empaquetado de la carpeta actual | ZIP temporal de **51 archivos**, con integridad verificada y sin `.venv` ni `node_modules`. No se sobrescribió una entrega anterior. |
| Datos privados | Las pruebas del backend se ejecutaron con carga de `.env` desactivada y bases temporales. No se modificaron la configuración privada ni la base de trabajo. |

La suite del backend mantiene tres avisos de obsolescencia de dependencias: TestClient de Starlette con httpx y dos avisos de configuración de Alembic. No hay pruebas fallidas. Estas comprobaciones no acreditan ejecución con PostgreSQL, consultas reales de EPSS/KEV ni compatibilidad con un XML real.

## Comprobaciones originales del 16 de octubre de 2026

| Comprobación | Resultado observado |
|---|---|
| Suite backend con pytest | **34 pruebas aprobadas**, 2,37 segundos en la última ejecución completa. |
| TypeScript estricto y compilación Vite | **Correctos**; paquete de interfaz generado en `frontend/dist`. |
| Migración inicial Alembic sobre SQLite | **Aplicada correctamente**. |
| Coherencia migración/modelos: `alembic check` | **Sin nuevas operaciones pendientes**. También cubierta por una prueba contra una base temporal. |
| Auditoría npm de dependencias de producción | **0 vulnerabilidades notificadas** en esa consulta. No es una auditoría integral de seguridad. |
| Navegador: carga de interfaz, acceso y creación de auditoría | **Comprobados** en una instancia local aislada con datos de prueba. |
| Navegador: carga de archivo y recorrido hasta el ranking | **No completados**: la interacción quedó interrumpida al seleccionar el XML. El recorrido API sí está cubierto por pruebas automatizadas. |
| PostgreSQL / Docker Compose | **No ejecutados**: el daemon Docker no estaba en funcionamiento. |
| EPSS / KEV reales | Adaptadores implementados; **no se acredita una consulta real exitosa**. Las pruebas utilizan respuestas controladas. |
| XML de un escaneo real | **Pendiente de T07**. Solo se utilizaron fixtures identificados como sintéticos. |

En esa ejecución, pytest mostró tres avisos de obsolescencia de dependencias: TestClient de Starlette con httpx y la configuración de separación de rutas de Alembic. No hubo pruebas fallidas. No se ocultaron los avisos; deberán revisarse al actualizar esas dependencias.

## Comportamiento cubierto por las pruebas

- Datos ausentes con peso activo no se convierten en prioridad cero.
- EPSS de cero y KEV falso conocidos siguen siendo entradas válidas.
- Rechazo de pesos, rangos y configuraciones inválidos.
- Cálculo determinista del motor puro con entradas fijas y efecto del contexto.
- Importación de tres observaciones sintéticas, incluidas una sin CVE y dos con CVSS 3.1 calculado desde vector.
- Reimportación secuencial y concurrente sin duplicar la importación lógica ni sus hallazgos.
- Rechazo de XML malformado, DTD/entidad externa, IDs repetidos y campos obligatorios ausentes sin persistencia parcial.
- Reporte vacío válido y conservación de severidad sin inventar una versión CVSS.
- Restricciones de base de datos que impiden asociar un hallazgo con un activo de otra auditoría.
- Snapshots de resultados, exportación de evidencia y conservación de ejecuciones anteriores tras editar contexto o fuentes.
- Datos externos antiguos tratados como no admisibles según la política explícita.
- Autorización por clave, validación de seguimiento y alcance de importaciones por auditoría.
- Fallos de fuentes externas, ausencia de EPSS y catálogo KEV incompleto sin fabricar valores cero o falsos.
- Migración inicial y límites de carga.
- Exclusión de entornos Python, dependencias frontend, datos privados y enlaces simbólicos del ZIP.
- Coherencia de auditoría, reporte y hallazgos de la interfaz cuando una carga falla.

## Qué no demuestra esta verificación

No demuestra que la fórmula experimental mejore CVSS, que el sistema detecte vulnerabilidades por sí mismo, que un activo del fixture esté realmente afectado ni que el software esté listo para exposición pública. La validación académica requiere modelo v1, referencia independiente, casos reales, piloto y evaluación final conforme a T04–T05.

## Reproducción

Consultar `README.md` para instalar y ejecutar. La suite usa respuestas externas controladas y no escanea redes. `requirements.lock` y `frontend/package-lock.json` conservan las versiones utilizadas.

El archivo ZIP de entrega excluye `.env`, las bases locales, los datos de la instancia de prueba, entornos virtuales, caches y `node_modules`. Incluye código, pruebas, documentación y la interfaz compilada. Cada instalación genera sus propias claves mediante `scripts/setup.py`.
