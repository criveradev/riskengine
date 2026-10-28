# RiskEngine

Proyecto independiente basado en el código original de VulnRisk. Las referencias de procedencia se conservan en `CONTINUAR_EN_CHAT_NUEVO.md` y `MANIFIESTO_COPIA.json`; este último describe la copia original, no el estado actual.

Primer incremento funcional del MVP: importar un reporte XML de Greenbone, conservar sus hallazgos, registrar el contexto del activo y generar una priorización explicable con entradas congeladas.

React y TypeScript en la interfaz; FastAPI en el backend; SQLAlchemy y migraciones Alembic. SQLite permite probar localmente sin servidor de base de datos. La configuración Docker utiliza PostgreSQL. El escáner queda fuera de la aplicación.

## Estado y alcance

- Auditorías, importaciones idempotentes y hallazgos paginados.
- Hallazgos sin CVE y asociaciones de varios CVE; XML inválido rechazado sin guardados parciales.
- Contexto de criticidad y exposición por activo; seguimiento abierto/en revisión/resuelto.
- Consulta explícita de EPSS y KEV con fuentes, fechas y estados de error.
- Motor puro y versionado, ejecuciones con snapshots y descargas PDF, CSV y JSON.
- Tema oscuro con fondos grafito, paneles translúcidos y acentos naranja.
- Acceso con clave compartida para un laboratorio local de un usuario.

La fórmula implementada es **una candidata experimental**, no la fórmula académica aprobada. No hay pesos predeterminados: el usuario los indica y confirma su carácter experimental. El adaptador XML se comprobó con fixtures sintéticos; falta validarlo con el archivo real de T07. Este incremento no acredita la finalización de H5–H7 ni una validación académica.

## Requisitos

Para publicar en Render con PostgreSQL en Neon y el subdominio `riskengine.criveradev.com`, consulta [la guía de despliegue](docs/DESPLIEGUE.md).

- Python 3.12 o posterior y Node.js 22.12 o posterior, con npm.
- Para la alternativa Docker: Docker Engine/Desktop y Compose en funcionamiento.
- Internet para instalar dependencias y consultar fuentes. La importación y los cálculos que no requieren fuentes externas funcionan sin consultar Internet.

## Instalación local

Desde esta carpeta, crea la configuración y el entorno. `setup.py` genera claves aleatorias en `.env` sin mostrarlas; conserva un archivo existente.

```bash
python3 scripts/setup.py
python3 -m venv backend/.venv
source backend/.venv/bin/activate
python -m pip install -r backend/requirements.lock
python -m pip install --no-deps -e backend
```

Si ya existe `backend/.venv`, activa ese entorno y omite su creación. En PyCharm selecciona `backend/.venv/bin/python` como intérprete del proyecto y del módulo del backend.

En Windows utiliza `py -3.12` o tu ejecutable Python y activa con `backend\.venv\Scripts\Activate.ps1` en PowerShell. Después usa `python` para los comandos del entorno.

Compila la interfaz:

```bash
cd frontend
npm ci
npm run build
cd ../backend
alembic upgrade head
uvicorn riskengine.main:app --host 127.0.0.1 --port 8000
```

Abre **http://127.0.0.1:8000**. Entra con el valor de `RISKENGINE_API_TOKEN` de `.env`. No publiques ese archivo. La clave se guarda en `sessionStorage` durante la sesión del navegador y se elimina con «Salir».

Para desarrollar la interfaz sin recompilar, ejecuta `npm run dev` desde `frontend` en otra terminal, manteniendo el backend en el puerto 8000. Abre http://127.0.0.1:5173. Vite reenvía `/api` al backend; no se habilita CORS abierto.

## Ejecutar desde PyCharm

Después de la instalación local, abre la carpeta raíz `riskengine` como proyecto y selecciona `backend/.venv/bin/python` como intérprete en **Settings → Python → Interpreter**. Debe usar Python 3.12 o superior.

La configuración compartida `.run/RiskEngine.run.xml` aparece como **RiskEngine** en el selector de ejecución. Usa el módulo `uvicorn`, los parámetros `riskengine.main:app --host 127.0.0.1 --port 8001 --reload` y el directorio de trabajo `backend`. Pulsa **Run** y abre **http://127.0.0.1:8001**. La aplicación carga automáticamente el `.env` de la raíz.

Esta configuración sirve la interfaz compilada en `frontend/dist`. Cuando cambies React o los estilos, ejecuta `npm run build` desde `frontend` y recarga el navegador. Para usar Vite en desarrollo con este puerto, ajusta el destino del proxy de `frontend/vite.config.ts` a `http://127.0.0.1:8001`.

## Primer recorrido de comprobación

1. Crea una auditoría con su alcance.
2. Descarga desde la interfaz el XML **sintético** o utiliza `backend/tests/fixtures/synthetic-greenbone.xml`.
3. Impórtalo: contiene tres resultados ficticios y dos activos. No es un escaneo ni acredita vulnerabilidades de esos activos.
4. En «Contexto y fuentes», registra niveles exploratorios de 1 a 5 por activo si necesitas esas entradas. Desconocido no se transforma en cero.
5. Para probar solamente el recorrido con CVSS, configura pesos `CVSS=1` y los otros cuatro en `0`. Indica explícitamente la antigüedad admisible de fuentes y confirma el carácter experimental. Esto reproduce CVSS reescalado; no demuestra mejora contextual.
6. Con el fixture, los índices esperados en ese recorrido son 98, 75 y un resultado pendiente por falta de CVSS comparable. Son salidas técnicas de un ejemplo sintético, no resultados de validación.
7. Prueba después una configuración contextual que tú documentes. Los pesos deben sumar uno. Su elección y las escalas deben cerrarse antes de la evaluación final.
8. Selecciona una ejecución guardada y utiliza «Descargar PDF», «Descargar CSV» o «Descargar JSON». El PDF contiene un resumen y fichas legibles; el CSV permite revisar la tabla en una hoja de cálculo; el JSON conserva la evidencia completa. Los tres usan los datos guardados de esa ejecución. Un índice pendiente queda vacío en el CSV, nunca se convierte en cero. Cambiar el contexto del activo no reescribe una ejecución anterior.

Reimportar el mismo archivo en la misma auditoría reutiliza la importación. Otro archivo se conserva como otra observación: no se deduplica únicamente por CVE. En esta versión, la identidad del activo usa el host informado dentro de la auditoría; cambios de IP y reconciliación de identidades quedan pendientes.

## Modelo experimental

Versión: `weighted-context-experimental-v0.2`.

```text
índice = 100 × suma(peso × entrada_normalizada)
CVSS = Base 3.1 / 10
EPSS = puntuación disponible en [0, 1]
KEV = 1 si pertenece, 0 si se verificó que no pertenece
criticidad = (nivel − 1) / 4
exposición = (nivel − 1) / 4
```

CVSS se calcula mediante la biblioteca `cvss` a partir de vectores explícitos `CVSS:3.1/...`. Si hay varios, se conserva el máximo Base 3.1 y su vector. Una severidad numérica sin versión no se presenta como CVSS comparable; permanece como severidad original.

EPSS y KEV requieren revisar la aplicabilidad de todas las referencias CVE de cada hallazgo desde su detalle. Mientras quede una referencia pendiente, ambas entradas permanecen desconocidas. Las revisiones se conservan como historial; el nombre del revisor es declarado, no una identidad autenticada.

Una vez completada la revisión, solo se consideran los CVE marcados como aplicables. EPSS utiliza el máximo si todos los aplicables tienen un valor admisible; KEV es verdadero si alguno tiene pertenencia conocida, falso si todos tienen no pertenencia conocida y desconocido en los demás casos. Un hallazgo sin CVE aplicables no dispone automáticamente de EPSS o KEV. Estas son reglas de la candidata experimental, pendientes de aprobación académica. Las ejecuciones anteriores conservan sus entradas y su política original.

La interfaz ofrece perfiles experimentales de CVSS solo, cinco pesos iguales y ROC, además de pesos personalizados. La comparación de perfiles reutiliza las entradas congeladas y muestra su cobertura; no acredita superioridad sin una referencia independiente. Los resultados con severidad original negativa quedan pendientes de revisión, cualquiera que sea la configuración de pesos.

Si falta una entrada con peso positivo, no se calcula el índice: se guarda un motivo. Un peso cero desactiva explícitamente esa entrada. No hay umbrales de niveles de riesgo ni probabilidad calibrada. La fórmula y los pesos deben evaluarse; no se presupone que una combinación lineal sea el modelo definitivo.

Las evidencias deben tener fecha admisible según la antigüedad indicada por el usuario. Un error de actualización no se convierte en cero ni produce una sustitución silenciosa por datos antiguos. Cada ejecución conserva copia de lo utilizado.

## Variables de entorno

| Variable | Uso |
|---|---|
| `RISKENGINE_API_TOKEN` | Clave de al menos 32 caracteres, generada por `setup.py`. Obligatoria. |
| `DATABASE_URL` | Local: `sqlite:///./riskengine.db`, relativa al directorio de ejecución del backend. PostgreSQL: URL con driver `postgresql+psycopg`. |
| `POSTGRES_PASSWORD` | Contraseña generada para la alternativa Compose. No se utiliza en SQLite. |

Las variables ya definidas en el entorno tienen prioridad sobre `.env`. No copies las claves a la configuración pública del frontend ni al código.

## Endpoints principales

La documentación interactiva está en `/docs`. Los recursos de `/api` requieren `Authorization: Bearer <clave>`. `/health` expone solo estado y versión.

| Método | Recurso | Función |
|---|---|---|
| GET / POST | `/api/audits` | Listar o crear auditorías. |
| GET / POST | `/api/audits/{id}/imports` | Listar o cargar XML multipart con campo `file`. |
| GET | `/api/audits/{id}/findings` | Listar; filtros `import_id`, `limit` y `offset`. |
| GET | `/api/audits/{id}/assets` | Listar activos. |
| PATCH | `/api/audits/{id}/assets/{asset_id}` | Actualizar contexto. |
| PATCH | `/api/audits/{id}/findings/{finding_id}` | Actualizar seguimiento. |
| POST | `/api/audits/{id}/findings/{finding_id}/cves/{cve}/reviews` | Registrar revisión de aplicabilidad CVE. |
| POST | `/api/audits/{id}/enrichments` | Consultar EPSS y KEV; máximo 500 CVE únicos por auditoría. |
| GET / POST | `/api/audits/{id}/runs` | Listar o ejecutar priorización de una importación. |
| GET | `/api/audits/{id}/runs/{run_id}/results` | Consultar resultados paginados y configuración. |
| GET | `/api/audits/{id}/runs/{run_id}/comparison` | Comparar perfiles sobre las entradas congeladas. |
| GET | `/api/audits/{id}/runs/{run_id}/export` | Descargar toda la ejecución en JSON, PDF o CSV. |

La exportación admite `?format=json` (predeterminado), `?format=pdf` y `?format=csv`, con la misma clave de acceso. El CSV utiliza UTF-8 con BOM y neutraliza textos importados que una hoja de cálculo podría interpretar como fórmulas.

Los hallazgos admiten búsqueda `q` por nombre, CVE, host o puerto y orden `sort` (`original`, `name`, `cvss_desc`, `cvss_asc`, `host`). El orden original conserva la posición de los resultados dentro del XML; la migración recupera esa posición para los reportes ya importados sin modificar snapshots históricos.

La carga devuelve 201 al crear y 200 al reutilizar. Errores de entrada: 422; acceso: 401; recurso ajeno a la auditoría: 404; límite: 413; conflicto: 409. Los errores tienen un objeto `error` con `code` y `message`; las respuestas API incluyen identificador de solicitud.

## Pruebas y comandos

Desde `backend` con el entorno activado:

```bash
python -m pytest -q
alembic check
```

Desde `frontend`:

```bash
npm test
npm run build
```

Las pruebas de interfaz cubren cambios de reporte y auditoría, fallos de carga, botones de exportación y descargas binarias. Las pruebas del backend cubren formatos, autorización, resultados congelados y protección de celdas CSV. El empaquetador se prueba con archivos sintéticos para excluir entornos, datos privados y enlaces simbólicos.

Las pruebas no escanean redes ni consultan EPSS/KEV: las respuestas externas se controlan para comprobar fallos y datos ausentes de forma determinista. La migración inicial se prueba contra SQLite y se comprueba su correspondencia con el modelo. Revisar `VALIDACION.md` para el resultado real de las verificaciones de esta entrega.

## Estructura

```text
backend/riskengine/domain.py      Motor puro y errores de aplicación
backend/riskengine/parser.py      Adaptador XML seguro
backend/riskengine/enrichment.py  Adaptadores EPSS y KEV
backend/riskengine/services.py    Orquestación y snapshots
backend/riskengine/repository.py  Acceso a datos y transacciones
backend/riskengine/models.py      Persistencia y restricciones
backend/riskengine/api.py         Rutas, validación y control de acceso
backend/riskengine/exports.py     Informes PDF y tablas CSV de ejecuciones guardadas
backend/migrations/            Migraciones Alembic versionadas
backend/tests/                 Pruebas y fixtures sintéticos
frontend/src/                  Interfaz React y TypeScript
scripts/setup.py               Configuración local y ejemplo descargable
scripts/package_source.py      ZIP de entrega sin entornos ni datos privados
```

## Docker y PostgreSQL

Después de ejecutar `python scripts/setup.py`, puedes usar:

```bash
docker compose up --build
```

Compose publica la aplicación únicamente en `127.0.0.1:8000`, no publica PostgreSQL y conserva la base en un volumen. El proceso aplica migraciones antes de iniciar un único trabajador. Entra con la misma clave de `.env`.

**Esta alternativa requiere comprobación en un Docker Engine activo.** No se ha verificado una ejecución real de PostgreSQL en el entorno de esta entrega. La opción local con SQLite permite verificar el incremento mientras se prepara ese entorno.

## Límites y siguiente incremento

- Aplicación local de un usuario: la clave compartida autoriza todo el laboratorio. No hay usuarios individuales, roles, sesiones revocables ni aislamiento entre organizaciones. No se presenta como servicio listo para Internet.
- Límite de archivo: 10 MiB; 10.000 resultados, 100 CVE por resultado, 10.000 CVE únicos, profundidad 48 y 100.000 nodos. El parser no admite DTD, entidades externas ni variantes XML con namespaces en esta versión.
- Las escrituras de una importación y de una ejecución son atómicas. Los fallos se registran como eventos operativos; no hay todavía una tabla persistente de intentos fallidos o trabajos en curso.
- El límite de solicitudes es local al proceso, 120 por minuto por dirección. No es un control distribuido. El enriquecimiento es síncrono, sin colas ni reintentos automáticos. Las fuentes tienen destinos fijos y respuestas acotadas.
- Pendientes: XML real T07, pruebas sobre PostgreSQL, identidad del activo más allá de su host, modelo académico v1, referencia independiente y cálculo de métricas T04–T05 con casos reales. NVD no está integrado.
- No hay escaneo, explotación, remediación automática ni resultados de validación académica. La evaluación seguirá separando piloto y conjunto final.
- El despliegue remoto, cuentas individuales, TLS y endurecimiento operativo corresponden a un incremento posterior con requisitos concretos.

### 👨🏻‍💻 Developed by

<p align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://res.cloudinary.com/docscluster/image/upload/v1782698757/logo-dark_qddsa3.svg">
    <source
      media="(prefers-color-scheme: light)"
      srcset="https://res.cloudinary.com/docscluster/image/upload/v1782698757/logo-light_wilpp4.svg">
    <img
      alt="criveradev"
      src="https://res.cloudinary.com/docscluster/image/upload/v1782698757/logo-light_wilpp4.svg"
      width="200">
  </picture>
</p>
