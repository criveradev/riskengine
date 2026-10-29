<div align="center">

# RiskEngine

**Priorización explicable de vulnerabilidades**

Convierte reportes de Greenbone en prioridades trazables, incorporando el contexto de los activos y fuentes de inteligencia de vulnerabilidades.

[Aplicación web](https://riskengine-ochre.vercel.app) · [Reportar un problema](https://github.com/criveradev/riskengine/issues) · [Guía de despliegue](docs/DESPLIEGUE.md)

</div>

## Acerca del proyecto

La severidad técnica es una parte de la decisión de remediación. RiskEngine permite analizar hallazgos junto con la criticidad y la exposición de los activos, consultar EPSS y el catálogo KEV, y conservar la evidencia utilizada en cada ejecución.

La aplicación reúne la gestión de auditorías, la importación de reportes, la revisión de referencias CVE y la exportación de resultados en una interfaz con tema oscuro. Cada ejecución guarda sus entradas y configuración para que los resultados puedan revisarse sin depender del estado actual de las fuentes.

El motor de priorización es experimental: sus resultados son índices comparativos, no probabilidades calibradas ni una validación de superioridad frente a CVSS. La aplicación analiza reportes existentes; no realiza escaneos ni remediaciones automáticas.

## Funcionalidades

- **Auditorías y hallazgos:** organización por alcance, búsqueda, ordenamiento, paginación y seguimiento abierto, en revisión o resuelto.
- **Importación de Greenbone:** carga XML con validación y transacciones atómicas. Reimportar el mismo archivo en una auditoría reutiliza la importación existente.
- **Contexto por activo:** registro de criticidad y exposición para incorporar información del entorno a la priorización.
- **Inteligencia de vulnerabilidades:** consulta explícita de EPSS y KEV, con fuentes, fechas y estados de error visibles.
- **Revisión de CVE:** evaluación de aplicabilidad por hallazgo e historial de revisiones.
- **Motor explicable:** perfiles experimentales, pesos personalizados y comparación de perfiles sobre las mismas entradas congeladas.
- **Evidencia reproducible:** snapshots por ejecución y exportación en PDF, CSV y JSON.
- **Acceso personal:** cuenta única con correo y contraseña, sesiones revocables y sin registro público.

## Tecnologías

| Capa | Tecnologías |
| --- | --- |
| Interfaz | React 19, TypeScript, Vite |
| API | Python, FastAPI, Uvicorn |
| Persistencia | SQLAlchemy 2, Alembic, PostgreSQL / SQLite |
| Procesamiento | defusedxml, biblioteca CVSS, HTTPX |
| Informes | ReportLab, exportaciones CSV y JSON |
| Pruebas | pytest, Vitest, jsdom |
| Despliegue | Docker Compose, Vercel, Render, Neon |

## Arquitectura

La interfaz consume una API FastAPI. Los servicios coordinan la importación, el enriquecimiento y las ejecuciones; el motor de cálculo se mantiene separado de HTTP, persistencia y fuentes externas.

```text
frontend/                     Interfaz React y TypeScript
backend/
├── riskengine/
│   ├── api.py                Rutas, validación y control de acceso
│   ├── domain.py             Motor de priorización y reglas de dominio
│   ├── parser.py             Adaptador XML de Greenbone
│   ├── enrichment.py         Adaptadores EPSS y KEV
│   ├── services.py           Orquestación y snapshots
│   ├── repository.py         Acceso a datos y transacciones
│   ├── models.py             Modelos y restricciones de persistencia
│   └── exports.py            Informes PDF y tablas CSV
├── migrations/               Migraciones Alembic
└── tests/                    Pruebas y fixtures sintéticos
scripts/                      Configuración y empaquetado del código
docs/                        Documentación técnica y despliegue
```

SQLite permite ejecutar el proyecto localmente sin un servidor de base de datos. Docker Compose utiliza PostgreSQL. El despliegue documentado separa la interfaz en Vercel, la API en Render y la base de datos en Neon.

## Instalación local

### Requisitos

- Python 3.12 o posterior.
- Node.js 22.12 o posterior y npm.
- Docker y Docker Compose, si se utiliza la alternativa con contenedores.
- Conexión a Internet para instalar dependencias y consultar EPSS y KEV.

### 1. Preparar el proyecto

```bash
git clone https://github.com/criveradev/riskengine.git
cd riskengine
python3 scripts/setup.py
python3 -m venv backend/.venv
source backend/.venv/bin/activate
python -m pip install -r backend/requirements.lock
python -m pip install --no-deps -e backend
python scripts/configure_admin.py
```

En Windows, crea el entorno con `py -3.12 -m venv backend/.venv` y actívalo con `backend\.venv\Scripts\Activate.ps1` en PowerShell.

`setup.py` prepara el archivo `.env` y el XML sintético de ejemplo; conserva una configuración existente. `configure_admin.py` solicita las credenciales de la cuenta personal. El archivo `.env` contiene configuración privada y está excluido de Git.

### 2. Compilar la interfaz

```bash
cd frontend
npm ci
npm run build
cd ..
```

### 3. Iniciar la aplicación

Con el entorno Python activado:

```bash
cd backend
alembic upgrade head
uvicorn riskengine.main:app --host 127.0.0.1 --port 8000
```

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000) e inicia sesión con las credenciales configuradas.

### Desarrollo de la interfaz

Para trabajar con recarga automática, mantén la API en el puerto 8000 y ejecuta en otra terminal:

```bash
cd frontend
npm run dev
```

Abre [http://127.0.0.1:5173](http://127.0.0.1:5173). Vite reenvía las solicitudes de `/api` al backend.

### Docker Compose

Después de preparar `.env` y configurar la cuenta personal:

```bash
docker compose up --build
```

La aplicación queda disponible en `http://127.0.0.1:8000`. Compose aplica las migraciones al arrancar, mantiene PostgreSQL en un volumen y no publica el puerto de la base de datos.

## Primer uso

1. Crea una auditoría e indica su alcance.
2. Descarga el XML sintético desde la interfaz e impórtalo para explorar el flujo.
3. Revisa los hallazgos, el contexto de los activos y la aplicabilidad de las referencias CVE.
4. Consulta EPSS y KEV cuando necesites esas entradas.
5. Selecciona un perfil o configura los pesos y la antigüedad admisible de las fuentes.
6. Confirma el carácter experimental del modelo y guarda una ejecución.
7. Consulta sus resultados, compara perfiles y descarga los informes.

El archivo de ejemplo contiene datos ficticios y no representa un escaneo real. Modificar el contexto o actualizar las fuentes no reescribe las ejecuciones anteriores.

## Modelo de priorización

La versión `weighted-context-experimental-v0.2` calcula un índice ponderado:

```text
índice = 100 × suma(peso × entrada_normalizada)
```

| Entrada | Tratamiento |
| --- | --- |
| CVSS | Base 3.1 calculada desde un vector explícito, dividida por 10 |
| EPSS | Puntuación disponible entre 0 y 1 |
| KEV | 1 si pertenece al catálogo; 0 si se verificó que no pertenece |
| Criticidad | Nivel exploratorio de 1 a 5, normalizado como `(nivel − 1) / 4` |
| Exposición | Nivel exploratorio de 1 a 5, normalizado como `(nivel − 1) / 4` |

Los pesos deben sumar uno y no se aplican pesos predeterminados sin elección del usuario. Un peso cero desactiva una entrada. Si falta una entrada con peso positivo, el resultado queda pendiente con un motivo; los datos desconocidos no se convierten en cero.

EPSS y KEV requieren completar la revisión de aplicabilidad de las referencias CVE. Las evidencias deben cumplir la antigüedad máxima configurada. Cada ejecución conserva la versión del motor, la configuración y las entradas utilizadas.

Los perfiles y las escalas necesitan evaluación con una referencia independiente y casos reales. Consulta [la documentación de revisión de CVE](docs/REVISION_CVE.md) para conocer sus reglas de aplicabilidad.

## Configuración

| Variable | Uso |
| --- | --- |
| `DATABASE_URL` | Conexión SQLAlchemy. Por defecto, SQLite local; PostgreSQL utiliza Psycopg 3. |
| `RISKENGINE_ADMIN_EMAIL` | Correo de la única cuenta autorizada. |
| `RISKENGINE_ADMIN_PASSWORD` | Contraseña de configuración; la base de datos almacena un hash scrypt con sal. |
| `RISKENGINE_ALLOWED_ORIGINS` | Orígenes exactos permitidos para operaciones de escritura, separados por comas. |
| `RISKENGINE_SECURE_COOKIE` | Activa cookies Secure y el prefijo `__Host-`; se activa automáticamente en Render. |
| `POSTGRES_PASSWORD` | Contraseña de PostgreSQL para Docker Compose. |

Las variables definidas en el entorno tienen prioridad sobre `.env`. La configuración privada pertenece al backend y no debe incluirse en variables públicas del frontend. Las sesiones caducan a las ocho horas y se revocan al cerrar sesión.

## API

La documentación interactiva de FastAPI está disponible en `/docs`. Los recursos de `/api` requieren una sesión, salvo el inicio de sesión. Las operaciones de escritura también requieren un origen permitido y la cabecera `X-RiskEngine-Request: 1`.

| Recurso | Operaciones principales |
| --- | --- |
| `/api/auth/login`, `/api/auth/me`, `/api/auth/logout` | Inicio, consulta y cierre de sesión |
| `/api/audits` | Consulta y creación de auditorías |
| `/api/audits/{id}/imports` | Importación de reportes XML |
| `/api/audits/{id}/findings` | Consulta de hallazgos y seguimiento por identificador |
| `/api/audits/{id}/assets` | Consulta de activos y actualización de contexto por identificador |
| `/api/audits/{id}/findings/{finding_id}/cves/{cve}/reviews` | Registro de revisión de aplicabilidad |
| `/api/audits/{id}/enrichments` | Consulta de EPSS y KEV |
| `/api/audits/{id}/runs` | Creación y consulta de ejecuciones |
| `/api/audits/{id}/runs/{run_id}/results` | Resultados y configuración |
| `/api/audits/{id}/runs/{run_id}/comparison` | Comparación de perfiles |
| `/api/audits/{id}/runs/{run_id}/export` | Exportación con `format=pdf`, `csv` o `json` |
| `/health` | Estado y versión del servicio |

## Pruebas

Desde `backend`, con el entorno Python activado:

```bash
python -m pytest -q
alembic check
```

Desde `frontend`:

```bash
npm test
npm run build
```

Las suites cubren importaciones, validación XML, autenticación, datos ausentes, snapshots, exportaciones y flujos de interfaz. Utilizan fixtures sintéticos y respuestas controladas de las fuentes externas; no realizan escaneos ni consultas reales a EPSS o KEV. `alembic check` comprueba que el esquema configurado coincide con los modelos.

## Despliegue

La [guía de despliegue](docs/DESPLIEGUE.md) describe la configuración de Vercel, Render y Neon, las variables del backend, el proxy de la API y el dominio personalizado. El servicio de API en el plan gratuito puede requerir tiempo para reactivarse tras un período de inactividad.

## Alcance actual

- Acceso personal con una sola cuenta. No hay registro público, roles ni aislamiento entre organizaciones.
- Importaciones de hasta 10 MiB y 10.000 resultados. El adaptador XML no admite DTD, entidades externas ni variantes con namespaces.
- La identidad de un activo corresponde al host informado dentro de cada auditoría; la reconciliación de cambios de IP queda pendiente.
- Enriquecimiento síncrono, sin colas ni reintentos automáticos. NVD no está integrado.
- El modelo experimental y la compatibilidad con reportes reales requieren evaluación adicional.

### 👨🏻‍💻 Developed by

<p align="center">
  <a href="https://criveradev.com" aria-label="Visitar el portafolio de criveradev">
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
  </a>
</p>
