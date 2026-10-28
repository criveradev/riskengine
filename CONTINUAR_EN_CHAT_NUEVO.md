# Copia base para un proyecto independiente

Esta copia parte del código actual de VulnRisk. El proyecto de tesis original se conserva por separado. Extraer este ZIP en una carpeta diferente y trabajar solamente en esa copia, sin reutilizar la base ni las claves de la tesis.

## Contexto para continuar en un chat nuevo

Quiero convertir esta copia en un proyecto independiente para crear un repositorio y desplegarlo. Definir un nombre nuevo y otra paleta de colores. Adaptar la marca, los textos y la configuración. Mantener la atribución y referencias que correspondan al código original.

Usar PostgreSQL para el proyecto desplegable. La copia incluye compose.yaml con PostgreSQL 17, psycopg y migraciones Alembic. Deben comprobarse las migraciones y el flujo completo contra PostgreSQL: esta copia no acredita un despliegue validado. El código actual también admite SQLite.

Preparar configuración por entorno, instalación reproducible, pruebas, documentación y despliegue. El acceso actual es personal, mediante correo y contraseña; no hay registro público. El repositorio público está en GitHub, el frontend en Vercel, la API en Render y PostgreSQL en Neon.

La marca actual es RiskEngine y la paleta usa grafito y naranja. El paquete Python es `riskengine`. El acceso personal se configura con `RISKENGINE_ADMIN_EMAIL` y `RISKENGINE_ADMIN_PASSWORD`; la antigua clave compartida ya no da acceso. El dominio público es riskengine.criveradev.com y el repositorio es github.com/criveradev/riskengine. El índice sigue siendo experimental; no atribuir al proyecto una validación de riesgo ni eficacia que no se haya medido.

## Contenido

Backend, frontend, pruebas, migraciones, dependencias fijadas, Dockerfile, Compose y documentación técnica. Solo se incluye el XML sintético de pruebas. Se excluyen .env, bases y respaldos, entornos Python, node_modules, compilados, historial Git, archivos del IDE, documentos de tesis y reportes reales del laboratorio.

MANIFIESTO_COPIA.json contiene los hashes de los archivos incluidos. Las fechas de los archivos fuente se conservan en sus entradas del ZIP.
