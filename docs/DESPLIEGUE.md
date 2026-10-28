# Despliegue de RiskEngine: Render + Neon

Destino propuesto: `https://riskengine.criveradev.com`. El frontend y FastAPI se sirven juntos desde un contenedor Docker en Render; PostgreSQL se aloja en Neon. Vercel no se utiliza en esta configuración.

## 1. PostgreSQL en Neon

Crea una base dedicada a RiskEngine. En **Connect**, copia la URL de conexión directa (sin pooling) y conserva sus parámetros TLS, incluidos `sslmode=require` y `channel_binding=require` si aparecen. No subas esta URL al repositorio ni la pegues en una incidencia pública.

Render solicitará la URL como variable secreta `DATABASE_URL`. Se admiten los prefijos `postgresql://`, `postgres://` y `postgresql+psycopg://`; la aplicación y Alembic seleccionan el driver Psycopg 3 instalado. Ejemplo ficticio:

```text
postgresql://USUARIO:CLAVE@HOST.neon.tech/BASE?sslmode=require&channel_binding=require
```

Mantén los caracteres escapados de la URL que entrega Neon. No copies el comando `psql` completo ni las comillas. Elige la región de Render más cercana a la región de Neon al crear el servicio.

## 2. Aplicación en Render

1. Conecta el repositorio de GitHub desde **New → Blueprint**.
2. Render leerá `render.yaml` y usará el Dockerfile de la raíz.
3. Introduce `DATABASE_URL` con la conexión de la base dedicada de Neon.
4. El Blueprint genera una clave nueva `RISKENGINE_API_TOKEN`. Consulta su valor en las variables del servicio para iniciar sesión en la aplicación.
5. Revisa el plan **Free** seleccionado en el archivo y crea el servicio. Este plan puede suspenderse por inactividad; es apropiado para la primera demostración, no garantiza disponibilidad continua.

El arranque ejecuta `alembic upgrade head` antes de iniciar Uvicorn. Se utiliza una sola instancia. El proceso escucha en `0.0.0.0` y en el puerto `PORT` que indica Render. `/health` es la ruta de comprobación del servicio. Si la migración falla, el servidor no arranca; revisa los registros antes de reintentar. Para cambios posteriores, conserva un respaldo de Neon antes de aplicar migraciones.

El contenedor compila React automáticamente. No configures `DATABASE_URL` ni la clave de acceso como variables `VITE_*`: solo las necesita el backend. Render exige PostgreSQL; no se permite caer accidentalmente en una base SQLite efímera.

## 3. Dominio en Cloudflare

El Blueprint propone `riskengine.criveradev.com`; comprueba que aparezca en **Settings → Custom Domains** del servicio de Render. En Cloudflare, agrega este registro:

| Campo | Valor |
| --- | --- |
| Tipo | CNAME |
| Nombre | riskengine |
| Destino | El hostname real `…onrender.com` que asigne Render, sin `https://` |
| Proxy | DNS only al verificar y emitir el certificado |
| TTL | Auto |

El destino no se puede conocer antes de crear el servicio. Si ya existe un registro para ese subdominio, revisa su uso antes de sustituirlo. Verifica el dominio en Render y espera a que el certificado sea válido. No es necesario cambiar los registros de `criveradev.com` ni de `www`.

## 4. Comprobación del primer despliegue

1. Comprueba que `/health` responde correctamente en el hostname de Render y en el dominio personalizado.
2. Inicia sesión con la clave generada en Render.
3. Crea una auditoría de prueba e importa el XML sintético disponible en la interfaz.
4. Verifica la consulta de hallazgos, guarda una ejecución y descarga PDF, CSV y JSON.
5. Reinicia el servicio y comprueba que los datos siguen en Neon.

El acceso actual utiliza una clave compartida: quien la tenga accede al mismo conjunto de auditorías. Este despliegue inicial está pensado para uso personal con acceso restringido por esa clave. Si se incorporan usuarios independientes, habrá que implementar cuentas, permisos y aislamiento de datos.

## Referencias

- [Blueprints de Render](https://render.com/docs/blueprint-spec)
- [Limitaciones del plan gratuito](https://render.com/docs/free)
- [Cloudflare DNS para Render](https://render.com/docs/configure-cloudflare-dns)
- [SQLAlchemy con Neon](https://neon.com/docs/guides/sqlalchemy)

Verificación local del 28 de octubre de 2026: 71 pruebas de backend, 17 de frontend y compilación de producción aprobadas. En PostgreSQL 16 temporal con UTF-8 se comprobaron migraciones, correspondencia del esquema, importación XML sintética, cálculo, exportaciones PDF/CSV/JSON y persistencia al recrear la aplicación. Esto no acredita una conexión real a Neon ni un despliegue en Render; esas comprobaciones se completan con las cuentas y la base elegidas.
