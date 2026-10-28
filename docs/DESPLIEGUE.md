# Despliegue de RiskEngine: Vercel + Render + Neon

## Distribución

| Componente | Servicio |
| --- | --- |
| Interfaz React y dominio `riskengine.criveradev.com` | Vercel |
| API FastAPI | Render: `https://riskengine-s0dr.onrender.com` |
| PostgreSQL 17 | Neon, región AWS Oregon |
| DNS | Cloudflare |

Render y Neon están desplegados en Oregon. La interfaz utiliza `/api` en su propio dominio. `frontend/vercel.json` reenvía estas solicitudes a Render mediante rewrites externos; no se necesita abrir CORS. La sesión viaja en una cookie HttpOnly, Secure y SameSite=Strict, y el backend devuelve `Cache-Control: no-store` para la API.

## 1. PostgreSQL en Neon

Usa una base dedicada a RiskEngine. En **Connect**, selecciona la conexión directa (sin pooling) y conserva sus parámetros TLS, incluidos `sslmode=require` y `channel_binding=require` si aparecen. Guarda la URL como variable secreta `DATABASE_URL` exclusivamente en Render.

La aplicación y Alembic admiten los prefijos `postgresql://`, `postgres://` y `postgresql+psycopg://` y utilizan el driver Psycopg 3 instalado. Ejemplo ficticio:

```text
postgresql://USUARIO:CLAVE@HOST.neon.tech/BASE?sslmode=require&channel_binding=require
```

Mantén los caracteres escapados de la URL original. No copies el comando `psql` completo ni las comillas. No subas esta conexión al repositorio ni a las variables del frontend.

## 2. API en Render

El servicio se administra desde `render.yaml`, que usa el Dockerfile de la raíz y el plan Free con una sola instancia. El Blueprint solicita `DATABASE_URL` y `RISKENGINE_ADMIN_PASSWORD`; configura además `RISKENGINE_ADMIN_EMAIL` y `RISKENGINE_ALLOWED_ORIGINS`. El administrador es una única cuenta y no existe registro público.

Para configurar las credenciales localmente ejecuta `backend/.venv/bin/python scripts/configure_admin.py`. En Render, introduce el correo en `RISKENGINE_ADMIN_EMAIL` y la contraseña elegida directamente en `RISKENGINE_ADMIN_PASSWORD`. No necesitas generar ni copiar hashes: la aplicación los calcula internamente y almacena solo el hash con sal en `personal_account` en Neon. No añadas las credenciales a GitHub o Vercel. El archivo `.env` local contiene la configuración privada y está excluido del repositorio.

Antes de publicar un cambio de autenticación, configura estas variables en Render. Después del despliegue, retira `RISKENGINE_API_TOKEN`, que ya no se acepta. Al cambiar el correo o la contraseña se invalidan las sesiones anteriores. Para cambiar la contraseña o recuperarla repite este procedimiento; no se envían correos de recuperación.

Las sesiones se guardan en `auth_sessions` en Neon; solo se almacena el hash de su identificador aleatorio. Caducan a las 8 horas y «Salir» las revoca. La migración de sesiones no modifica auditorías ni resultados existentes.

El arranque ejecuta `alembic upgrade head` antes de iniciar Uvicorn. El proceso escucha en `0.0.0.0` y el puerto `PORT` que indica Render. La ruta de salud es `/health`. Si la migración falla, el servidor no arranca. Conserva un respaldo en Neon antes de aplicar migraciones futuras.

Render usa su hostname `onrender.com`, sin un dominio personalizado. El plan gratuito puede suspender el servicio por inactividad y provocar una espera al abrir la aplicación o usar la API. La interfaz de Vercel puede cargar mientras la API se está reactivando.

## 3. Interfaz en Vercel

Importa el repositorio de GitHub y configura:

| Campo | Valor |
| --- | --- |
| Root Directory | `frontend` |
| Framework Preset | Vite |
| Install Command | `npm ci` |
| Build Command | `npm run build` |
| Output Directory | `dist` |

El archivo `frontend/vercel.json` contiene las reglas de proxy para `/api/:path*` y `/health`. Si cambia el hostname de Render, actualiza sus destinos. No se necesitan `DATABASE_URL`, credenciales del administrador ni variables `VITE_*` en Vercel. El proxy debe conservar las cookies, `Set-Cookie`, `Origin` y `X-RiskEngine-Request`.

Añade `riskengine.criveradev.com` en **Settings → Domains** del proyecto de Vercel. Mantén el plan Hobby gratuito dentro de sus condiciones y límites de uso.

## 4. Dominio en Cloudflare

Configura el registro indicado por Vercel:

| Campo | Valor |
| --- | --- |
| Tipo | CNAME |
| Nombre | riskengine |
| Destino | El hostname `…vercel-dns…` mostrado por Vercel |
| Proxy | DNS only |
| TTL | Auto |

Si el registro `riskengine` apunta a `riskengine-s0dr.onrender.com`, edítalo para usar el destino indicado por Vercel. No crees dos CNAME con el mismo nombre. El dominio raíz y los demás subdominios conservan su configuración. Espera la validación y la emisión del certificado en Vercel antes de comprobar HTTPS.

## 5. Verificación

1. Comprueba `/health` desde Render y desde el dominio público de Vercel.
2. Inicia sesión con el correo y la contraseña personales y comprueba la consulta de auditorías en Neon.
3. Crea una auditoría identificada como prueba e importa el XML sintético disponible en la interfaz.
4. Guarda una ejecución y descarga PDF, CSV y JSON.
5. Comprueba que los datos sobreviven a un reinicio de la aplicación.

El acceso actual está limitado a una sola cuenta personal. Si se incorporan usuarios independientes, se necesitan cuentas, permisos y aislamiento de datos. El correo se usa como identificador de acceso y no necesita recibir mensajes.

Verificación local del 28 de octubre de 2026: 71 pruebas de backend, 17 de frontend y compilación de producción aprobadas. En PostgreSQL 16 temporal con UTF-8 se comprobaron migraciones, esquema, importación XML sintética, cálculo, exportaciones y persistencia al recrear la aplicación. El primer despliegue de Render con PostgreSQL 17 en Neon también completó el arranque y el acceso autenticado a la lista de auditorías.

## Referencias

- [Blueprints de Render](https://render.com/docs/blueprint-spec)
- [Limitaciones del plan gratuito de Render](https://render.com/docs/free)
- [Rewrites de Vercel](https://vercel.com/docs/routing/rewrites)
- [Dominios personalizados en Vercel](https://vercel.com/docs/domains/set-up-custom-domain)
- [SQLAlchemy con Neon](https://neon.com/docs/guides/sqlalchemy)
