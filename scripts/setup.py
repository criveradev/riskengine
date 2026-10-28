from pathlib import Path
import os
import secrets
import shutil

root = Path(__file__).resolve().parents[1]
env = root / '.env'
if env.exists():
    print('Se conserva el archivo .env existente.')
else:
    env.write_text('POSTGRES_PASSWORD=' + secrets.token_hex(24) + '\nDATABASE_URL=sqlite:///./riskengine.db\n', encoding='utf-8')
    if os.name != 'nt':
        env.chmod(0o600)
    print('Configuración creada en .env. Conserva sus valores en privado.')
public = root / 'frontend/public'
public.mkdir(exist_ok=True)
shutil.copyfile(root / 'backend/tests/fixtures/synthetic-greenbone.xml', public / 'ejemplo-sintetico.xml')
print('Ejemplo sintético preparado. Instala dependencias y aplica las migraciones según README.md.')

print('Configura el acceso personal con backend/.venv/bin/python scripts/configure_admin.py.')
