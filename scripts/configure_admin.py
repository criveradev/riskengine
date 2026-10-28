"""Configure the personal account locally in a private environment file."""
from getpass import getpass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from dotenv import set_key, unset_key


def main():
    email = input('Correo de administrador: ').strip().casefold()
    if '@' not in email or len(email) > 254:
        raise SystemExit('Correo no válido.')
    password = getpass('Contraseña (no se muestra): ')
    if not password or len(password) > 1024 or password != getpass('Repite la contraseña: '):
        raise SystemExit('Las contraseñas deben coincidir y tener entre 1 y 1024 caracteres.')
    env = ROOT / '.env'
    env.touch(mode=0o600, exist_ok=True)
    env.chmod(0o600)
    set_key(str(env), 'RISKENGINE_ADMIN_EMAIL', email)
    set_key(str(env), 'RISKENGINE_ADMIN_PASSWORD', password)
    unset_key(str(env), 'RISKENGINE_ADMIN_PASSWORD_HASH')
    print('Acceso personal configurado en .env. La contraseña queda en el archivo privado; la base solo guardará su hash.')


if __name__ == '__main__':
    main()
