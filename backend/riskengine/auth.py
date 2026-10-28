"""Single-owner authentication with revocable, server-side sessions."""
from datetime import UTC, datetime, timedelta
from hashlib import scrypt, sha256
import secrets

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .models import AuthSession


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, maxmem=64 * 1024 * 1024).hex()
    return f'scrypt$32768$8$3${salt}${digest}'


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split('$')
        if (algorithm, n, r, p) != ('scrypt', '32768', '8', '3'):
            return False
        actual = scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, maxmem=64 * 1024 * 1024).hex()
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


class Authentication:
    def __init__(self, engine, settings):
        self.engine, self.settings = engine, settings
        self.revision = sha256((settings.admin_email + '\0' + settings.admin_password_hash).encode()).hexdigest()

    def create_session(self, previous: str = '') -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        with Session(self.engine) as db, db.begin():
            db.execute(delete(AuthSession).where(AuthSession.expires_at <= now.isoformat()))
            if previous:
                db.execute(delete(AuthSession).where(AuthSession.token_hash == sha256(previous.encode()).hexdigest()))
            db.add(AuthSession(token_hash=sha256(token.encode()).hexdigest(), credential_revision=self.revision,
                               expires_at=(now + timedelta(hours=8)).isoformat()))
        return token

    def authenticated(self, token: str) -> bool:
        if not token or len(token) > 128 or not self.settings.admin_password_hash:
            return False
        with Session(self.engine) as db:
            row = db.get(AuthSession, sha256(token.encode()).hexdigest())
            return bool(row and row.credential_revision == self.revision and row.expires_at > datetime.now(UTC).isoformat())

    def revoke(self, token: str):
        with Session(self.engine) as db, db.begin():
            db.execute(delete(AuthSession).where(AuthSession.token_hash == sha256(token.encode()).hexdigest()))
