from dataclasses import dataclass, field
from pathlib import Path
import os
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def database_url_from_env() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if os.getenv("RENDER") == "true" and not url.startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
        raise RuntimeError("Configura DATABASE_URL con la conexión PostgreSQL de Neon en Render.")
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url or "sqlite:///./riskengine.db"


@dataclass(frozen=True)
class Settings:
    database_url: str
    admin_email: str = ""
    admin_password_hash: str = field(default="", repr=False)
    max_upload_bytes: int = 10 * 1024 * 1024
    secure_cookie: bool = False
    allowed_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:8001", "http://127.0.0.1:8001")

    admin_password: str = field(default="", repr=False)

    @property
    def cookie_name(self):
        return "__Host-riskengine-session" if self.secure_cookie else "riskengine-session"

    @classmethod
    def from_env(cls):
        load_dotenv(PROJECT_ROOT / ".env")
        deployed = os.getenv("RENDER") == "true"
        origins = os.getenv("RISKENGINE_ALLOWED_ORIGINS", "")
        return cls(database_url=database_url_from_env(),
                   admin_email=os.getenv("RISKENGINE_ADMIN_EMAIL", "").strip().casefold(),
                   admin_password_hash=os.getenv("RISKENGINE_ADMIN_PASSWORD_HASH", ""),
                   admin_password=os.getenv("RISKENGINE_ADMIN_PASSWORD", ""),
                   secure_cookie=deployed or os.getenv("RISKENGINE_SECURE_COOKIE") == "true",
                   allowed_origins=tuple(origin.strip().rstrip('/') for origin in origins.split(',') if origin.strip()) if origins else cls.allowed_origins)
