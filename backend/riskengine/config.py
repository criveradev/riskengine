from dataclasses import dataclass
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
    api_token: str
    max_upload_bytes: int = 10 * 1024 * 1024

    @classmethod
    def from_env(cls):
        load_dotenv(PROJECT_ROOT / ".env")
        token = os.environ.get("RISKENGINE_API_TOKEN", "")
        if len(token) < 32:
            raise RuntimeError("Configura RISKENGINE_API_TOKEN con al menos 32 caracteres. Ejecuta scripts/setup.py.")
        return cls(database_url_from_env(), token)
