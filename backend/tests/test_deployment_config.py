import pytest

from riskengine.config import database_url_from_env


@pytest.mark.parametrize('prefix', ['postgres://', 'postgresql://', 'postgresql+psycopg://'])
def test_neon_url_uses_installed_driver_and_preserves_credentials_and_tls(monkeypatch, prefix):
    suffix = 'user:pass%25word@ep-example.neon.tech/db?sslmode=require&channel_binding=require'
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.setenv('DATABASE_URL', prefix + suffix)
    assert database_url_from_env() == 'postgresql+psycopg://' + suffix


@pytest.mark.parametrize('url', ['', 'sqlite:///./riskengine.db'])
def test_render_requires_postgres_instead_of_ephemeral_sqlite(monkeypatch, url):
    monkeypatch.setenv('RENDER', 'true')
    monkeypatch.setenv('DATABASE_URL', url)
    with pytest.raises(RuntimeError, match='DATABASE_URL'):
        database_url_from_env()


def test_local_default_still_uses_sqlite(monkeypatch):
    monkeypatch.delenv('RENDER', raising=False)
    monkeypatch.delenv('DATABASE_URL', raising=False)
    assert database_url_from_env() == 'sqlite:///./riskengine.db'
