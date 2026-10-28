from pathlib import Path
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from riskengine.api import create_app
from riskengine.config import Settings
from riskengine.database import make_engine
from riskengine.models import Base


def test_initial_migration_matches_models(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path / "migrated.db"}')
    cfg = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    command.upgrade(cfg, 'head')
    command.check(cfg)
    engine = make_engine(f'sqlite:///{tmp_path / "migrated.db"}')
    assert set(Base.metadata.tables).issubset(inspect(engine).get_table_names())
    engine.dispose()


def test_position_migration_restores_xml_order(tmp_path, monkeypatch):
    from sqlalchemy import text
    from conftest import FIXTURE
    from riskengine.parser import parse_report
    from riskengine.repository import Repository
    url = f'sqlite:///{tmp_path / "position.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    cfg = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    command.upgrade(cfg, 'c2d3e4f50612')
    engine = make_engine(url)
    parsed = parse_report(FIXTURE.read_bytes())
    with engine.begin() as con:
        con.execute(text("INSERT INTO audits (id,name,scope,created_at) VALUES ('a','a','a','2026-10-20')"))
        con.execute(text("INSERT INTO imports (id,audit_id,sha256,filename,content,report_metadata,created_at) VALUES ('i','a','hash','test.xml',:xml,'{}','2026-10-20')"), {'xml': FIXTURE.read_bytes()})
        con.execute(text("INSERT INTO assets (id,audit_id,identifier) VALUES ('asset','a','test')"))
        for index, finding in enumerate(parsed.findings):
            con.execute(text("INSERT INTO findings (id,audit_id,import_id,asset_id,external_id,name,oid,port,description,status) VALUES (:id,'a','i','asset',:external_id,:name,'','','','open')"),
                        {'id': str(len(parsed.findings) - index), 'external_id': finding.external_id, 'name': finding.name})
    command.upgrade(cfg, 'head')
    actual = Repository(engine).findings('a', 'i')['items']
    assert [row['external_id'] for row in actual] == [finding.external_id for finding in parsed.findings]
    command.check(cfg)
    engine.dispose()


def test_upload_limit_and_auth_before_processing(tmp_path):
    engine = make_engine(f'sqlite:///{tmp_path / "limits.db"}')
    Base.metadata.create_all(engine)
    from conftest import test_settings, sign_in, AUTH_HEADERS
    app = create_app(test_settings(max_upload_bytes=50), engine)
    with TestClient(app, headers=AUTH_HEADERS) as client:
        sign_in(client)
        audit = client.post('/api/audits', json={'name': 'Límite', 'scope': 'Prueba'}).json()['id']
        result = client.post(f'/api/audits/{audit}/imports', files={'file': ('large.xml', b'x' * 100)})
        assert result.status_code == 413
        result = client.post(f'/api/audits/{audit}/imports', files={'file': ('large.xml', b'x' * 70_000)})
        assert result.status_code == 413
        assert client.get(f'/api/audits/{audit}/imports').json()['total'] == 0
    engine.dispose()
