from pathlib import Path
import runpy
from zipfile import ZipFile


PACKAGE_SCRIPT = Path(__file__).parents[2] / 'scripts/package_source.py'


def test_package_excludes_local_environments_and_private_data(tmp_path):
    root = tmp_path / 'project'
    included = {
        'README.md', 'backend/riskengine/domain.py', 'backend/requirements.lock',
        'frontend/src/App.tsx', 'frontend/package.json', 'frontend/dist/index.html',
        'scripts/setup.py',
    }
    excluded = {
        '.env', 'backend/.env', 'backend/riskengine.db', 'backend/local.sqlite3',
        'backend/.venv/lib/python3.14/site-packages/private.py',
        '.venv/lib/python3.14/site-packages/private.py',
        'backend/venv/lib/private.py', 'frontend/node_modules/dependency/index.js',
        'backend/.idea/config.xml', 'backend/__pycache__/cached.py',
        'backend/example.egg-info/config.py',
    }
    for name in included | excluded:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic test content', encoding='utf-8')

    package_source = runpy.run_path(str(PACKAGE_SCRIPT))['package_source']
    destination = tmp_path / 'source.zip'
    assert package_source(root, destination) == len(included)
    with ZipFile(destination) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == {f'RiskEngine/{name}' for name in included}


def test_package_does_not_follow_symbolic_links(tmp_path):
    root = tmp_path / 'project'
    backend = root / 'backend'
    backend.mkdir(parents=True)
    external = tmp_path / 'external'
    external.mkdir()
    (external / 'private.py').write_text('synthetic private content', encoding='utf-8')
    (backend / 'linked.py').symlink_to(external / 'private.py')
    (backend / 'linked-directory').symlink_to(external, target_is_directory=True)
    package_source = runpy.run_path(str(PACKAGE_SCRIPT))['package_source']
    destination = tmp_path / 'source.zip'
    assert package_source(root, destination) == 0
    with ZipFile(destination) as archive:
        assert archive.namelist() == []
