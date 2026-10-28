"""Package only deliverable files; local keys, databases and caches stay out."""
import os
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT_FILES = {'README.md', 'VALIDACION.md', 'Dockerfile', 'compose.yaml', 'render.yaml', '.gitignore', '.dockerignore'}
BLOCKED_DIRECTORIES = {
    '.venv', 'venv', '.git', '.idea', 'node_modules', '.npm-cache', '.qa',
    '__pycache__', '.pytest_cache', '.test-tmp',
}
EXTENSIONS = {'.py', '.toml', '.ini', '.mako', '.xml', '.ts', '.tsx', '.css', '.html', '.js', '.svg'}


def select_files(root: Path) -> list[Path]:
    selected = []
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directory = Path(directory)
        directories[:] = sorted(
            name for name in directories
            if name not in BLOCKED_DIRECTORIES
            and not name.endswith('.egg-info')
            and not (directory / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = directory / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root)
            if len(relative.parts) == 1:
                allowed = relative.name in ROOT_FILES
            elif relative.parts[0] == 'backend':
                allowed = path.suffix in EXTENSIONS or relative.name == 'requirements.lock'
            elif relative.parts[0] == 'frontend':
                allowed = path.suffix in EXTENSIONS or relative.name in {'package.json', 'package-lock.json', 'tsconfig.json', 'vercel.json'}
            elif relative.parts[0] == 'docs':
                allowed = path.suffix == '.md'
            elif relative.parts[0] == 'scripts':
                allowed = path.suffix == '.py'
            else:
                allowed = False
            if allowed:
                selected.append(path)
    return sorted(selected)


def package_source(root: Path, destination: Path) -> int:
    selected = select_files(root)
    with ZipFile(destination, 'w', ZIP_DEFLATED) as archive:
        for path in selected:
            archive.write(path, Path('RiskEngine') / path.relative_to(root))
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Archive verification failed')
        for name in archive.namelist():
            path = Path(name)
            if (path.name == '.env' or path.suffix in {'.db', '.sqlite', '.sqlite3'}
                    or any(part in BLOCKED_DIRECTORIES for part in path.parts)):
                raise RuntimeError('Private or generated data in archive')
    return len(selected)


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    destination = root / 'RiskEngine_codigo_v0.1.zip'
    count = package_source(root, destination)
    print(f'{destination.name}: {count} archivos, {destination.stat().st_size} bytes; ZIP verificado.')
