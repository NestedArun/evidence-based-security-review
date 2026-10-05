import os
import tempfile
from pathlib import Path

# Importing app.main builds a module-level app; point it at a throwaway DB first so
# test runs never touch backend/data/.
os.environ.setdefault("EBSR_DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/import-time.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import REPO_ROOT, Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}")


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def make_project(tmp_path):
    """Create a throwaway project directory from {relative_path: str|bytes}."""

    def _make(files: dict, name: str = "proj") -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return root

    return _make
