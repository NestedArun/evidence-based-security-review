import hashlib
import os

from app.processing.discovery import SKIP_NOT_UTF8, SKIP_TOO_LARGE, discover_files, normalise_text

EXCLUDED = frozenset({".git", "node_modules", "__pycache__"})


def _by_path(items):
    return {i.relative_path: i for i in items}


def test_discovery_filters_and_reports(make_project):
    root = make_project({
        "a.py": "x = 1\n",
        "pkg/b.py": "y = 2\n",
        "README.md": "# hi",
        "meta/ground_truth.json": "{}",
        "node_modules/dep/c.py": "z = 3\n",
        ".git/hooks/h.py": "h = 1\n",
        "big.py": "#" * 500,
        "latin.py": b"s = '\xe9'\n",
    })
    found = _by_path(discover_files(root, EXCLUDED, max_file_bytes=100))
    # Non-source files (README.md, *.json) are not discovered at all.
    assert set(found) == {"a.py", "pkg/b.py", "big.py", "latin.py"}
    assert found["a.py"].skip_reason is None and found["a.py"].text == "x = 1\n"
    assert found["big.py"].skip_reason == SKIP_TOO_LARGE and found["big.py"].text is None
    assert found["latin.py"].skip_reason == SKIP_NOT_UTF8
    assert found["a.py"].sha256 == hashlib.sha256(b"x = 1\n").hexdigest()


def test_symlinks_are_not_followed(make_project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("s = 1\n")
    root = make_project({"ok.py": "a = 1\n"})
    os.symlink(outside, root / "linked_dir")
    os.symlink(outside / "secret.py", root / "linked_file.py")
    assert set(_by_path(discover_files(root, EXCLUDED, 10_000))) == {"ok.py"}


def test_discovery_is_sorted_and_deterministic(make_project):
    root = make_project({"z.py": "", "a.py": "", "m/b.py": ""})
    paths = [f.relative_path for f in discover_files(root, EXCLUDED, 1000)]
    assert paths == ["a.py", "z.py", "m/b.py"]  # files of a directory first, then subdirectories
    assert paths == [f.relative_path for f in discover_files(root, EXCLUDED, 1000)]


def test_newline_and_bom_normalisation():
    assert normalise_text(b"\xef\xbb\xbfa\r\nb\rc\n") == "a\nb\nc\n"
