from pathlib import Path

import pytest

from app.processing.discovery import normalise_text
from app.processing.parser import extract_units

SAMPLE = '''import os

API_KEY = "k"

def top(a):
    return a

@decorator
def decorated():
    def inner():
        return 1
    return inner

class Outer:
    """doc"""
    LIMIT = 3

    def method(self):
        return self.LIMIT

    @staticmethod
    def static():
        pass

    class Inner:
        def deep(self):
            pass

if __name__ == "__main__":
    top(1)
'''


def _units(text, max_lines=200):
    return extract_units(text, max_lines).units


def test_unit_kinds_names_and_lines():
    units = _units(SAMPLE)
    got = [(u.unit_type, u.function_name, u.class_name, u.start_line, u.end_line) for u in units]
    assert got == [
        ("module", None, None, 1, 3),
        ("function", "top", None, 5, 6),
        ("function", "decorated", None, 8, 12),
        ("class", None, "Outer", 15, 16),
        ("method", "method", "Outer", 18, 19),
        ("method", "static", "Outer", 21, 23),
        ("method", "deep", "Outer.Inner", 26, 27),
        ("module", None, None, 29, 30),
    ]


def test_source_code_matches_reported_lines_and_units_do_not_overlap():
    lines = SAMPLE.split("\n")
    units = _units(SAMPLE)
    prev_end = 0
    for u in units:
        assert u.source_code == "\n".join(lines[u.start_line - 1 : u.end_line])
        assert u.start_line > prev_end
        prev_end = u.end_line


def test_chunking_splits_long_units_with_exact_lines():
    body = "\n".join(f"    x{i} = {i}" for i in range(25))
    text = f"def big():\n{body}\n"
    units = _units(text, max_lines=10)
    assert [(u.start_line, u.end_line, u.chunk_index) for u in units] == [
        (1, 10, 0), (11, 20, 1), (21, 26, 2)]
    assert all(u.function_name == "big" for u in units)
    lines = text.split("\n")
    assert all(u.source_code == "\n".join(lines[u.start_line - 1 : u.end_line]) for u in units)


def test_short_units_are_not_chunked():
    assert all(u.chunk_index is None for u in _units(SAMPLE))


def test_syntax_error_is_flagged_not_hidden():
    result = extract_units("def ok():\n    return 1\n\ndef broken(:\n    pass\n", 200)
    assert result.has_syntax_errors
    assert any(u.function_name == "ok" for u in result.units)


def test_empty_and_blank_files_yield_no_units():
    assert _units("") == [] and _units("\n\n") == []
    assert not extract_units("x = 1\n", 200).has_syntax_errors


def test_crlf_files_keep_line_numbers():
    text = normalise_text(b"import os\r\n\r\ndef f():\r\n    return 1\r\n")
    got = [(u.unit_type, u.start_line, u.end_line) for u in _units(text)]
    assert got == [("module", 1, 1), ("function", 3, 4)]


DATASET = Path(__file__).resolve().parents[2] / "dataset"


@pytest.mark.parametrize("path", sorted(DATASET.rglob("*.py")), ids=lambda p: p.name)
def test_dataset_samples_are_fully_covered(path):
    text = normalise_text(path.read_bytes())
    lines = text.split("\n")
    units = _units(text)
    covered = set()
    for u in units:
        assert u.source_code == "\n".join(lines[u.start_line - 1 : u.end_line])
        covered.update(range(u.start_line, u.end_line + 1))
    non_blank = {i + 1 for i, l in enumerate(lines) if l.strip()}
    assert non_blank <= covered  # no code line silently dropped


def test_hardcoded_secret_sample_keeps_module_level_line_1():
    text = normalise_text((DATASET / "vulnerable" / "V003_hardcoded_secret.py").read_bytes())
    units = _units(text)
    assert units[0].unit_type == "module" and units[0].start_line == 1
    assert "API_KEY" in units[0].source_code
