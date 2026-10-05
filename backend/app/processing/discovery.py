"""File discovery, language detection and filtering (Code Processing Layer).

Contract: only files of a supported source language (currently ``.py``) are
"discovered source files". Everything else (``ground_truth.json``, READMEs, data
files, ...) is not source code, so it is neither counted nor reported. Supported
source files may still be *skipped* with a reason (too large, not UTF-8, unreadable).

Pure file-system inspection: files are only ever *read as text bytes*; nothing
submitted for review is imported or executed.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

# Extension -> language. Only Python is in scope (RESEARCH_SCOPE.md section 2).
LANGUAGE_BY_EXTENSION = {".py": "python"}

SKIP_TOO_LARGE = "too_large"
SKIP_NOT_UTF8 = "not_utf8"
SKIP_UNREADABLE = "unreadable"


@dataclass
class DiscoveredFile:
    relative_path: str  # POSIX, relative to project root
    absolute_path: Path
    size_bytes: int
    language: str | None
    skip_reason: str | None = None
    sha256: str | None = None
    text: str | None = None  # normalised text, only when the file will be processed


def detect_language(path: Path) -> str | None:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def normalise_text(raw: bytes) -> str:
    """Decode UTF-8 (BOM tolerated) and normalise newlines so line numbers are stable."""
    text = raw.decode("utf-8-sig")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def discover_files(
    root: Path, excluded_dirs: frozenset[str], max_file_bytes: int
) -> list[DiscoveredFile]:
    """Walk ``root`` and return every file with a processing decision.

    Symlinks are never followed (neither files nor directories) so a review cannot
    escape the selected project directory. Results are sorted for reproducibility.
    """
    root = root.resolve()
    found: list[DiscoveredFile] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in excluded_dirs and not Path(dirpath, d).is_symlink()
        )
        for name in sorted(filenames):
            abs_path = Path(dirpath, name)
            if abs_path.is_symlink():
                continue
            rel = abs_path.relative_to(root).as_posix()
            language = detect_language(abs_path)
            if language is None:
                continue  # not a source file: not part of the discovery contract
            try:
                size = abs_path.stat().st_size
            except OSError:
                found.append(DiscoveredFile(rel, abs_path, 0, language, SKIP_UNREADABLE))
                continue

            item = DiscoveredFile(rel, abs_path, size, language)
            if size > max_file_bytes:
                item.skip_reason = SKIP_TOO_LARGE
            else:
                try:
                    raw = abs_path.read_bytes()
                except OSError:
                    item.skip_reason = SKIP_UNREADABLE
                else:
                    item.sha256 = hashlib.sha256(raw).hexdigest()
                    try:
                        item.text = normalise_text(raw)
                    except UnicodeDecodeError:
                        item.skip_reason = SKIP_NOT_UTF8
            found.append(item)
    return found
