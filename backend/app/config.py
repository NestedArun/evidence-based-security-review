"""Application settings and project-configuration loading.

Two kinds of configuration:
  * ``project_config.json`` - the research configuration defined by the repository
    (read-only here, validated at startup).
  * ``Settings`` - backend runtime settings (paths, thresholds). Overridable with
    ``EBSR_*`` environment variables; nothing here is a secret.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectInfo(_Strict):
    name: str
    version: str


class AnalysisConfig(_Strict):
    language: Literal["python"]
    vulnerability_categories: list[str]
    agents: list[str]


class LLMConfig(_Strict):
    provider: str
    model: str
    temperature: float


class ToolToggle(_Strict):
    enabled: bool


class StaticAnalysisConfig(_Strict):
    semgrep: ToolToggle
    bandit: ToolToggle


class DecisionConfig(_Strict):
    statuses: list[str]


class EvaluationConfig(_Strict):
    metrics: list[str]


class ProjectConfig(_Strict):
    """Validated view of configuration/project_config.json."""

    project: ProjectInfo
    analysis: AnalysisConfig
    llm: LLMConfig
    static_analysis: StaticAnalysisConfig
    decision: DecisionConfig
    evaluation: EvaluationConfig


def load_project_config(path: Path) -> ProjectConfig:
    """Load and validate the project configuration. Raises on missing/invalid file."""
    with open(path, encoding="utf-8") as fh:
        return ProjectConfig.model_validate(json.load(fh))


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


@dataclass
class Settings:
    repo_root: Path = REPO_ROOT
    project_config_path: Path = field(default=None)  # type: ignore[assignment]
    database_url: str = field(default=None)  # type: ignore[assignment]
    # Code-processing thresholds
    max_file_bytes: int = 1_000_000  # files larger than this are skipped (reported, not hidden)
    max_unit_lines: int = 200  # code units longer than this are split into line chunks
    # Directories never descended into during file discovery
    excluded_dirs: frozenset[str] = frozenset(
        {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", "node_modules",
         ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist",
         "site-packages", ".eggs"}
    )

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root)
        if self.project_config_path is None:
            self.project_config_path = Path(
                os.environ.get(
                    "EBSR_PROJECT_CONFIG",
                    self.repo_root / "configuration" / "project_config.json",
                )
            )
        if self.database_url is None:
            default_db = self.repo_root / "backend" / "data" / "review.db"
            self.database_url = os.environ.get("EBSR_DATABASE_URL", f"sqlite:///{default_db}")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            max_file_bytes=_env_int("EBSR_MAX_FILE_BYTES", 1_000_000),
            max_unit_lines=_env_int("EBSR_MAX_UNIT_LINES", 200),
        )
