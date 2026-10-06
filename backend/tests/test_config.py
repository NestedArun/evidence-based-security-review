import json

import pytest
from pydantic import ValidationError

from app.config import Settings, load_project_config


def test_real_project_config_loads(repo_root):
    cfg = load_project_config(repo_root / "configuration" / "project_config.json")
    assert cfg.analysis.language == "python"
    assert cfg.analysis.agents == ["security_review", "owasp_cwe", "crypto", "auth"]
    assert cfg.decision.statuses == ["VERIFIED", "UNCERTAIN", "REJECTED"]
    assert cfg.llm.provider == "ollama"
    assert cfg.static_analysis.bandit.enabled and cfg.static_analysis.ast_rules.enabled


def test_invalid_config_is_rejected(tmp_path, repo_root):
    data = json.loads((repo_root / "configuration" / "project_config.json").read_text())
    data["analysis"]["language"] = "java"  # out of scope
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ValidationError):
        load_project_config(bad)


def test_missing_config_fails_fast(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_project_config(tmp_path / "nope.json")


def test_settings_env_overrides(monkeypatch):
    monkeypatch.setenv("EBSR_MAX_UNIT_LINES", "50")
    monkeypatch.setenv("EBSR_DATABASE_URL", "sqlite:////tmp/x.db")
    s = Settings.from_env()
    assert s.max_unit_lines == 50
    assert s.database_url == "sqlite:////tmp/x.db"
