"""Pydantic models must stay in lock-step with the canonical schemas/*.json."""
import json

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from app.schemas import CandidateFinding, Decision, Evidence, Review, StaticAnalysisResult

CASES = {
    "review": (Review, {
        "review_id": "r1", "project_name": "p", "language": "python",
        "status": "PENDING", "created_at": "2026-01-01T00:00:00Z"}),
    "finding": (CandidateFinding, {
        "finding_id": "f1", "review_id": "r1", "agent": "crypto", "title": "t",
        "category": "weak_cryptography", "severity": "HIGH", "file": "a.py",
        "start_line": 4, "description": "d"}),
    "evidence": (Evidence, {
        "evidence_id": "e1", "finding_id": "f1",
        "source": {"found": True, "file": "a.py", "line": 3},
        "sink": {"found": False},
        "data_flow": {"found": True, "path": ["a", "b"]},
        "security_control": {"present": False}}),
    "static_result": (StaticAnalysisResult, {
        "result_id": "s1", "finding_id": None, "tool": "bandit", "matched": True}),
    "decision": (Decision, {
        "decision_id": "d1", "finding_id": "f1", "status": "VERIFIED",
        "evidence_score": 80, "confidence": 0.5, "reason": "r"}),
}
SCHEMA_FILES = {
    "review": "review", "finding": "finding", "evidence": "evidence",
    "static_result": "static_result", "decision": "decision",
}


def _schema(repo_root, key):
    return json.loads((repo_root / "schemas" / f"{SCHEMA_FILES[key]}.schema.json").read_text())


def _pydantic_ok(model, data) -> bool:
    try:
        model.model_validate_json(json.dumps(data))
        return True
    except ValidationError:
        return False


@pytest.mark.parametrize("key", CASES)
def test_properties_and_required_match_schema(repo_root, key):
    model, _ = CASES[key]
    schema = _schema(repo_root, key)
    assert set(model.model_fields) == set(schema["properties"])
    required = {n for n, f in model.model_fields.items() if f.is_required()}
    assert required == set(schema["required"])


@pytest.mark.parametrize("key", CASES)
def test_valid_example_accepted_by_both(repo_root, key):
    model, example = CASES[key]
    validator = Draft202012Validator(_schema(repo_root, key), format_checker=FormatChecker())
    assert not list(validator.iter_errors(example))
    assert _pydantic_ok(model, example)


@pytest.mark.parametrize("key", CASES)
def test_extra_property_rejected_by_both(repo_root, key):
    model, example = CASES[key]
    bad = {**example, "unexpected": 1}
    assert list(Draft202012Validator(_schema(repo_root, key)).iter_errors(bad))
    assert not _pydantic_ok(model, bad)


@pytest.mark.parametrize("key", CASES)
def test_missing_required_rejected_by_both(repo_root, key):
    model, example = CASES[key]
    schema = _schema(repo_root, key)
    for req in schema["required"]:
        bad = {k: v for k, v in example.items() if k != req}
        assert list(Draft202012Validator(schema).iter_errors(bad)), req
        assert not _pydantic_ok(model, bad), req


@pytest.mark.parametrize(
    "key,patch",
    [
        ("review", {"language": "java"}),
        ("review", {"status": "DONE"}),
        ("finding", {"agent": "other"}),
        ("finding", {"category": "xss"}),
        ("finding", {"severity": "INFO"}),
        ("finding", {"start_line": 0}),
        ("finding", {"start_line": "4"}),
        ("static_result", {"tool": "pylint"}),
        ("decision", {"status": "MAYBE"}),
        ("decision", {"confidence": 1.5}),
        ("decision", {"evidence_score": -1}),
    ],
)
def test_invalid_values_rejected_by_both(repo_root, key, patch):
    model, example = CASES[key]
    bad = {**example, **patch}
    assert list(Draft202012Validator(_schema(repo_root, key)).iter_errors(bad))
    assert not _pydantic_ok(model, bad)


def test_evidence_nested_required_flags(repo_root):
    model, example = CASES["evidence"]
    schema = _schema(repo_root, "evidence")
    for field, bad_value in [("source", {}), ("sink", {"file": "a"}), ("data_flow", {}), ("security_control", {})]:
        bad = {**example, field: bad_value}
        assert list(Draft202012Validator(schema).iter_errors(bad)), field
        assert not _pydantic_ok(model, bad), field


def test_end_line_before_start_line_rejected():
    _, example = CASES["finding"]
    assert not _pydantic_ok(CandidateFinding, {**example, "start_line": 5, "end_line": 4})
