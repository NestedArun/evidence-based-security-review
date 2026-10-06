"""Checkpoint 4: Windows-native static-analysis corroboration.

Uses Bandit plus deterministic local AST rules. Results corroborate candidate
findings; this layer never makes a final security decision and never executes
reviewed source code.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import FindingRow, ReviewRow, StaticResultRow


@dataclass(frozen=True)
class AnalyzerMatch:
    tool: str
    rule_id: str
    severity: str | None
    file: str
    start_line: int
    end_line: int
    message: str
    category: str | None


_BANDIT_CATEGORY = {
    "B303": "weak_cryptography",
    "B304": "weak_cryptography",
    "B305": "weak_cryptography",
    "B324": "weak_cryptography",
    "B602": "command_injection",
    "B603": "command_injection",
    "B605": "command_injection",
    "B607": "command_injection",
    "B105": "hardcoded_secret",
    "B106": "hardcoded_secret",
    "B107": "hardcoded_secret",
}


def _relative(root: Path, raw: str) -> str:
    return Path(raw).resolve().relative_to(root.resolve()).as_posix()


def _run_bandit(root: Path) -> list[AnalyzerMatch]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-q"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not completed.stdout.strip():
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    matches: list[AnalyzerMatch] = []
    for item in payload.get("results", []):
        rule_id = str(item.get("test_id", ""))
        line = int(item.get("line_number", 1))
        line_range = item.get("line_range") or [line]
        matches.append(AnalyzerMatch(
            tool="bandit",
            rule_id=rule_id,
            severity=str(item.get("issue_severity", "")).upper() or None,
            file=_relative(root, str(item.get("filename", ""))),
            start_line=line,
            end_line=int(line_range[-1]),
            message=str(item.get("issue_text", "")),
            category=_BANDIT_CATEGORY.get(rule_id),
        ))
    return matches


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _run_ast_rules(root: Path) -> list[AnalyzerMatch]:
    matches: list[AnalyzerMatch] = []
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
    for path in sorted(root.rglob("*.py")):
        if any(part in excluded for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = _relative(root, str(path))
        assigned_sql: dict[str, ast.BinOp] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned_sql[target.id] = node.value
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and any(t in target.id.lower() for t in ("password", "secret", "api_key", "token")):
                            matches.append(AnalyzerMatch("ast_rules", "AST-SEC-001", "MEDIUM", rel, node.lineno, node.end_lineno or node.lineno, "A security-sensitive variable contains a literal string.", "hardcoded_secret"))
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name == "execute" and node.args:
                    sql_arg = node.args[0]
                    if isinstance(sql_arg, ast.BinOp) or (isinstance(sql_arg, ast.Name) and sql_arg.id in assigned_sql):
                        evidence_node = assigned_sql.get(sql_arg.id, sql_arg) if isinstance(sql_arg, ast.Name) else sql_arg
                        matches.append(AnalyzerMatch("ast_rules", "AST-SQL-001", "HIGH", rel, evidence_node.lineno, evidence_node.end_lineno or evidence_node.lineno, "Dynamically constructed SQL is passed to execute().", "sql_injection"))
                if name == "run" and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    matches.append(AnalyzerMatch("ast_rules", "AST-CMD-001", "HIGH", rel, node.lineno, node.end_lineno or node.lineno, "subprocess.run() enables shell interpretation.", "command_injection"))
    return matches


def _normalise_review_path(value: str) -> str:
    return Path(value.replace("\\", "/")).as_posix().lstrip("./")


def _same_review_file(match_file: str, finding_file: str) -> bool:
    match_path = _normalise_review_path(match_file)
    finding_path = _normalise_review_path(finding_file)
    if match_path == finding_path:
        return True
    # Static analyzers may report a path relative to a narrower scan root while
    # candidate findings retain the review-root-relative path. Treat a path as
    # equivalent when one is a complete suffix of the other.
    return match_path.endswith("/" + finding_path) or finding_path.endswith("/" + match_path)


def _matches_finding(match: AnalyzerMatch, finding: FindingRow) -> bool:
    if not _same_review_file(match.file, finding.file):
        return False
    if match.category and match.category != finding.category:
        return False
    finding_end = finding.end_line or finding.start_line
    return finding.start_line <= match.end_line and match.start_line <= finding_end


def _find_finding(match: AnalyzerMatch, findings: list[FindingRow]) -> str | None:
    exact = [f for f in findings if _matches_finding(match, f)]
    if exact:
        return exact[0].finding_id

    fallback = [
        f
        for f in findings
        if _same_review_file(match.file, f.file)
        and (not match.category or match.category == f.category)
    ]

    if len(fallback) == 1:
        return fallback[0].finding_id

    # When multiple candidates have the same file/category, use the closest
    # candidate line range rather than arbitrarily selecting one.
    if fallback:
        return min(
            fallback,
            key=lambda f: min(
                abs(match.start_line - f.start_line),
                abs(match.end_line - (f.end_line or f.start_line)),
            ),
        ).finding_id

    return None


def run_static_analysis(db: Session, review: ReviewRow, project_config) -> list[StaticResultRow]:
    """Run enabled analyzers and persist results mapped to candidate findings."""
    root = Path(review.target_path).resolve()
    if not root.is_dir():
        raise ValueError(f"review target is not a directory: {root}")
    db.execute(
        delete(StaticResultRow).where(
            StaticResultRow.review_id == review.review_id
        )
    )
    findings = db.scalars(select(FindingRow).where(FindingRow.review_id == review.review_id)).all()
    matches: list[AnalyzerMatch] = []
    if project_config.static_analysis.bandit.enabled:
        matches.extend(_run_bandit(root))
    if project_config.static_analysis.ast_rules.enabled:
        matches.extend(_run_ast_rules(root))
    rows: list[StaticResultRow] = []
    for match in matches:
        finding_id = _find_finding(match, findings)
        rows.append(StaticResultRow(
            result_id=uuid.uuid4().hex,
            review_id=review.review_id,
            finding_id=finding_id,
            tool=match.tool,
            matched=finding_id is not None,
            rule_id=match.rule_id,
            severity=match.severity,
            file=match.file,
            start_line=match.start_line,
            end_line=match.end_line,
            message=match.message,
        ))
    db.add_all(rows)
    return rows
