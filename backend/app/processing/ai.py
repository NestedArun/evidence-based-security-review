"""Checkpoint 2 orchestration: code units -> specialized AI candidates."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.agents import AGENTS, run_agent
from app.llm import OllamaClient
from app.models import (
    CodeUnitRow,
    DecisionRow,
    EvaluationRunRow,
    EvidenceRow,
    FindingRow,
    ReviewRow,
    StaticResultRow,
)
from app.schemas import CandidateFinding


def configured_model(project_config) -> str:
    return os.environ.get("EBSR_OLLAMA_MODEL", project_config.llm.model)


def _is_import_only_unit(unit) -> bool:
    """Return True when a module unit contains only import statements."""
    if unit.unit_type != "module":
        return False

    lines = [
        line.strip()
        for line in unit.source_code.splitlines()
        if line.strip()
    ]

    if not lines:
        return True

    return all(
        line.startswith("import ") or line.startswith("from ")
        for line in lines
    )


_CRYPTO_HINTS = (
    "crypt", "hash", "md5", "sha1", "sha256", "bcrypt", "password",
    "secret", "api_key", "private_key", "cipher", "encrypt", "decrypt",
    "digest", "hmac", "certificate", "ssl", "tls", "token",
)
_AUTH_HINTS = (
    "auth", "login", "logout", "password", "session", "permission",
    "role", "admin", "authorize", "authenticate", "access", "credential",
    "jwt", "privilege", "owner", "is_admin",
)


def _agent_applies_to_unit(spec, unit) -> bool:
    """Route specialist agents only to units with relevant security signals.

    The two general-purpose agents still inspect every eligible code unit, so
    this routing reduces redundant specialist calls without removing broad
    vulnerability coverage.
    """
    if spec.name not in {"crypto", "auth"}:
        return True

    text = (
        f"{unit.file}\\n{unit.function_name or ''}\\n"
        f"{unit.class_name or ''}\\n{unit.source_code}"
    ).lower()
    hints = _CRYPTO_HINTS if spec.name == "crypto" else _AUTH_HINTS
    return any(hint in text for hint in hints)


def run_ai_review(
    session: Session,
    review: ReviewRow,
    project_config,
) -> list[CandidateFinding]:
    model = configured_model(project_config)

    units = session.scalars(
        select(CodeUnitRow)
        .where(CodeUnitRow.review_id == review.review_id)
        .order_by(
            CodeUnitRow.file,
            CodeUnitRow.start_line,
            CodeUnitRow.chunk_index,
        )
    ).all()

    # Convert database rows to immutable Pydantic objects before
    # starting worker threads. Database sessions are not shared with workers.
    code_units = [
        __import__("app.schemas", fromlist=["CodeUnit"])
        .CodeUnit.model_validate(unit_row)
        for unit_row in units
    ]

    # Import-only module units provide no useful security-review context.
    # Keep module units containing actual declarations such as hardcoded secrets.
    code_units = [
        unit for unit in code_units
        if not _is_import_only_unit(unit)
    ]

    def review_agent(spec_and_unit):
        spec, unit = spec_and_unit

        client = OllamaClient(
            model=model,
            temperature=project_config.llm.temperature,
        )

        return run_agent(client, spec, unit)

    jobs = [
        (spec, unit)
        for unit in code_units
        for spec in AGENTS
        if _agent_applies_to_unit(spec, unit)
    ]

    findings: list[CandidateFinding] = []

    # Two concurrent Ollama requests are used deliberately. Four concurrent
    # generations can overload a CPU-only development machine. Specialist
    # routing reduces the number of requests before concurrency is used.
    with ThreadPoolExecutor(max_workers=2) as executor:
        for finding in executor.map(review_agent, jobs):
            if finding is not None:
                findings.append(finding)

    # Replace prior outputs only after every model call succeeds. This makes
    # repeated AI-review requests idempotent and prevents stale evidence,
    # static-analysis matches, decisions, or evaluation metrics from surviving
    # after the candidate findings have changed.
    old_finding_ids = session.scalars(
        select(FindingRow.finding_id).where(
            FindingRow.review_id == review.review_id
        )
    ).all()

    if old_finding_ids:
        session.execute(
            delete(EvidenceRow).where(
                EvidenceRow.finding_id.in_(old_finding_ids)
            )
        )
        session.execute(
            delete(DecisionRow).where(
                DecisionRow.finding_id.in_(old_finding_ids)
            )
        )

    # Static results include unmatched analyzer results, so clear by review ID.
    session.execute(
        delete(StaticResultRow).where(
            StaticResultRow.review_id == review.review_id
        )
    )
    session.execute(
        delete(FindingRow).where(
            FindingRow.review_id == review.review_id
        )
    )
    session.execute(
        delete(EvaluationRunRow).where(
            EvaluationRunRow.review_id == review.review_id
        )
    )

    # Database writes remain on the request/session thread.
    for finding in findings:
        session.add(
            FindingRow(
                finding_id=finding.finding_id,
                review_id=finding.review_id,
                agent=finding.agent,
                title=finding.title,
                category=finding.category,
                cwe=finding.cwe,
                severity=finding.severity,
                file=finding.file,
                start_line=finding.start_line,
                end_line=finding.end_line,
                function=finding.function,
                description=finding.description,
                reasoning=finding.reasoning,
            )
        )

    session.flush()
    return findings