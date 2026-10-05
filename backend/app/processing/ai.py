"""Checkpoint 2 orchestration: code units -> specialized AI candidates."""
from __future__ import annotations

import os
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents import AGENTS, run_agent
from app.llm import OllamaClient
from app.models import CodeUnitRow, FindingRow, ReviewRow
from app.schemas import CandidateFinding


def configured_model(project_config) -> str:
    return os.environ.get("EBSR_OLLAMA_MODEL", project_config.llm.model)


def run_ai_review(session: Session, review: ReviewRow, project_config) -> list[CandidateFinding]:
    model = configured_model(project_config)
    client = OllamaClient(
        model=model,
        temperature=project_config.llm.temperature,
    )

    units = session.scalars(
        select(CodeUnitRow)
        .where(CodeUnitRow.review_id == review.review_id)
        .order_by(CodeUnitRow.file, CodeUnitRow.start_line, CodeUnitRow.chunk_index)
    ).all()

    findings: list[CandidateFinding] = []
    for unit_row in units:
        unit = __import__("app.schemas", fromlist=["CodeUnit"]).CodeUnit.model_validate(unit_row)
        for spec in AGENTS:
            finding = run_agent(client, spec, unit)
            if finding is None:
                continue
            findings.append(finding)
            session.add(FindingRow(
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
            ))
    session.flush()
    return findings
