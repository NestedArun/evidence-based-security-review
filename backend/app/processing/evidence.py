"""Checkpoint 3 orchestration: candidate findings -> source-code evidence."""
from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.evidence import verify_finding
from app.models import EvidenceRow, FindingRow, ReviewRow
from app.schemas import Evidence


def run_evidence_verification(
    session: Session,
    review: ReviewRow,
) -> list[Evidence]:
    findings = session.scalars(
        select(FindingRow)
        .where(FindingRow.review_id == review.review_id)
        .order_by(FindingRow.file, FindingRow.start_line, FindingRow.finding_id)
    ).all()

    # Evidence is reproducible from the current source and candidate findings.
    # Re-running the checkpoint therefore replaces, rather than duplicates, evidence.
    finding_ids = [f.finding_id for f in findings]
    if finding_ids:
        session.execute(delete(EvidenceRow).where(EvidenceRow.finding_id.in_(finding_ids)))

    results: list[Evidence] = []
    for finding in findings:
        evidence = verify_finding(review, finding)
        results.append(evidence)
        session.add(
            EvidenceRow(
                evidence_id=evidence.evidence_id,
                finding_id=evidence.finding_id,
                source=evidence.source.model_dump() if evidence.source else None,
                sink=evidence.sink.model_dump() if evidence.sink else None,
                data_flow=evidence.data_flow.model_dump() if evidence.data_flow else None,
                security_control=(
                    evidence.security_control.model_dump()
                    if evidence.security_control else None
                ),
            )
        )

    session.flush()
    return results
