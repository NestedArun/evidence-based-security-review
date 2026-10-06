"""Checkpoint 5: deterministic evidence-based finding decisions.

The AI agents generate hypotheses; Checkpoint 3 verifies source evidence and
Checkpoint 4 supplies independent static-analysis corroboration. This module
combines those persisted artifacts into a reproducible verdict without asking
an LLM to make the final security decision.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import DecisionRow, EvidenceRow, FindingRow, ReviewRow, StaticResultRow
from app.schemas import Decision


@dataclass(frozen=True)
class FindingGroup:
    """Nearby candidate findings that likely describe the same issue."""

    finding_ids: tuple[str, ...]


_REMEDIATION = {
    "sql_injection": "Use parameterized queries/prepared statements and never concatenate or interpolate untrusted input into SQL.",
    "command_injection": "Avoid shell interpretation and pass command arguments as a structured argument list; validate input against an allowlist where applicable.",
    "hardcoded_secret": "Remove the secret from source control, rotate the exposed credential, and load secrets from a secure secret manager or environment configuration.",
    "weak_cryptography": "Replace weak or obsolete cryptographic primitives with a modern approved primitive; use a password-specific KDF such as Argon2, scrypt, or PBKDF2 for passwords.",
    "authentication_authorization": "Enforce authentication and authorization checks at the protected-resource boundary, using explicit role/permission checks before returning sensitive data.",
}


def _nearby(a: FindingRow, b: FindingRow) -> bool:
    if a.category != b.category:
        return False
    if a.file.replace("\\", "/") != b.file.replace("\\", "/"):
        return False
    a_end = a.end_line or a.start_line
    b_end = b.end_line or b.start_line
    return a.start_line <= b_end + 3 and b.start_line <= a_end + 3


def correlate_findings(findings: list[FindingRow]) -> list[FindingGroup]:
    """Group overlapping/nearby same-category findings without deleting candidates."""
    groups: list[list[str]] = []
    for finding in findings:
        placed = False
        for group in groups:
            members = [next(f for f in findings if f.finding_id == fid) for fid in group]
            if any(_nearby(finding, member) for member in members):
                group.append(finding.finding_id)
                placed = True
                break
        if not placed:
            groups.append([finding.finding_id])
    return [FindingGroup(tuple(group)) for group in groups]


def _found(obj: dict | None) -> bool:
    return bool(obj and obj.get("found") is True)


def _control_present(obj: dict | None) -> bool:
    return bool(obj and obj.get("present") is True)


def _score(finding: FindingRow, evidence: EvidenceRow | None, static: list[StaticResultRow]) -> tuple[float, list[str]]:
    """Score concrete evidence, independent of LLM reasoning."""
    if evidence is None:
        return 0.0, ["No independently verified evidence record exists."]

    source = evidence.source or {}
    sink = evidence.sink or {}
    flow = evidence.data_flow or {}
    control = evidence.security_control or {}
    corroboration = [r for r in static if r.finding_id == finding.finding_id and r.matched]

    score = 0.0
    reasons: list[str] = []

    if finding.category in {"sql_injection", "command_injection"}:
        if _found(source):
            score += 20
            reasons.append("an untrusted/input source was located")
        if _found(sink):
            score += 35
            reasons.append("a dangerous sink was located")
        if _found(flow):
            score += 30
            reasons.append("a source-to-sink data flow was established")
    elif finding.category == "hardcoded_secret":
        if _found(source):
            score += 50
            reasons.append("a secret-like literal was located in source")
        if _found(sink):
            score += 20
            reasons.append("the secret reaches a security-sensitive use")
        if _found(flow):
            score += 15
            reasons.append("secret data flow was established")
    elif finding.category == "weak_cryptography":
        if _found(source):
            score += 15
            reasons.append("input/password data was located")
        if _found(sink):
            score += 50
            reasons.append("a weak cryptographic primitive was located")
        if _found(flow):
            score += 20
            reasons.append("input data reaches the weak primitive")
    elif finding.category == "authentication_authorization":
        if _found(source):
            score += 20
            reasons.append("identity/authorization input was located")
        if _found(sink):
            score += 30
            reasons.append("a protected-resource sink was located")
        if _found(flow):
            score += 30
            reasons.append("authorization data reaches the protected resource")

    if corroboration:
        score += min(20.0, 10.0 * len({r.tool for r in corroboration}))
        reasons.append("independent static analysis corroborates the candidate")

    if _control_present(control):
        # A concrete security control is counter-evidence. It is deliberately
        # stronger than merely lacking evidence, but it cannot drive the score below 0.
        score -= 30.0
        reasons.append("a relevant security control was detected")

    return max(0.0, min(100.0, score)), reasons


def _decide(score: float, evidence: EvidenceRow | None, finding: FindingRow) -> tuple[str, float]:
    """Map evidence strength to a verdict and bounded confidence."""
    if evidence is None:
        return "REJECTED", 0.95

    source = evidence.source or {}
    sink = evidence.sink or {}
    flow = evidence.data_flow or {}
    control = evidence.security_control or {}

    strong_direct = _found(sink) or _found(source)
    if _control_present(control) and not _found(flow):
        status = "REJECTED"
    elif score >= 70 and strong_direct:
        status = "VERIFIED"
    elif score < 35:
        status = "REJECTED"
    else:
        status = "UNCERTAIN"

    # Confidence measures decision stability from evidence strength; it is not
    # presented as a calibrated probability.
    if status == "VERIFIED":
        confidence = min(1.0, 0.70 + (score - 70.0) / 100.0)
    elif status == "REJECTED":
        confidence = min(1.0, 0.70 + (35.0 - min(score, 35.0)) / 100.0)
    else:
        confidence = 0.45 + min(0.20, abs(score - 52.5) / 100.0)

    return status, round(confidence, 3)


def run_decision_review(session: Session, review: ReviewRow) -> list[Decision]:
    """Correlate and judge all candidate findings for a review.

    Re-running this checkpoint replaces existing decisions for the review, so
    results remain deterministic and never accumulate duplicates.
    """
    findings = session.scalars(
        select(FindingRow)
        .where(FindingRow.review_id == review.review_id)
        .order_by(FindingRow.file, FindingRow.start_line, FindingRow.finding_id)
    ).all()

    if findings:
        finding_ids = [f.finding_id for f in findings]
        session.execute(delete(DecisionRow).where(DecisionRow.finding_id.in_(finding_ids)))

    evidence_rows = {
        row.finding_id: row
        for row in session.scalars(
            select(EvidenceRow).where(EvidenceRow.finding_id.in_([f.finding_id for f in findings]))
        ).all()
    } if findings else {}

    static_rows = session.scalars(
        select(StaticResultRow).where(StaticResultRow.review_id == review.review_id)
    ).all()

    groups = correlate_findings(findings)
    group_by_finding = {
        finding_id: group for group in groups for finding_id in group.finding_ids
    }

    decisions: list[Decision] = []
    for finding in findings:
        evidence = evidence_rows.get(finding.finding_id)
        score, reasons = _score(finding, evidence, static_rows)
        status, confidence = _decide(score, evidence, finding)

        group = group_by_finding[finding.finding_id]
        if len(group.finding_ids) > 1:
            reasons.append(f"{len(group.finding_ids)} nearby candidate findings were correlated for the same category and file")

        if reasons:
            reason = f"Evidence score {score:.1f}/100: " + "; ".join(reasons) + "."
        else:
            reason = f"Evidence score {score:.1f}/100: no supporting evidence was established."

        decision = Decision(
            decision_id=uuid.uuid4().hex,
            finding_id=finding.finding_id,
            status=status,  # type: ignore[arg-type]
            evidence_score=score,
            confidence=confidence,
            reason=reason,
            remediation=_REMEDIATION.get(finding.category),
        )
        decisions.append(decision)
        session.add(
            DecisionRow(
                decision_id=decision.decision_id,
                finding_id=decision.finding_id,
                status=decision.status,
                evidence_score=decision.evidence_score,
                confidence=decision.confidence,
                reason=decision.reason,
                remediation=decision.remediation,
            )
        )

    session.flush()
    return decisions
