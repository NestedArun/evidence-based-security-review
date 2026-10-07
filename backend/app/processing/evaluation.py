"""Checkpoint 6: reproducible evaluation against manually verified ground truth.

Evaluation is deliberately downstream of prediction. Ground-truth labels are loaded
only by this module and are never passed to the review agents.

The three selectable configurations are represented as prediction views over the
same persisted review run:
- single_llm: the broad security_review agent only
- multi_agent: findings from all specialized agents
- proposed: findings whose persisted Judge decision is VERIFIED

This keeps the prototype locally executable while making the configurations
explicit and comparable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DecisionRow, EvidenceRow, FindingRow, ReviewRow, StaticResultRow

EvaluationMode = Literal["single_llm", "multi_agent", "proposed"]


@dataclass(frozen=True)
class GroundTruthSample:
    sample_id: str
    file: str
    category: str
    expected_vulnerable: bool
    start_line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class EvaluationResult:
    review_id: str
    mode: EvaluationMode
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    evidence_completeness: float
    predictions: int
    matched_samples: int


def load_ground_truth(path: Path) -> list[GroundTruthSample]:
    """Load researcher-approved ground truth; never mutate it."""
    with path.open(encoding="utf-8") as fh:
        payload = json.load(fh)

    samples: list[GroundTruthSample] = []
    for raw in payload.get("samples", []):
        samples.append(
            GroundTruthSample(
                sample_id=str(raw["id"]),
                file=str(raw["file"]).replace("\\", "/"),
                category=str(raw["category"]),
                expected_vulnerable=bool(raw["expected_vulnerable"]),
                start_line=raw.get("start_line"),
                end_line=raw.get("end_line"),
            )
        )
    return samples


def _dataset_target_prefix(review: ReviewRow, ground_truth_path: Path) -> str | None:
    """Return the reviewed target's path relative to the dataset root when applicable.

    Ground truth stores paths relative to ``dataset/``. Review findings store paths
    relative to the review target. When a review targets ``dataset/vulnerable``,
    ``V001_sql_injection.py`` therefore corresponds to
    ``vulnerable/V001_sql_injection.py`` in ground truth.
    """
    dataset_root = ground_truth_path.parent.resolve()
    target_root = Path(review.target_path).resolve()

    try:
        relative = target_root.relative_to(dataset_root)
    except ValueError:
        return None

    return relative.as_posix() if relative.as_posix() != "." else ""


def _samples_for_review(
    samples: list[GroundTruthSample],
    review: ReviewRow,
    ground_truth_path: Path,
) -> list[GroundTruthSample]:
    """Limit ground-truth samples to the portion of the dataset being reviewed."""
    prefix = _dataset_target_prefix(review, ground_truth_path)
    if prefix is None:
        return samples

    if not prefix:
        return samples

    prefix_with_slash = f"{prefix}/"
    return [sample for sample in samples if sample.file == prefix or sample.file.startswith(prefix_with_slash)]


def _prediction_file_for_review(
    prediction: FindingRow,
    review: ReviewRow,
    ground_truth_path: Path,
) -> str:
    """Map a finding's review-relative path into ground-truth dataset coordinates."""
    prefix = _dataset_target_prefix(review, ground_truth_path)
    file = prediction.file.replace("\\", "/")
    if prefix:
        return f"{prefix}/{file}"
    return file


def _overlaps(prediction_file: str, prediction: FindingRow, sample: GroundTruthSample) -> bool:
    if prediction_file.replace("\\", "/") != sample.file:
        return False
    if prediction.category != sample.category:
        return False
    if sample.start_line is None:
        return True

    pred_end = prediction.end_line or prediction.start_line
    sample_end = sample.end_line or sample.start_line
    return prediction.start_line <= sample_end and sample.start_line <= pred_end


def _predictions_for_mode(
    findings: list[FindingRow],
    decisions: dict[str, DecisionRow],
    mode: EvaluationMode,
) -> list[FindingRow]:
    if mode == "single_llm":
        return [f for f in findings if f.agent == "security_review"]
    if mode == "multi_agent":
        return findings
    return [f for f in findings if decisions.get(f.finding_id) and decisions[f.finding_id].status == "VERIFIED"]


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _evidence_completeness(
    predictions: list[FindingRow],
    evidence: dict[str, EvidenceRow],
    static: list[StaticResultRow],
) -> float:
    """Average established evidence elements over predicted findings.

    Five elements are checked: source, sink, data flow, security-control record,
    and matched static-analysis corroboration. A present=False security-control
    object still counts as established evidence because it is a verified finding
    that the control is absent.
    """
    if not predictions:
        return 0.0

    static_by_finding: dict[str, bool] = {}
    for row in static:
        if row.finding_id and row.matched:
            static_by_finding[row.finding_id] = True

    total = 0
    for finding in predictions:
        ev = evidence.get(finding.finding_id)
        if ev is None:
            continue
        total += sum(
            (
                ev.source is not None,
                ev.sink is not None,
                ev.data_flow is not None,
                ev.security_control is not None,
                static_by_finding.get(finding.finding_id, False),
            )
        )

    return round(total / (len(predictions) * 5), 4)


def evaluate_review(
    session: Session,
    review: ReviewRow,
    mode: EvaluationMode,
    ground_truth_path: Path,
) -> EvaluationResult:
    """Calculate actual metrics from persisted predictions and ground truth."""
    samples = _samples_for_review(load_ground_truth(ground_truth_path), review, ground_truth_path)
    findings = session.scalars(
        select(FindingRow)
        .where(FindingRow.review_id == review.review_id)
        .order_by(FindingRow.file, FindingRow.start_line, FindingRow.finding_id)
    ).all()
    finding_ids = [f.finding_id for f in findings]

    decisions = {
        d.finding_id: d
        for d in session.scalars(
            select(DecisionRow).where(DecisionRow.finding_id.in_(finding_ids))
        ).all()
    } if finding_ids else {}

    evidence = {
        e.finding_id: e
        for e in session.scalars(
            select(EvidenceRow).where(EvidenceRow.finding_id.in_(finding_ids))
        ).all()
    } if finding_ids else {}

    static = session.scalars(
        select(StaticResultRow).where(StaticResultRow.review_id == review.review_id)
    ).all()

    predictions = _predictions_for_mode(findings, decisions, mode)

    tp = fp = fn = tn = 0
    matched_ids: set[str] = set()

    # Sample-level matching avoids counting duplicate agent findings as separate
    # vulnerabilities. This is intentionally simple and reproducible.
    for sample in samples:
        matched = [
            f
            for f in predictions
            if _overlaps(_prediction_file_for_review(f, review, ground_truth_path), f, sample)
        ]
        if sample.expected_vulnerable:
            if matched:
                tp += 1
                matched_ids.add(sample.sample_id)
            else:
                fn += 1
        elif matched:
            fp += 1
        else:
            tn += 1

    return EvaluationResult(
        review_id=review.review_id,
        mode=mode,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=_safe_ratio(tp, tp + fp),
        recall=_safe_ratio(tp, tp + fn),
        false_positive_rate=_safe_ratio(fp, fp + tn),
        evidence_completeness=_evidence_completeness(predictions, evidence, static),
        predictions=len(predictions),
        matched_samples=len(matched_ids),
    )
