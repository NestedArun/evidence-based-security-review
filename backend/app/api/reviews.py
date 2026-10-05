"""Basic review API (Checkpoint 1).

POST /reviews                    create a review for a local project directory
GET  /reviews, /reviews/{id}     list / read reviews (Review schema)
POST /reviews/{id}/process       run Code Processing for the review
GET  /reviews/{id}/files         discovered source files and skip reasons
GET  /reviews/{id}/code-units    extracted code units

Status semantics for now: PENDING -> (process) -> RUNNING. The review stays RUNNING
after processing because the remaining pipeline stages (Checkpoints 2-6) are not
implemented; COMPLETED is reserved for a finished pipeline and FAILED is set if
processing errors out. Nothing here executes the reviewed source code.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CodeUnitRow, ReviewRow, SourceFileRow, utcnow
from app.processing.service import process_review
from app.processing.ai import run_ai_review
from app.schemas import (
    CodeUnit,
    ProcessingSummary,
    Review,
    ReviewCreate,
    SourceFileOut,
    AIProcessingSummary,
    FindingOut,
)

router = APIRouter(prefix="/reviews", tags=["reviews"])


def get_db(request: Request):
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def _get_review_or_404(db: Session, review_id: str) -> ReviewRow:
    review = db.get(ReviewRow, review_id)
    if review is None:
        raise HTTPException(status_code=404, detail=f"Review not found: {review_id}")
    return review


@router.post("", response_model=Review, status_code=201)
def create_review(body: ReviewCreate, request: Request, db: Session = Depends(get_db)):
    target = Path(body.project_path).expanduser()
    if not target.is_dir():
        raise HTTPException(status_code=400, detail=f"project_path is not a directory: {body.project_path}")

    config = request.app.state.project_config
    review = ReviewRow(
        review_id=str(uuid.uuid4()),
        project_name=body.project_name,
        language=config.analysis.language,
        status="PENDING",
        created_at=utcnow(),
        target_path=str(target.resolve()),
    )
    db.add(review)
    db.commit()
    return Review.model_validate(review)


@router.get("", response_model=list[Review])
def list_reviews(db: Session = Depends(get_db)):
    rows = db.scalars(select(ReviewRow).order_by(ReviewRow.created_at, ReviewRow.review_id)).all()
    return [Review.model_validate(r) for r in rows]


@router.get("/{review_id}", response_model=Review)
def get_review(review_id: str, db: Session = Depends(get_db)):
    return Review.model_validate(_get_review_or_404(db, review_id))


@router.post("/{review_id}/process", response_model=ProcessingSummary)
def process(review_id: str, request: Request, db: Session = Depends(get_db)):
    review = _get_review_or_404(db, review_id)
    if review.status not in ("PENDING", "FAILED"):
        raise HTTPException(
            status_code=409,
            detail=f"Review is {review.status}; processing is only allowed for PENDING or FAILED reviews",
        )

    review.status = "RUNNING"
    review.error_message = None
    db.commit()

    try:
        summary = process_review(db, review, request.app.state.settings)
        db.commit()
    except Exception as exc:  # report the real error; never mark success silently
        db.rollback()
        review = _get_review_or_404(db, review_id)
        review.status = "FAILED"
        review.error_message = f"{type(exc).__name__}: {exc}"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Code processing failed: {review.error_message}")
    return summary


@router.get("/{review_id}/files", response_model=list[SourceFileOut])
def list_files(review_id: str, db: Session = Depends(get_db)):
    _get_review_or_404(db, review_id)
    rows = db.scalars(
        select(SourceFileRow).where(SourceFileRow.review_id == review_id).order_by(SourceFileRow.path)
    ).all()
    return [SourceFileOut.model_validate(r) for r in rows]


@router.get("/{review_id}/code-units", response_model=list[CodeUnit])
def list_code_units(
    review_id: str,
    file: str | None = Query(default=None, description="Filter by relative file path"),
    db: Session = Depends(get_db),
):
    _get_review_or_404(db, review_id)
    stmt = select(CodeUnitRow).where(CodeUnitRow.review_id == review_id)
    if file is not None:
        stmt = stmt.where(CodeUnitRow.file == file)
    rows = db.scalars(stmt.order_by(CodeUnitRow.file, CodeUnitRow.start_line, CodeUnitRow.chunk_index)).all()
    return [CodeUnit.model_validate(r) for r in rows]


@router.post("/{review_id}/ai-review", response_model=AIProcessingSummary)
def ai_review(review_id: str, request: Request, db: Session = Depends(get_db)):
    """Run the four Checkpoint-2 agents over persisted code units.

    Findings are hypotheses only. No evidence or final decision is created here.
    """
    review = _get_review_or_404(db, review_id)
    if review.status != "RUNNING":
        raise HTTPException(
            status_code=409,
            detail=f"Review is {review.status}; AI review requires a processed RUNNING review",
        )
    try:
        findings = run_ai_review(db, review, request.app.state.project_config)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=f"AI review failed: {type(exc).__name__}: {exc}") from exc

    return AIProcessingSummary(
        review_id=review.review_id,
        agents=["security_review", "owasp_cwe", "crypto", "auth"],
        code_units=db.query(CodeUnitRow).filter(CodeUnitRow.review_id == review_id).count(),
        findings=len(findings),
        status=review.status,
    )


@router.get("/{review_id}/findings", response_model=list[FindingOut])
def list_findings(review_id: str, db: Session = Depends(get_db)):
    _get_review_or_404(db, review_id)
    from app.models import FindingRow
    rows = db.scalars(
        select(FindingRow)
        .where(FindingRow.review_id == review_id)
        .order_by(FindingRow.file, FindingRow.start_line, FindingRow.agent, FindingRow.finding_id)
    ).all()
    return [FindingOut.model_validate(r) for r in rows]
