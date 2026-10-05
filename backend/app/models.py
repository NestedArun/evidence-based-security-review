"""SQLAlchemy database models.

Tables for Review/Finding/Evidence/StaticResult/Decision mirror schemas/*.json.
Final decision/confidence live ONLY in ``decisions`` (never on findings), per
AI_BUILD_INSTRUCTIONS.md section 5. ``source_files`` and ``code_units`` come from the
Code Processing Layer (ARCHITECTURE.md section 5).

Checkpoint 1 only reads/writes reviews, source_files and code_units; the other
tables are created now so later checkpoints do not need schema changes.

Child tables declare a (never lazily loaded) many-to-one ``_parent`` relationship so
SQLAlchemy inserts parents before children inside a single flush.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.database import Base


class UTCDateTime(TypeDecorator):
    """Store naive UTC in SQLite, always return timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ReviewRow(Base):
    __tablename__ = "reviews"

    review_id: Mapped[str] = mapped_column(String, primary_key=True)
    project_name: Mapped[str] = mapped_column(String, nullable=False)
    language: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    # Internal (not part of the Review schema / API contract):
    target_path: Mapped[str] = mapped_column(Text, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class SourceFileRow(Base):
    __tablename__ = "source_files"

    file_id: Mapped[str] = mapped_column(String, primary_key=True)
    review_id: Mapped[str] = mapped_column(
        ForeignKey("reviews.review_id", ondelete="CASCADE"), index=True, nullable=False
    )
    path: Mapped[str] = mapped_column(Text, nullable=False)  # relative to project root, POSIX
    language: Mapped[str | None] = mapped_column(String, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    line_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    skip_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    has_syntax_errors: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    _parent: Mapped["ReviewRow"] = relationship(lazy="raise")  # insert-ordering only



class CodeUnitRow(Base):
    __tablename__ = "code_units"

    unit_id: Mapped[str] = mapped_column(String, primary_key=True)
    review_id: Mapped[str] = mapped_column(
        ForeignKey("reviews.review_id", ondelete="CASCADE"), index=True, nullable=False
    )
    file: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_type: Mapped[str] = mapped_column(String, nullable=False)
    function_name: Mapped[str | None] = mapped_column(String, nullable=True)
    class_name: Mapped[str | None] = mapped_column(String, nullable=True)
    chunk_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_code: Mapped[str] = mapped_column(Text, nullable=False)
    _parent: Mapped["ReviewRow"] = relationship(lazy="raise")  # insert-ordering only



class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    review_id: Mapped[str] = mapped_column(
        ForeignKey("reviews.review_id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    file: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    function: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    _parent: Mapped["ReviewRow"] = relationship(lazy="raise")  # insert-ordering only



class EvidenceRow(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.finding_id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sink: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    data_flow: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    security_control: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    _parent: Mapped["FindingRow"] = relationship(lazy="raise")  # insert-ordering only



class StaticResultRow(Base):
    __tablename__ = "static_results"

    result_id: Mapped[str] = mapped_column(String, primary_key=True)
    # Nullable per schema: a tool may report an issue not tied to any finding.
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.finding_id", ondelete="CASCADE"), index=True, nullable=True
    )
    tool: Mapped[str] = mapped_column(String, nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    file: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    _parent: Mapped["FindingRow"] = relationship(lazy="raise")  # insert-ordering only



class DecisionRow(Base):
    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.finding_id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String, nullable=False)
    evidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    _parent: Mapped["FindingRow"] = relationship(lazy="raise")  # insert-ordering only
