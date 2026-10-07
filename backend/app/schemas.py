"""Pydantic models.

Review / CandidateFinding / Evidence / StaticAnalysisResult / Decision mirror the
canonical JSON schemas in ``schemas/`` (``extra="forbid"`` + strict types, matching
``additionalProperties: false``). ``tests/test_schema_contracts.py`` fails if they drift.

CodeUnit has NO schema file in ``schemas/``; its fields come from ARCHITECTURE.md
section 5 ("Code-unit metadata"). Request/summary models below are API plumbing only.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Language = Literal["python"]
ReviewStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED"]
AgentName = Literal["security_review", "owasp_cwe", "crypto", "auth"]
Category = Literal[
    "sql_injection",
    "command_injection",
    "hardcoded_secret",
    "weak_cryptography",
    "authentication_authorization",
]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
DecisionStatus = Literal["VERIFIED", "UNCERTAIN", "REJECTED"]
StaticTool = Literal["bandit", "ast_rules"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, from_attributes=True)


# --------------------------------------------------------------------------- schemas/
class Review(_Contract):
    review_id: str
    project_name: str
    language: Language
    status: ReviewStatus
    created_at: datetime


class CandidateFinding(_Contract):
    finding_id: str
    review_id: str
    agent: AgentName
    title: str
    category: Category
    cwe: str | None = None
    severity: Severity
    file: str
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    function: str | None = None
    description: str
    reasoning: str | None = None

    @model_validator(mode="after")
    def _end_not_before_start(self) -> "CandidateFinding":
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class LocatedEvidence(_Contract):
    """Shared shape of the ``source`` and ``sink`` evidence objects."""

    found: bool
    file: str | None = None
    line: int | None = None
    code: str | None = None
    description: str | None = None


class DataFlowEvidence(_Contract):
    found: bool
    path: list[str] = Field(default_factory=list)
    description: str | None = None


class SecurityControlEvidence(_Contract):
    present: bool
    description: str | None = None


class Evidence(_Contract):
    evidence_id: str
    finding_id: str
    source: LocatedEvidence | None = None
    sink: LocatedEvidence | None = None
    data_flow: DataFlowEvidence | None = None
    security_control: SecurityControlEvidence | None = None


class StaticAnalysisResult(_Contract):
    result_id: str
    finding_id: str | None
    tool: StaticTool
    matched: bool
    rule_id: str | None = None
    severity: str | None = None
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    message: str | None = None


class Decision(_Contract):
    decision_id: str
    finding_id: str
    status: DecisionStatus
    evidence_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    reason: str
    remediation: str | None = None


EvaluationMode = Literal["single_llm", "multi_agent", "proposed"]


class EvaluationResult(_Contract):
    review_id: str
    mode: EvaluationMode
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)
    evidence_completeness: float = Field(ge=0, le=1)
    predictions: int = Field(ge=0)
    matched_samples: int = Field(ge=0)


# ------------------------------------------------------- code processing (no schema file)
UnitType = Literal["function", "method", "class", "module"]


class CodeUnit(BaseModel):
    """Structured code unit with preserved metadata (ARCHITECTURE.md section 5)."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    unit_id: str
    review_id: str
    file: str  # path relative to the reviewed project root (POSIX separators)
    language: Language
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    unit_type: UnitType
    function_name: str | None = None
    class_name: str | None = None
    chunk_index: int | None = None  # set only when a long unit was split into chunks
    source_code: str


# ------------------------------------------------------------------ API request/response
class ReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_name: str = Field(min_length=1)
    project_path: str = Field(min_length=1)


class SourceFileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    path: str
    language: str | None
    size_bytes: int
    sha256: str | None
    line_count: int | None
    processed: bool
    skip_reason: str | None
    has_syntax_errors: bool


class SkippedFile(BaseModel):
    file: str
    reason: str


class ProcessingSummary(BaseModel):
    review_id: str
    status: ReviewStatus
    files_discovered: int
    files_processed: int
    files_skipped: int
    code_units: int
    skipped: list[SkippedFile]


class EvidenceProcessingSummary(BaseModel):
    review_id: str
    findings: int
    evidence_created: int
    status: ReviewStatus


class AIProcessingSummary(BaseModel):
    review_id: str
    agents: list[AgentName]
    code_units: int
    findings: int
    status: ReviewStatus


class FindingOut(CandidateFinding):
    pass
