"""Code Processing Layer orchestration.

Project -> File Discovery -> Language Detection -> File Filtering -> Parsing
        -> Function/Class Extraction -> Code Chunking -> Metadata Attachment

This layer never decides whether a vulnerability exists (ARCHITECTURE.md section 5).
"""
from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import CodeUnitRow, ReviewRow, SourceFileRow
from app.processing.discovery import discover_files
from app.processing.parser import extract_units
from app.schemas import ProcessingSummary, SkippedFile


def process_review(session: Session, review: ReviewRow, settings: Settings) -> ProcessingSummary:
    """Run code processing for ``review`` and persist source files + code units.

    Re-running replaces any earlier processing output for the same review. Raises on
    unexpected errors (caller records them); it never fabricates results.
    """
    root = Path(review.target_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Project path is not a directory: {review.target_path}")

    session.execute(delete(CodeUnitRow).where(CodeUnitRow.review_id == review.review_id))
    session.execute(delete(SourceFileRow).where(SourceFileRow.review_id == review.review_id))

    discovered = discover_files(root, settings.excluded_dirs, settings.max_file_bytes)

    processed = 0
    unit_count = 0
    skipped: list[SkippedFile] = []

    for item in discovered:
        file_row = SourceFileRow(
            file_id=str(uuid.uuid4()),
            review_id=review.review_id,
            path=item.relative_path,
            language=item.language,
            size_bytes=item.size_bytes,
            sha256=item.sha256,
            line_count=None,
            processed=False,
            skip_reason=item.skip_reason,
            has_syntax_errors=False,
        )
        if item.skip_reason is None and item.text is not None and item.language == "python":
            result = extract_units(item.text, settings.max_unit_lines)
            lines = item.text.split("\n")
            file_row.line_count = len(lines) - 1 if lines and lines[-1] == "" else len(lines)
            file_row.processed = True
            file_row.has_syntax_errors = result.has_syntax_errors
            processed += 1
            for u in result.units:
                session.add(
                    CodeUnitRow(
                        unit_id=str(uuid.uuid4()),
                        review_id=review.review_id,
                        file=item.relative_path,
                        language=item.language,
                        start_line=u.start_line,
                        end_line=u.end_line,
                        unit_type=u.unit_type,
                        function_name=u.function_name,
                        class_name=u.class_name,
                        chunk_index=u.chunk_index,
                        source_code=u.source_code,
                    )
                )
                unit_count += 1
        else:
            skipped.append(SkippedFile(file=item.relative_path, reason=item.skip_reason or "unknown"))
        session.add(file_row)

    session.flush()
    return ProcessingSummary(
        review_id=review.review_id,
        status=review.status,  # type: ignore[arg-type]
        files_discovered=len(discovered),
        files_processed=processed,
        files_skipped=len(skipped),
        code_units=unit_count,
        skipped=skipped,
    )
