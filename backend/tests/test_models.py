from datetime import timezone

from sqlalchemy import select, text

from app.database import init_db, make_engine, make_session_factory
from app.models import (CodeUnitRow, DecisionRow, EvidenceRow, FindingRow, ReviewRow,
                        SourceFileRow, StaticResultRow, utcnow)


def _session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'm.db'}")
    init_db(engine)
    return make_session_factory(engine)()


def _review():
    return ReviewRow(review_id="r1", project_name="p", language="python",
                     status="PENDING", created_at=utcnow(), target_path="/x")


def test_all_tables_round_trip_and_keep_decision_separate(tmp_path):
    s = _session(tmp_path)
    s.add(_review())
    s.add(FindingRow(finding_id="f1", review_id="r1", agent="auth", title="t",
                     category="authentication_authorization", severity="HIGH",
                     file="a.py", start_line=2, description="d"))
    s.flush()
    s.add_all([
        EvidenceRow(evidence_id="e1", finding_id="f1", source={"found": True}, sink=None,
                    data_flow={"found": False, "path": []}, security_control={"present": False}),
        StaticResultRow(result_id="s1", finding_id=None, tool="semgrep", matched=False),
        StaticResultRow(result_id="s2", finding_id="f1", tool="bandit", matched=True, rule_id="B303"),
        DecisionRow(decision_id="d1", finding_id="f1", status="UNCERTAIN",
                    evidence_score=40.0, confidence=0.4, reason="r"),
        SourceFileRow(file_id="sf1", review_id="r1", path="a.py", language="python",
                      size_bytes=1, processed=True),
        CodeUnitRow(unit_id="u1", review_id="r1", file="a.py", language="python",
                    start_line=1, end_line=2, unit_type="function", source_code="x"),
    ])
    s.commit()
    assert s.get(EvidenceRow, "e1").source == {"found": True}
    assert s.get(DecisionRow, "d1").status == "UNCERTAIN"
    # Final decision/confidence must not live on the finding row.
    assert not hasattr(FindingRow, "confidence") and not hasattr(FindingRow, "status")


def test_created_at_is_timezone_aware_utc(tmp_path):
    s = _session(tmp_path)
    s.add(_review())
    s.commit()
    s.expire_all()
    assert s.get(ReviewRow, "r1").created_at.tzinfo == timezone.utc


def test_foreign_keys_enforced_and_cascade(tmp_path):
    s = _session(tmp_path)
    s.add(_review())
    s.add(CodeUnitRow(unit_id="u1", review_id="r1", file="a.py", language="python",
                      start_line=1, end_line=1, unit_type="module", source_code="x"))
    s.commit()
    s.execute(text("DELETE FROM reviews WHERE review_id='r1'"))
    s.commit()
    assert s.scalars(select(CodeUnitRow)).all() == []

    s.add(CodeUnitRow(unit_id="u2", review_id="missing", file="a.py", language="python",
                      start_line=1, end_line=1, unit_type="module", source_code="x"))
    import sqlalchemy.exc as exc
    try:
        s.commit()
        raised = False
    except exc.IntegrityError:
        raised = True
    assert raised
