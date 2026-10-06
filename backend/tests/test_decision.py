from app.models import EvidenceRow, FindingRow, ReviewRow, StaticResultRow, utcnow
from app.processing.decision import correlate_findings, run_decision_review


def _review():
    return ReviewRow(review_id="r1", project_name="p", language="python", status="RUNNING", created_at=utcnow(), target_path="/x")


def _finding(fid, category="sql_injection", line=2, agent="security_review"):
    return FindingRow(
        finding_id=fid, review_id="r1", agent=agent, title="t", category=category,
        severity="HIGH", file="a.py", start_line=line, end_line=line, description="d",
    )


def test_correlates_nearby_same_category_findings():
    groups = correlate_findings([_finding("f1", line=2), _finding("f2", line=4), _finding("f3", line=20)])
    assert {tuple(g.finding_ids) for g in groups} == {("f1", "f2"), ("f3",)}


def test_verified_when_concrete_evidence_and_static_corroboration(tmp_path):
    from app.database import init_db, make_engine, make_session_factory
    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1"))
    s.flush()
    s.add(EvidenceRow(
        evidence_id="e1", finding_id="f1",
        source={"found": True}, sink={"found": True},
        data_flow={"found": True, "path": ["user", "execute"]},
        security_control={"present": False},
    ))
    s.add(StaticResultRow(result_id="s1", review_id="r1", finding_id="f1", tool="bandit", matched=True, rule_id="B608"))
    s.commit()

    decisions = run_decision_review(s, s.get(ReviewRow, "r1"))
    assert decisions[0].status == "VERIFIED"
    assert decisions[0].evidence_score >= 70
    assert 0 <= decisions[0].confidence <= 1


def test_secure_control_rejects_without_flow(tmp_path):
    from app.database import init_db, make_engine, make_session_factory
    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1"))
    s.flush()
    s.add(EvidenceRow(
        evidence_id="e1", finding_id="f1",
        source={"found": True}, sink={"found": False},
        data_flow={"found": False, "path": []},
        security_control={"present": True},
    ))
    s.commit()
    decisions = run_decision_review(s, s.get(ReviewRow, "r1"))
    assert decisions[0].status == "REJECTED"


def test_rerun_replaces_decisions(tmp_path):
    from app.database import init_db, make_engine, make_session_factory
    from sqlalchemy import select
    from app.models import DecisionRow
    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1"))
    s.flush()
    s.add(EvidenceRow(evidence_id="e1", finding_id="f1", source=None, sink=None,
                      data_flow={"found": False, "path": []}, security_control={"present": False}))
    s.commit()
    r = s.get(ReviewRow, "r1")
    first = run_decision_review(s, r)
    second = run_decision_review(s, r)
    s.commit()
    rows = s.scalars(select(DecisionRow).where(DecisionRow.finding_id == "f1")).all()
    assert len(rows) == 1
    assert first[0].status == second[0].status == "REJECTED"
