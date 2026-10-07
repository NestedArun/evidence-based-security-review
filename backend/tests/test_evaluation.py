import json

from app.models import DecisionRow, EvidenceRow, FindingRow, ReviewRow, StaticResultRow, utcnow
from app.processing.evaluation import evaluate_review, load_ground_truth


def _review():
    return ReviewRow(
        review_id="r1",
        project_name="p",
        language="python",
        status="RUNNING",
        created_at=utcnow(),
        target_path="/x",
    )


def _finding(fid, file, category, line, agent="security_review"):
    return FindingRow(
        finding_id=fid,
        review_id="r1",
        agent=agent,
        title="candidate",
        category=category,
        severity="HIGH",
        file=file,
        start_line=line,
        end_line=line,
        description="candidate",
    )


def _ground_truth(tmp_path):
    path = tmp_path / "ground_truth.json"
    path.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "id": "V1",
                        "file": "vulnerable/V1.py",
                        "category": "sql_injection",
                        "expected_vulnerable": True,
                        "start_line": 5,
                        "end_line": 5,
                    },
                    {
                        "id": "S1",
                        "file": "secure/S1.py",
                        "category": "sql_injection",
                        "expected_vulnerable": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_evaluation_counts_tp_fn_tn_and_fp(tmp_path):
    from app.database import init_db, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1", "vulnerable/V1.py", "sql_injection", 5))
    s.add(_finding("f2", "secure/S1.py", "sql_injection", 3))
    s.add(_finding("f3", "unrelated.py", "sql_injection", 1))
    s.commit()

    result = evaluate_review(s, s.get(ReviewRow, "r1"), "single_llm", _ground_truth(tmp_path))
    assert (result.true_positives, result.false_positives, result.false_negatives, result.true_negatives) == (1, 1, 0, 0)
    assert result.precision == 0.5
    assert result.recall == 1.0


def test_multi_agent_deduplicates_at_sample_level(tmp_path):
    from app.database import init_db, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1", "vulnerable/V1.py", "sql_injection", 5, "security_review"))
    s.add(_finding("f2", "vulnerable/V1.py", "sql_injection", 5, "owasp_cwe"))
    s.commit()

    result = evaluate_review(s, s.get(ReviewRow, "r1"), "multi_agent", _ground_truth(tmp_path))
    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.predictions == 2


def test_proposed_uses_only_verified_decisions_and_calculates_evidence(tmp_path):
    from app.database import init_db, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    s.add(_review())
    s.add(_finding("f1", "vulnerable/V1.py", "sql_injection", 5))
    s.add(_finding("f2", "secure/S1.py", "sql_injection", 3))
    s.flush()
    s.add_all(
        [
            DecisionRow(
                decision_id="d1",
                finding_id="f1",
                status="VERIFIED",
                evidence_score=85,
                confidence=0.85,
                reason="verified",
            ),
            DecisionRow(
                decision_id="d2",
                finding_id="f2",
                status="REJECTED",
                evidence_score=0,
                confidence=0.9,
                reason="rejected",
            ),
            EvidenceRow(
                evidence_id="e1",
                finding_id="f1",
                source={"found": True},
                sink={"found": True},
                data_flow={"found": True, "path": ["input", "execute"]},
                security_control={"present": False},
            ),
            StaticResultRow(
                result_id="s1",
                review_id="r1",
                finding_id="f1",
                tool="bandit",
                matched=True,
                rule_id="B608",
            ),
        ]
    )
    s.commit()

    result = evaluate_review(s, s.get(ReviewRow, "r1"), "proposed", _ground_truth(tmp_path))
    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.true_negatives == 1
    assert result.evidence_completeness == 1.0



def test_evaluation_resolves_review_relative_paths_within_dataset_scope(tmp_path):
    from app.database import init_db, make_engine, make_session_factory

    dataset = tmp_path / "dataset"
    vulnerable = dataset / "vulnerable"
    vulnerable.mkdir(parents=True)
    ground_truth = dataset / "ground_truth.json"
    ground_truth.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "id": "V1",
                        "file": "vulnerable/V1.py",
                        "category": "sql_injection",
                        "expected_vulnerable": True,
                        "start_line": 5,
                        "end_line": 5,
                    },
                    {
                        "id": "S1",
                        "file": "secure/S1.py",
                        "category": "sql_injection",
                        "expected_vulnerable": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    engine = make_engine(f"sqlite:///{tmp_path / 'd.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    review = ReviewRow(
        review_id="r1",
        project_name="vulnerable-only",
        language="python",
        status="COMPLETED",
        created_at=utcnow(),
        target_path=str(vulnerable),
    )
    s.add(review)
    s.add(_finding("f1", "V1.py", "sql_injection", 5))
    s.commit()

    result = evaluate_review(s, review, "single_llm", ground_truth)

    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.true_negatives == 0
    assert result.matched_samples == 1
    assert result.predictions == 1
