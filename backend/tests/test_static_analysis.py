from app.models import FindingRow, ReviewRow
from app.processing.static_analysis import run_static_analysis
from app.schemas import StaticAnalysisResult
from app.database import init_db, make_engine, make_session_factory


def _cfg(bandit=False, ast_rules=True):
    return type("Cfg", (), {"static_analysis": type("SA", (), {
        "bandit": type("T", (), {"enabled": bandit})(),
        "ast_rules": type("T", (), {"enabled": ast_rules})(),
    })()})()


def test_ast_rules_map_sql_and_command_findings(tmp_path):
    root = tmp_path / "project"; root.mkdir()
    (root / "v.py").write_text(
        "def f(username, directory, connection):\n"
        "    query = 'SELECT * FROM users WHERE name=' + username\n"
        "    connection.execute(query)\n"
        "    import subprocess\n"
        "    subprocess.run('ls ' + directory, shell=True)\n"
    )
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}"); init_db(engine); db = make_session_factory(engine)()
    review = ReviewRow(review_id="r1", project_name="p", language="python", status="RUNNING", target_path=str(root))
    db.add(review)
    db.add_all([
        FindingRow(finding_id="f1", review_id="r1", agent="security_review", title="SQL", category="sql_injection", severity="HIGH", file="v.py", start_line=1, end_line=3, description="d"),
        FindingRow(finding_id="f2", review_id="r1", agent="security_review", title="CMD", category="command_injection", severity="HIGH", file="v.py", start_line=4, end_line=7, description="d"),
    ])
    db.flush()
    rows = run_static_analysis(db, review, _cfg())
    assert {r.rule_id for r in rows} == {"AST-SQL-001", "AST-CMD-001"}
    assert {r.finding_id for r in rows} == {"f1", "f2"}
    assert all(r.matched for r in rows)


def test_static_result_schema_accepts_ast_rules():
    value = StaticAnalysisResult.model_validate({"result_id": "s1", "finding_id": None, "tool": "ast_rules", "matched": True})
    assert value.tool == "ast_rules"


def test_static_rules_map_unique_file_category_when_candidate_lines_are_imprecise(tmp_path):
    root = tmp_path / "project"; root.mkdir()
    (root / "v.py").write_text(
        "def f(directory):\n"
        "    import subprocess\n"
        "    subprocess.run('ls ' + directory, shell=True)\n"
    )
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}"); init_db(engine); db = make_session_factory(engine)()
    review = ReviewRow(review_id="r1", project_name="p", language="python", status="RUNNING", target_path=str(root))
    db.add(review)
    db.add(FindingRow(
        finding_id="f1", review_id="r1", agent="security_review", title="CMD",
        category="command_injection", severity="HIGH", file="v.py",
        start_line=1, end_line=1, description="d"
    ))
    db.flush()
    rows = run_static_analysis(db, review, _cfg())
    assert len(rows) == 1
    assert rows[0].rule_id == "AST-CMD-001"
    assert rows[0].finding_id == "f1"
    assert rows[0].matched is True
