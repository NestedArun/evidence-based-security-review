import json
import shutil

from jsonschema import Draft202012Validator, FormatChecker

DATASET_REL = "dataset"


def _create(client, path, name="demo"):
    return client.post("/reviews", json={"project_name": name, "project_path": str(path)})


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_create_review_matches_review_schema(client, repo_root, make_project):
    root = make_project({"a.py": "x = 1\n"})
    r = _create(client, root)
    assert r.status_code == 201
    body = r.json()
    schema = json.loads((repo_root / "schemas" / "review.schema.json").read_text())
    assert not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(body))
    assert body["status"] == "PENDING" and body["language"] == "python"
    assert "target_path" not in body


def test_create_review_validation_errors(client, tmp_path):
    assert _create(client, tmp_path / "missing").status_code == 400
    f = tmp_path / "file.txt"
    f.write_text("x")
    assert _create(client, f).status_code == 400
    assert client.post("/reviews", json={"project_name": "", "project_path": str(tmp_path)}).status_code == 422
    assert client.post("/reviews", json={"project_name": "p"}).status_code == 422
    assert client.post("/reviews", json={"project_name": "p", "project_path": ".", "x": 1}).status_code == 422


def test_get_and_list_reviews(client, make_project):
    root = make_project({"a.py": "x = 1\n"})
    ids = [_create(client, root, f"p{i}").json()["review_id"] for i in range(2)]
    assert client.get(f"/reviews/{ids[0]}").json()["project_name"] == "p0"
    assert [r["review_id"] for r in client.get("/reviews").json()] == ids
    assert client.get("/reviews/nope").status_code == 404


def test_process_dataset_end_to_end(client, repo_root):
    review_id = _create(client, repo_root / DATASET_REL).json()["review_id"]
    r = client.post(f"/reviews/{review_id}/process")
    assert r.status_code == 200
    s = r.json()
    assert (s["files_discovered"], s["files_processed"], s["files_skipped"]) == (10, 10, 0)
    assert s["status"] == "RUNNING"
    assert client.get(f"/reviews/{review_id}").json()["status"] == "RUNNING"

    units = client.get(f"/reviews/{review_id}/code-units").json()
    assert s["code_units"] == len(units)
    # Paths are relative to the reviewed root so they line up with ground-truth "file" values.
    files = {u["file"] for u in units}
    assert "vulnerable/V001_sql_injection.py" in files and "secure/S005_auth_authorization.py" in files

    v3 = client.get(f"/reviews/{review_id}/code-units", params={"file": "vulnerable/V003_hardcoded_secret.py"}).json()
    assert [(u["unit_type"], u["start_line"], u["end_line"]) for u in v3] == [("module", 1, 1), ("function", 3, 4)]
    assert 'API_KEY = "demo-production-api-key-12345"' in v3[0]["source_code"]

    v5 = client.get(f"/reviews/{review_id}/code-units", params={"file": "vulnerable/V005_auth_authorization.py"}).json()
    assert [(u["function_name"], u["start_line"], u["end_line"]) for u in v5] == [("get_admin_report", 1, 5)]

    for u in units:
        assert set(u) == {"unit_id", "review_id", "file", "language", "start_line", "end_line",
                          "unit_type", "function_name", "class_name", "chunk_index", "source_code"}


def test_process_reports_skipped_files_and_file_metadata(client, make_project):
    root = make_project({"a.py": "def f():\n    return 1\n", "notes.txt": "hi", "meta.json": "{}", "bad.py": b"\xff\xfe\x00"})
    rid = _create(client, root).json()["review_id"]
    s = client.post(f"/reviews/{rid}/process").json()
    # notes.txt / meta.json are not source files: not discovered, not reported as skipped.
    assert (s["files_discovered"], s["files_processed"], s["files_skipped"]) == (2, 1, 1)
    assert {(x["file"], x["reason"]) for x in s["skipped"]} == {("bad.py", "not_utf8")}
    files = {f["path"]: f for f in client.get(f"/reviews/{rid}/files").json()}
    assert files["a.py"]["processed"] and files["a.py"]["line_count"] == 2 and len(files["a.py"]["sha256"]) == 64
    assert not files["bad.py"]["processed"] and files["bad.py"]["skip_reason"] == "not_utf8"


def test_non_source_files_are_not_discovered(client, make_project):
    root = make_project({"ground_truth.json": "{}", "a.py": "x = 1\n"})
    rid = _create(client, root).json()["review_id"]
    s = client.post(f"/reviews/{rid}/process").json()
    assert (s["files_discovered"], s["files_processed"], s["files_skipped"]) == (1, 1, 0)
    assert [f["path"] for f in client.get(f"/reviews/{rid}/files").json()] == ["a.py"]


def test_syntax_error_file_is_flagged(client, make_project):
    root = make_project({"b.py": "def ok():\n    return 1\n\ndef broken(:\n    pass\n"})
    rid = _create(client, root).json()["review_id"]
    client.post(f"/reviews/{rid}/process")
    (f,) = client.get(f"/reviews/{rid}/files").json()
    assert f["processed"] and f["has_syntax_errors"]


def test_reprocessing_running_review_is_rejected(client, make_project):
    rid = _create(client, make_project({"a.py": "x = 1\n"})).json()["review_id"]
    assert client.post(f"/reviews/{rid}/process").status_code == 200
    assert client.post(f"/reviews/{rid}/process").status_code == 409
    assert client.post("/reviews/nope/process").status_code == 404


def test_failed_processing_is_reported_and_recoverable(client, make_project):
    root = make_project({"a.py": "def f():\n    return 1\n"})
    rid = _create(client, root).json()["review_id"]
    saved = root.parent / "saved"
    shutil.move(root, saved)  # project vanishes after review creation
    r = client.post(f"/reviews/{rid}/process")
    assert r.status_code == 500 and "not a directory" in r.json()["detail"]
    assert client.get(f"/reviews/{rid}").json()["status"] == "FAILED"
    assert client.get(f"/reviews/{rid}/code-units").json() == []  # nothing fabricated

    shutil.move(saved, root)
    assert client.post(f"/reviews/{rid}/process").status_code == 200
    assert client.get(f"/reviews/{rid}").json()["status"] == "RUNNING"
    assert len(client.get(f"/reviews/{rid}/code-units").json()) == 1


def test_submitted_code_is_never_executed(client, make_project):
    marker = make_project({}, name="markers") / "pwned.txt"
    evil = (f"open({str(marker)!r}, 'w').write('x')\n"
            "raise SystemExit('executed!')\n"
            "def f():\n    pass\n")
    root = make_project({"evil.py": evil})
    before = (root / "evil.py").read_bytes()
    rid = _create(client, root).json()["review_id"]
    assert client.post(f"/reviews/{rid}/process").status_code == 200
    assert not marker.exists()
    assert (root / "evil.py").read_bytes() == before  # analysed source is not modified
    assert client.get(f"/reviews/{rid}/code-units").json()[0]["unit_type"] == "module"
