from types import SimpleNamespace

from app.evidence import verify_finding


def _review(repo_root):
    return SimpleNamespace(target_path=str(repo_root / "dataset"))


def _finding(file, category, line):
    return SimpleNamespace(
        finding_id=f"finding-{category}",
        file=file,
        category=category,
        start_line=line,
    )


def test_vulnerable_samples_produce_traceable_evidence(repo_root):
    expected = [
        ("vulnerable/V001_sql_injection.py", "sql_injection", 5),
        ("vulnerable/V002_command_injection.py", "command_injection", 5),
        ("vulnerable/V003_hardcoded_secret.py", "hardcoded_secret", 1),
        ("vulnerable/V004_weak_cryptography.py", "weak_cryptography", 4),
        ("vulnerable/V005_auth_authorization.py", "authentication_authorization", 1),
    ]

    for file, category, line in expected:
        evidence = verify_finding(_review(repo_root), _finding(file, category, line))
        assert evidence.source is not None and evidence.source.found
        assert evidence.sink is not None and evidence.sink.found
        assert evidence.data_flow is not None and evidence.data_flow.found
        assert evidence.security_control is not None and not evidence.security_control.present


def test_secure_sql_is_recognized_as_parameterized(repo_root):
    evidence = verify_finding(
        _review(repo_root),
        _finding("secure/S001_sql_injection.py", "sql_injection", 5),
    )
    assert evidence.source.found
    assert not evidence.sink.found
    assert not evidence.data_flow.found
    assert evidence.security_control.present


def test_secure_command_execution_disables_shell(repo_root):
    evidence = verify_finding(
        _review(repo_root),
        _finding("secure/S002_command_injection.py", "command_injection", 5),
    )
    assert not evidence.sink.found
    assert evidence.security_control.present


def test_secure_secret_uses_external_storage(repo_root):
    evidence = verify_finding(
        _review(repo_root),
        _finding("secure/S003_hardcoded_secret.py", "hardcoded_secret", 3),
    )
    assert not evidence.source.found
    assert evidence.security_control.present


def test_secure_crypto_uses_password_hashing_primitive(repo_root):
    evidence = verify_finding(
        _review(repo_root),
        _finding("secure/S004_weak_cryptography.py", "weak_cryptography", 4),
    )
    assert not evidence.sink.found
    assert evidence.security_control.present


def test_secure_authorization_has_explicit_control(repo_root):
    evidence = verify_finding(
        _review(repo_root),
        _finding("secure/S005_auth_authorization.py", "authentication_authorization", 2),
    )
    assert evidence.source.found
    assert evidence.sink.found
    assert evidence.data_flow.found
    assert evidence.security_control.present


def test_path_traversal_is_rejected(repo_root):
    review = _review(repo_root)
    finding = _finding("../outside.py", "sql_injection", 1)
    try:
        verify_finding(review, finding)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("Expected path traversal to be rejected")
