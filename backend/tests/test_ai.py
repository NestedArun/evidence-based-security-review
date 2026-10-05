import json

import pytest

from app.agents import AGENTS, run_agent
from app.llm import OllamaClient, OllamaError
from app.schemas import CodeUnit


def unit():
    return CodeUnit(
        unit_id="u1", review_id="r1", file="vulnerable/V001.py", language="python",
        start_line=1, end_line=4, unit_type="function", function_name="get_user",
        source_code="def get_user(x):\n    q = f\"SELECT * FROM users WHERE id={x}\"\n    return q\n",
    )


class FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def chat_json(self, system, user):
        return self.payload


def test_all_four_agents_are_defined():
    assert [a.name for a in AGENTS] == ["security_review", "owasp_cwe", "crypto", "auth"]


def test_agent_output_is_structured_and_context_is_immutable():
    payload = {
        "has_finding": True, "title": "SQL injection", "category": "sql_injection",
        "cwe": "CWE-89", "severity": "HIGH", "start_line": 2, "end_line": 2,
        "description": "User input reaches a SQL statement.", "reasoning": "Dynamic query construction."
    }
    finding = run_agent(FakeClient(payload), AGENTS[0], unit())
    assert finding.file == "vulnerable/V001.py"
    assert finding.review_id == "r1"
    assert finding.function == "get_user"
    assert finding.start_line == 2


def test_agent_skips_unmappable_line_instead_of_failing_review():
    payload = {"has_finding": True, "title": "x", "category": "sql_injection",
               "severity": "HIGH", "start_line": 99, "description": "x"}
    assert run_agent(FakeClient(payload), AGENTS[0], unit()) is None

def test_agent_maps_snippet_relative_line_to_absolute_line():
    candidate = CodeUnit(
        unit_id="u2", review_id="r1", file="vulnerable/V001.py", language="python",
        start_line=3, end_line=6, unit_type="function", function_name="find_user",
        source_code="def find_user(x):\n    query = x\n    return query\n    # end\n",
    )
    payload = {"has_finding": True, "title": "SQL injection", "category": "sql_injection",
               "severity": "HIGH", "start_line": 2, "end_line": 2, "description": "x"}
    finding = run_agent(FakeClient(payload), AGENTS[0], candidate)
    assert finding.start_line == 4
    assert finding.end_line == 4


def test_agent_normalizes_model_severity_and_category_case():
    payload = {"has_finding": True, "title": "SQL injection", "category": "SQL_INJECTION",
               "severity": " Medium ", "start_line": 2, "description": "x"}
    finding = run_agent(FakeClient(payload), AGENTS[0], unit())
    assert finding.category == "sql_injection"
    assert finding.severity == "MEDIUM"

def test_agent_rejects_wrong_category():
    payload = {"has_finding": True, "title": "x", "category": "authentication_authorization",
               "severity": "HIGH", "start_line": 2, "description": "x"}
    with pytest.raises(ValueError, match="outside"):
        run_agent(FakeClient(payload), AGENTS[2], unit())


def test_no_finding_is_allowed():
    assert run_agent(FakeClient({"has_finding": False}), AGENTS[0], unit()) is None


def test_ollama_placeholder_fails_explicitly():
    with pytest.raises(OllamaError, match="No Ollama model configured"):
        OllamaClient("CONFIGURE_LOCALLY").chat_json("x", "y")
