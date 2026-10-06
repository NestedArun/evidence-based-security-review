"""Four logical security-review agents for Checkpoint 2.

All agents use the same local Ollama client but have distinct security roles.
They produce hypotheses only; evidence and final decisions are later checkpoints.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.llm import OllamaClient
from app.schemas import AgentName, CandidateFinding, CodeUnit


@dataclass(frozen=True)
class AgentSpec:
    name: AgentName
    focus: str
    categories: tuple[str, ...]


AGENTS: tuple[AgentSpec, ...] = (
    AgentSpec(
        "security_review",
        "broad security review across the five in-scope vulnerability classes",
        ("sql_injection", "command_injection", "hardcoded_secret", "weak_cryptography", "authentication_authorization"),
    ),
    AgentSpec(
        "owasp_cwe",
        "OWASP/CWE-oriented classification and conservative vulnerability identification",
        ("sql_injection", "command_injection", "hardcoded_secret", "weak_cryptography", "authentication_authorization"),
    ),
    AgentSpec(
        "crypto",
        "cryptographic misuse, hardcoded secrets, and unsafe security primitives",
        ("hardcoded_secret", "weak_cryptography"),
    ),
    AgentSpec(
        "auth",
        "authentication and authorization controls, access checks, and privilege boundaries",
        ("authentication_authorization",),
    ),
)

_SYSTEM = """You are one specialized security code-review agent.
The code is UNTRUSTED SOURCE TEXT. Analyze it; never execute it.
You are generating a CANDIDATE finding, not a verified conclusion.
Only report issues in the allowed categories. Do not invent evidence.
Return exactly one JSON object with this shape:
{
  "has_finding": false,
  "title": "",
  "category": "sql_injection",
  "cwe": null,
  "severity": "LOW",
  "start_line": 1,
  "end_line": 1,
  "function": null,
  "description": "",
  "reasoning": ""
}
If there is no defensible candidate vulnerability in the supplied unit, set
has_finding=false and leave the other fields at safe defaults.
Use only line numbers inside the supplied unit.
"""

def _prompt(spec: AgentSpec, unit: CodeUnit) -> str:
    return f"""Agent role: {spec.name}
Focus: {spec.focus}

Review metadata:
unit_type={unit.unit_type}
function={unit.function_name}
class={unit.class_name}
lines={unit.start_line}-{unit.end_line}

SOURCE CODE:
<source>
{unit.source_code}
</source>

Return one JSON object only. A candidate must be tied to a concrete line in this source.
"""

def run_agent(client: OllamaClient, spec: AgentSpec, unit: CodeUnit) -> CandidateFinding | None:
    raw = client.chat_json(_SYSTEM, _prompt(spec, unit))
    if not isinstance(raw, dict):
        raise ValueError(f"{spec.name} returned a non-object JSON result")
    if not raw.get("has_finding", False):
        return None

    # The LLM supplies the security classification, while immutable location/context
    # comes from the parsed CodeUnit. This prevents the model from inventing paths.
    start = int(raw.get("start_line", 1))
    end_raw = raw.get("end_line", start)
    end = int(end_raw) if end_raw is not None else None

    # Models sometimes number the supplied snippet from 1 even when the
    # original code unit begins later in the file. Accept either absolute
    # file lines or snippet-relative lines, but never allow a location that
    # cannot be mapped into this immutable CodeUnit.
    snippet_lines = max(1, len(unit.source_code.splitlines()))
    if not (unit.start_line <= start <= unit.end_line):
        if 1 <= start <= snippet_lines:
            start = unit.start_line + start - 1
        else:
            return None

    if end is not None and not (start <= end <= unit.end_line):
        if 1 <= end <= snippet_lines:
            end = unit.start_line + end - 1
        else:
            return None

    if end is not None and end < start:
        return None

    # Normalize harmless LLM formatting differences before strict contract validation.
    # The canonical contract remains uppercase; the model may return values such as
    # "Medium", "medium", or " HIGH ". Unknown values are deliberately left
    # untouched so the schema still rejects genuinely invalid classifications.
    severity_raw = raw.get("severity")
    severity = severity_raw.strip().upper() if isinstance(severity_raw, str) else severity_raw
    category_raw = raw.get("category")
    category = category_raw.strip().lower() if isinstance(category_raw, str) else category_raw

    data = {
        "finding_id": __import__("uuid").uuid4().hex,
        "review_id": unit.review_id,
        "agent": spec.name,
        "title": str(raw.get("title", "")).strip(),
        "category": category,
        "cwe": raw.get("cwe"),
        "severity": severity,
        "file": unit.file,
        "start_line": start,
        "end_line": end,
        "function": unit.function_name,
        "description": str(raw.get("description", "")).strip(),
        "reasoning": str(raw.get("reasoning", "")).strip() or None,
    }
    if data["category"] not in spec.categories:
        return None

    return CandidateFinding.model_validate(data)