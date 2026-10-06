"""Checkpoint 3: deterministic source-code evidence verification.

This layer never asks the LLM to justify its own finding. It inspects the submitted
Python source with the AST and small lexical checks, producing only evidence that can
be located in the reviewed source file.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from app.models import FindingRow, ReviewRow
from app.schemas import Evidence


@dataclass(frozen=True)
class EvidenceContext:
    source_text: str
    file: str


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _line(text: str, number: int | None) -> str | None:
    if number is None or number < 1:
        return None
    lines = _lines(text)
    return lines[number - 1] if number <= len(lines) else None


def _node_line(node: ast.AST) -> int | None:
    return getattr(node, "lineno", None)


def _end_line(node: ast.AST) -> int | None:
    return getattr(node, "end_lineno", None)


def _snippet(text: str, start: int, end: int | None = None) -> str:
    lines = _lines(text)
    end = end or start
    return "\n".join(lines[max(0, start - 1):end])


def _located(found: bool, file: str | None = None, line: int | None = None,
             code: str | None = None, description: str | None = None) -> dict:
    return {
        "found": found,
        "file": file,
        "line": line,
        "code": code,
        "description": description,
    }


def _call_name(call: ast.Call) -> str:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST | None = fn
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _literal_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_user_source_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in (
        "user", "input", "param", "request", "query", "argument", "args", "data",
        "password", "username", "directory", "path", "command"
    ))


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _find_name_assignment(tree: ast.AST, name: str) -> ast.Assign | ast.AnnAssign | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return node
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                return node
    return None


def _function_for_line(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    matches = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (n.lineno <= line <= (n.end_lineno or n.lineno))
    ]
    return min(matches, key=lambda n: (n.end_lineno or n.lineno) - n.lineno, default=None)


def _source_for_parameter(fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
                          line: int, text: str, file: str) -> dict:
    if fn:
        params = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)]
        if fn.args.vararg:
            params.append(fn.args.vararg.arg)
        if fn.args.kwarg:
            params.append(fn.args.kwarg.arg)
        # Prefer parameters that occur on or before the finding line.
        body = ast.Module(body=fn.body, type_ignores=[])
        used = _names(body)
        candidates = [p for p in params if p in used]
        if candidates:
            p = candidates[0]
            for n in ast.walk(body):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == p:
                    return _located(
                        True, file, n.lineno, _line(text, n.lineno),
                        f"Function parameter '{p}' is used by the reviewed code.",
                    )
    return _located(False, description="No concrete untrusted/input source was established.")


def _security_control_sql(tree: ast.AST) -> tuple[bool, str]:
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n).endswith(("execute", "executemany", "executescript")):
            if len(n.args) >= 2:
                return True, "The database call supplies parameters separately from the SQL statement."
            if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                if "?" in n.args[0].value or "%s" in n.args[0].value:
                    return True, "The SQL statement uses a parameter placeholder."
    return False, "No parameterized SQL control was established."


def _security_control_command(tree: ast.AST) -> tuple[bool, str]:
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n) in {"subprocess.run", "subprocess.call",
                                                           "subprocess.Popen", "subprocess.check_output"}:
            for kw in n.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return True, "The subprocess call explicitly disables shell interpretation."
    return False, "No shell-disabled subprocess control was established."


def _security_control_secret(tree: ast.AST) -> tuple[bool, str]:
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n) in {"os.environ.get", "os.getenv"}:
            return True, "The secret is retrieved from an environment variable rather than embedded in source."
    return False, "No external secret-management control was established."


def _security_control_crypto(tree: ast.AST) -> tuple[bool, str]:
    safe_calls = {"hashlib.pbkdf2_hmac", "hashlib.scrypt", "bcrypt.hashpw", "argon2.hash_password"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n) in safe_calls:
            return True, "A password-oriented or memory-hard password hashing primitive is used."
    return False, "No stronger password-hashing control was established."


def _security_control_auth(tree: ast.AST) -> tuple[bool, str]:
    for n in ast.walk(tree):
        if isinstance(n, ast.If):
            text = ast.unparse(n.test)
            if any(token in text.lower() for token in ("role", "permission", "admin", "authorized", "is_authenticated")):
                return True, "An explicit authorization/authentication check guards a control-flow branch."
    return False, "No explicit authorization/authentication check was established."


def _sql_evidence(tree: ast.AST, ctx: EvidenceContext, finding: FindingRow) -> tuple[dict, dict, dict, dict]:
    source = _source_for_parameter(
        _function_for_line(tree, finding.start_line), finding.start_line, ctx.source_text, ctx.file
    )
    sink = _located(False, description="No dynamic database sink was established.")
    flow = {"found": False, "path": [], "description": "No source-to-sink data flow was established."}

    assignments: dict[str, ast.Assign] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assignments[t.id] = n

    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n).endswith(("execute", "executemany", "executescript")) and n.args:
            # Parameterized calls are a security control, not a vulnerable sink.
            if len(n.args) >= 2:
                continue
            arg = n.args[0]
            dynamic = not _literal_string(arg) or isinstance(arg, (ast.JoinedStr, ast.BinOp))
            if dynamic or _names(arg):
                line = _node_line(n)
                sink = _located(True, ctx.file, line, _line(ctx.source_text, line),
                                "A database execution call receives a dynamically constructed SQL value.")
                if isinstance(arg, ast.Name) and arg.id in assignments:
                    a = assignments[arg.id]
                    names = _names(a.value)
                    if names:
                        flow = {
                            "found": True,
                            "path": [*sorted(names), arg.id, _call_name(n)],
                            "description": f"Variable '{arg.id}' is constructed from source-referencing data and passed to the database sink.",
                        }
                elif _names(arg):
                    flow = {
                        "found": True,
                        "path": [*sorted(_names(arg)), _call_name(n)],
                        "description": "Input-referencing data reaches the database sink in the call expression.",
                    }
                break

    present, desc = _security_control_sql(tree)
    control = {"present": present, "description": desc}
    return source, sink, flow, control


def _command_evidence(tree: ast.AST, ctx: EvidenceContext, finding: FindingRow) -> tuple[dict, dict, dict, dict]:
    source = _source_for_parameter(
        _function_for_line(tree, finding.start_line), finding.start_line, ctx.source_text, ctx.file
    )
    sink = _located(False, description="No shell-enabled command sink was established.")
    flow = {"found": False, "path": [], "description": "No source-to-sink command flow was established."}
    assignments: dict[str, ast.Assign] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assignments[t.id] = n

    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n) in {
            "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"
        }:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in n.keywords
            )
            if shell_true:
                line = _node_line(n)
                sink = _located(True, ctx.file, line, _line(ctx.source_text, line),
                                "A subprocess sink explicitly enables shell interpretation.")
                if n.args:
                    arg = n.args[0]
                    if isinstance(arg, ast.Name) and arg.id in assignments:
                        names = _names(assignments[arg.id].value)
                        flow = {
                            "found": bool(names),
                            "path": [*sorted(names), arg.id, _call_name(n)],
                            "description": "The command variable reaches the shell-enabled subprocess sink."
                            if names else "The command variable reaches the sink, but its source was not established.",
                        }
                    elif _names(arg):
                        flow = {"found": True, "path": [*sorted(_names(arg)), _call_name(n)],
                                "description": "Input-referencing data reaches the shell-enabled subprocess sink."}
                break

    present, desc = _security_control_command(tree)
    return source, sink, flow, {"present": present, "description": desc}


def _secret_evidence(tree: ast.AST, ctx: EvidenceContext, finding: FindingRow) -> tuple[dict, dict, dict, dict]:
    source = _located(False, description="No hardcoded secret literal was established.")
    sink = _located(False, description="No security-sensitive use of the secret was established.")
    flow = {"found": False, "path": [], "description": "No secret data flow was established."}

    secret_name: str | None = None
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name) and re.search(r"(key|secret|token|password|credential)", t.id, re.I):
                    if len(n.value.value) >= 8:
                        secret_name = t.id
                        source = _located(
                            True, ctx.file, n.lineno, _line(ctx.source_text, n.lineno),
                            f"Secret-like variable '{t.id}' is assigned a literal value in source code.",
                        )
                        break
        if source["found"]:
            break

    if secret_name:
        for n in ast.walk(tree):
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and n.value.id == secret_name:
                sink = _located(True, ctx.file, n.lineno, _line(ctx.source_text, n.lineno),
                                f"Secret-like value '{secret_name}' is returned by the function.")
                flow = {"found": True, "path": [secret_name, "return"],
                        "description": f"'{secret_name}' flows from the source literal to a returned value."}
                break

    present, desc = _security_control_secret(tree)
    return source, sink, flow, {"present": present, "description": desc}


def _crypto_evidence(tree: ast.AST, ctx: EvidenceContext, finding: FindingRow) -> tuple[dict, dict, dict, dict]:
    fn = _function_for_line(tree, finding.start_line)
    source = _source_for_parameter(fn, finding.start_line, ctx.source_text, ctx.file)
    sink = _located(False, description="No weak cryptographic sink was established.")
    flow = {"found": False, "path": [], "description": "No source-to-cryptographic-sink flow was established."}

    weak = {"hashlib.md5", "hashlib.sha1", "hashlib.sha"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = _call_name(n)
            if name in weak or name.startswith("hashlib.md5") or name.startswith("hashlib.sha1"):
                line = _node_line(n)
                sink = _located(True, ctx.file, line, _line(ctx.source_text, line),
                                f"Weak cryptographic primitive '{name}' is invoked.")
                if n.args:
                    names = _names(n.args[0])
                    if names:
                        flow = {"found": True, "path": [*sorted(names), name],
                                "description": "Password/input data reaches the weak cryptographic primitive."}
                break

    present, desc = _security_control_crypto(tree)
    return source, sink, flow, {"present": present, "description": desc}


def _auth_evidence(tree: ast.AST, ctx: EvidenceContext, finding: FindingRow) -> tuple[dict, dict, dict, dict]:
    source = _located(False, description="No concrete user/role source was established.")
    sink = _located(False, description="No protected-resource sink was established.")
    flow = {"found": False, "path": [], "description": "No authorization data flow was established."}

    fn = _function_for_line(tree, finding.start_line)
    if fn:
        params = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)]
        if fn.args.vararg:
            params.append(fn.args.vararg.arg)
        if fn.args.kwarg:
            params.append(fn.args.kwarg.arg)
        user_param = next((p for p in params if _is_user_source_name(p)), params[0] if params else None)
        if user_param:
            line = _node_line(fn)
            source = _located(True, ctx.file, line, _line(ctx.source_text, line),
                              f"Function receives user-controlled identity/authorization data through '{user_param}'.")

    # A return of a confidential/admin resource is treated as the security-sensitive sink.
    for n in ast.walk(fn or tree):
        if isinstance(n, ast.Return):
            text = ast.get_source_segment(ctx.source_text, n) or _snippet(ctx.source_text, n.lineno, n.end_lineno)
            if any(token in text.lower() for token in ("admin", "confidential", "private", "secret", "report")):
                sink = _located(True, ctx.file, n.lineno, _line(ctx.source_text, n.lineno),
                                "The function returns a security-sensitive resource.")
                if source["found"]:
                    flow = {"found": True, "path": [source["description"], "protected return"],
                            "description": "User/authorization context reaches a protected-resource return without an established control."
                            }
                break

    present, desc = _security_control_auth(tree)
    return source, sink, flow, {"present": present, "description": desc}


def _read_review_file(review: ReviewRow, relative_file: str) -> str:
    root = Path(review.target_path).resolve()
    target = (root / relative_file).resolve()
    if root != target and root not in target.parents:
        raise ValueError("Finding file is outside the reviewed project root")
    if not target.is_file():
        raise FileNotFoundError(f"Finding file does not exist: {relative_file}")
    return target.read_text(encoding="utf-8")


def verify_finding(review: ReviewRow, finding: FindingRow) -> Evidence:
    """Verify one candidate finding using only the reviewed source file."""
    text = _read_review_file(review, finding.file)
    try:
        tree = ast.parse(text, filename=finding.file)
    except SyntaxError:
        return Evidence(
            evidence_id=__import__("uuid").uuid4().hex,
            finding_id=finding.finding_id,
            source=None,
            sink=None,
            data_flow=None,
            security_control=None,
        )

    ctx = EvidenceContext(text, finding.file)
    handlers = {
        "sql_injection": _sql_evidence,
        "command_injection": _command_evidence,
        "hardcoded_secret": _secret_evidence,
        "weak_cryptography": _crypto_evidence,
        "authentication_authorization": _auth_evidence,
    }
    source, sink, flow, control = handlers[finding.category](tree, ctx, finding)
    return Evidence(
        evidence_id=__import__("uuid").uuid4().hex,
        finding_id=finding.finding_id,
        source=source,
        sink=sink,
        data_flow=flow,
        security_control=control,
    )
