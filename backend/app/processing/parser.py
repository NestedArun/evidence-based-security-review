"""Tree-sitter based parsing, function/class extraction and chunking.

Unit layout for a Python file (units never overlap; every top-level/class-level
statement belongs to exactly one unit, so no source line is silently dropped):

  * ``function`` - a top-level ``def`` (decorators included)
  * ``method``   - a ``def`` directly inside a class (decorators included)
  * ``class``    - a contiguous run of non-``def`` statements in a class body
  * ``module``   - a contiguous run of top-level statements that are not a
                   ``def``/``class`` (imports, constants, ``if __name__`` blocks, ...)

Nested functions stay inside their parent unit. Units longer than ``max_unit_lines``
are split into consecutive line chunks (``chunk_index`` set).
"""
from __future__ import annotations

from dataclasses import dataclass

import tree_sitter_python
from tree_sitter import Language, Node, Parser

_PY_LANGUAGE = Language(tree_sitter_python.language())


@dataclass
class RawUnit:
    unit_type: str
    start_line: int  # 1-based, inclusive
    end_line: int
    function_name: str | None
    class_name: str | None
    chunk_index: int | None
    source_code: str


@dataclass
class ParseResult:
    units: list[RawUnit]
    has_syntax_errors: bool


def _new_parser() -> Parser:
    return Parser(_PY_LANGUAGE)


def _definition(node: Node) -> Node | None:
    """Return the underlying def/class node for ``node`` (unwrapping decorators)."""
    if node.type in ("function_definition", "class_definition"):
        return node
    if node.type == "decorated_definition":
        return node.child_by_field_name("definition")
    return None


def _name(defn: Node) -> str | None:
    n = defn.child_by_field_name("name")
    return n.text.decode("utf-8") if n is not None else None


def _slice(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1 : end])


def _chunk(unit: RawUnit, lines: list[str], max_lines: int) -> list[RawUnit]:
    if unit.end_line - unit.start_line + 1 <= max_lines:
        return [unit]
    chunks: list[RawUnit] = []
    start = unit.start_line
    index = 0
    while start <= unit.end_line:
        end = min(start + max_lines - 1, unit.end_line)
        chunks.append(
            RawUnit(
                unit.unit_type, start, end, unit.function_name, unit.class_name,
                index, _slice(lines, start, end),
            )
        )
        start = end + 1
        index += 1
    return chunks


def _walk_body(
    nodes: list[Node], lines: list[str], class_name: str | None, out: list[RawUnit]
) -> None:
    """Emit units for a sequence of sibling statements (module body or class body)."""
    run: list[Node] = []

    def flush() -> None:
        if not run:
            return
        start = run[0].start_point[0] + 1
        end = run[-1].end_point[0] + 1
        out.append(
            RawUnit("class" if class_name else "module", start, end, None, class_name,
                    None, _slice(lines, start, end))
        )
        run.clear()

    for node in nodes:
        defn = _definition(node)
        if defn is None:
            run.append(node)
            continue
        flush()
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        name = _name(defn)
        if defn.type == "function_definition":
            out.append(
                RawUnit("method" if class_name else "function", start, end, name, class_name,
                        None, _slice(lines, start, end))
            )
        else:  # class_definition: recurse into its body
            qualified = f"{class_name}.{name}" if class_name else name
            body = defn.child_by_field_name("body")
            _walk_body(list(body.children) if body is not None else [], lines, qualified, out)
    flush()


def extract_units(text: str, max_unit_lines: int) -> ParseResult:
    """Parse ``text`` (already newline-normalised) and return its code units."""
    tree = _new_parser().parse(text.encode("utf-8"))
    lines = text.split("\n")
    # A trailing newline yields a final empty element that is not a real line.
    if lines and lines[-1] == "":
        lines.pop()

    raw: list[RawUnit] = []
    _walk_body(list(tree.root_node.children), lines, None, raw)

    units: list[RawUnit] = []
    for unit in raw:
        units.extend(_chunk(unit, lines, max_unit_lines))
    return ParseResult(units=units, has_syntax_errors=tree.root_node.has_error)
