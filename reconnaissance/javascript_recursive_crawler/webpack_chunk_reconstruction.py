"""Reconstruct lazily loaded chunk file names from bundler runtimes.

Webpack 4/5 (and Rspack) runtimes compute chunk URLs with expressions like::

    l.u = e => "static/js/" + (291 === e ? "mapbox-gl" : e) + "." + {254:"c70382ad",291:"729f3dfb"}[e] + ".js"
    function a(e){return o.p+"static/js/"+({}[e]||e)+"."+{0:"3f2a"}[e]+".chunk.js"}

These chunk files are never referenced literally anywhere, so a plain string
scan misses them.  This module evaluates such expressions for every chunk id
found in their lookup maps.  It is a tiny evaluator for exactly this grammar
(string literals, the chunk variable, the public-path variable, ``{map}[v]``,
``({map}[v]||v)`` and ``(N===v?"name":v)``); anything else makes the
expression unevaluable and it is skipped (never guessed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CHUNK_URL_FUNCTION = re.compile(
    r"(?P<owner>[\w$]+)\.u\s*=\s*(?:function\s*\(\s*(?P<variable_a>[\w$]+)\s*\)\s*\{\s*return\s*|\(?\s*(?P<variable_b>[\w$]+)\s*\)?\s*=>\s*\(?)"
)
LEGACY_SCRIPT_SOURCE = re.compile(
    r"function\s*[\w$]*\s*\(\s*(?P<variable>[\w$]+)\s*\)\s*\{\s*return\s+(?P<expression>[\w$]+\.p\s*\+[^;]{0,200000}?\.m?js[\"'])\s*[;}]"
)
PUBLIC_PATH_ASSIGNMENT = re.compile(r"(?<![\w$])[\w$]+\.p\s*=\s*([\"'])([^\"']*)\1")
MAP_LOOKUP = re.compile(r"^\(?\s*\{(?P<body>[^{}]*)\}\s*\[\s*(?P<variable>[\w$]+)\s*\]\s*(?:\|\|\s*(?P<fallback>[\w$]+))?\s*\)?$")
TERNARY = re.compile(
    r"^\(?\s*(?:(?P<number_a>\d+)\s*===?\s*(?P<variable_a>[\w$]+)|(?P<variable_b>[\w$]+)\s*===?\s*(?P<number_b>\d+))\s*\?\s*"
    r"(?P<quote>[\"'])(?P<value>[^\"']*)(?P=quote)\s*:\s*(?P<fallback>[\w$]+)\s*\)?$"
)
MAP_ENTRY = re.compile(r"(?:\"([^\"]+)\"|'([^']+)'|([\w$]+))\s*:\s*(?:\"([^\"]*)\"|'([^']*)')")


@dataclass
class ChunkReconstruction:
    expression: str
    public_path: str | None
    chunk_paths: list[str]


def _expression_end(text: str, start: int) -> int:
    """End offset of an expression starting at ``start`` (top-level , ; or unmatched ) })."""
    depth = 0
    index = start
    length = len(text)
    while index < length:
        character = text[index]
        if character in "\"'":
            closing = index + 1
            while closing < length and text[closing] != character:
                closing += 2 if text[closing] == "\\" else 1
            index = closing + 1
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif character in ",;" and depth == 0:
            return index
        index += 1
    return length


def _split_top_level_plus(expression: str) -> list[str]:
    terms, depth, current, index = [], 0, [], 0
    while index < len(expression):
        character = expression[index]
        if character in "\"'":
            closing = index + 1
            while closing < len(expression) and expression[closing] != character:
                closing += 2 if expression[closing] == "\\" else 1
            current.append(expression[index:closing + 1])
            index = closing + 1
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        if character == "+" and depth == 0:
            terms.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    terms.append("".join(current).strip())
    return [term for term in terms if term]


def _parse_map(body: str) -> dict[str, str]:
    result = {}
    for match in MAP_ENTRY.finditer(body):
        key = match.group(1) or match.group(2) or match.group(3)
        value = match.group(4) if match.group(4) is not None else match.group(5)
        result[key] = value
    return result


def _evaluate(terms: list[str], chunk_variable: str, chunk_id: str, public_path: str | None) -> str | None:
    output = []
    for term in terms:
        stripped = term.strip()
        while stripped.startswith("(") and stripped.endswith(")") and _balanced(stripped[1:-1]):
            stripped = stripped[1:-1].strip()
        if len(stripped) >= 2 and stripped[0] in "\"'" and stripped[-1] == stripped[0]:
            output.append(stripped[1:-1])
            continue
        if stripped == chunk_variable:
            output.append(chunk_id)
            continue
        if re.fullmatch(r"[\w$]+\.p", stripped):
            if public_path is None:
                return None
            output.append(public_path)
            continue
        lookup = MAP_LOOKUP.match(stripped)
        if lookup and lookup.group("variable") == chunk_variable:
            mapping = _parse_map(lookup.group("body"))
            if chunk_id in mapping:
                output.append(mapping[chunk_id])
            elif lookup.group("fallback") == chunk_variable:
                output.append(chunk_id)
            else:
                return None
            continue
        ternary = TERNARY.match(stripped)
        if ternary:
            variable = ternary.group("variable_a") or ternary.group("variable_b")
            number = ternary.group("number_a") or ternary.group("number_b")
            if variable == chunk_variable and ternary.group("fallback") == chunk_variable:
                output.append(ternary.group("value") if chunk_id == number else chunk_id)
                continue
        return None
    return "".join(output)


def _balanced(text: str) -> bool:
    depth = 0
    for character in text:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _chunk_ids(expression: str) -> list[str]:
    ids: dict[str, None] = {}
    for body in re.findall(r"\{([^{}]*)\}\s*\[", expression):
        for key in _parse_map(body):
            ids.setdefault(key, None)
    return list(ids)


def reconstruct_chunks(text: str) -> list[ChunkReconstruction]:
    public_paths = [match.group(2) for match in PUBLIC_PATH_ASSIGNMENT.finditer(text)]
    public_path = public_paths[0] if public_paths else None
    candidates: list[tuple[str, str]] = []
    for match in CHUNK_URL_FUNCTION.finditer(text):
        variable = match.group("variable_a") or match.group("variable_b")
        end = _expression_end(text, match.end())
        candidates.append((variable, text[match.end():end]))
    for match in LEGACY_SCRIPT_SOURCE.finditer(text):
        candidates.append((match.group("variable"), match.group("expression")))
    results = []
    for variable, expression in candidates:
        expression = expression.strip().rstrip(")").strip() if expression.count(")") > expression.count("(") else expression.strip()
        if ".js" not in expression and ".mjs" not in expression:
            continue
        terms = _split_top_level_plus(expression)
        paths = []
        for chunk_id in _chunk_ids(expression):
            evaluated = _evaluate(terms, variable, chunk_id, public_path if public_path is not None else "")
            if evaluated and re.search(r"\.m?js$", evaluated):
                paths.append(evaluated)
        if paths:
            results.append(ChunkReconstruction(expression[:300], public_path, sorted(set(paths))))
    return results
