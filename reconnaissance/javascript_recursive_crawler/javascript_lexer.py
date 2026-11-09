"""Minimal JavaScript lexer: yields string literals, template literals and
comments with their offsets, skipping regular-expression literals.

It is not a full parser; it only needs to know whether a quote character
starts a string, so it tracks comments, strings, template literals (with
nested ``${...}`` expressions) and the regex-versus-division ambiguity using
the previous significant character.  It runs in linear time and is safe on
multi-megabyte minified bundles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

INTERESTING_CHARACTER = re.compile(r"[\"'`/]")
# After these characters a "/" starts a regular expression, not a division.
REGEX_PRECEDING_CHARACTERS = set("(,=:[!&|?{};+-*%<>~^")
REGEX_PRECEDING_KEYWORDS = ("return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await")
ESCAPE_SEQUENCES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
TEMPLATE_PLACEHOLDER = "{expression}"


@dataclass
class Literal:
    value: str            # decoded value (template expressions replaced by a placeholder)
    start: int            # offset of the opening quote
    end: int              # offset after the closing quote
    kind: str             # string | template | comment
    expressions: list[str] | None = None  # source of ${...} expressions in templates


def _decode_escapes(raw: str) -> str:
    if "\\" not in raw:
        return raw
    output = []
    index = 0
    length = len(raw)
    while index < length:
        character = raw[index]
        if character != "\\" or index + 1 >= length:
            output.append(character)
            index += 1
            continue
        following = raw[index + 1]
        if following == "u":
            if index + 2 < length and raw[index + 2] == "{":
                closing = raw.find("}", index + 3)
                if closing != -1:
                    try:
                        output.append(chr(int(raw[index + 3:closing], 16)))
                        index = closing + 1
                        continue
                    except ValueError:
                        pass
            hexadecimal = raw[index + 2:index + 6]
            if len(hexadecimal) == 4 and all(c in "0123456789abcdefABCDEF" for c in hexadecimal):
                output.append(chr(int(hexadecimal, 16)))
                index += 6
                continue
        elif following == "x":
            hexadecimal = raw[index + 2:index + 4]
            if len(hexadecimal) == 2 and all(c in "0123456789abcdefABCDEF" for c in hexadecimal):
                output.append(chr(int(hexadecimal, 16)))
                index += 4
                continue
        elif following == "\n":
            index += 2
            continue
        output.append(ESCAPE_SEQUENCES.get(following, following))
        index += 2
    return "".join(output)


def _previous_significant(text: str, position: int) -> tuple[str, str]:
    """Previous non-space character and the identifier ending there (if any)."""
    index = position - 1
    while index >= 0 and text[index] in " \t\r\n":
        index -= 1
    if index < 0:
        return "", ""
    character = text[index]
    word_end = index + 1
    while index >= 0 and (text[index].isalnum() or text[index] in "_$"):
        index -= 1
    return character, text[index + 1:word_end]


def _regex_allowed(text: str, position: int) -> bool:
    character, word = _previous_significant(text, position)
    if character == "":
        return True
    if character in REGEX_PRECEDING_CHARACTERS:
        return True
    if word and word in REGEX_PRECEDING_KEYWORDS:
        return True
    return False


def _skip_regex(text: str, position: int) -> int:
    """Return the offset after a regex literal starting at ``position``."""
    index = position + 1
    length = len(text)
    in_class = False
    while index < length:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == "\n":
            return position + 1  # not a regex after all; treat "/" as an operator
        if in_class:
            if character == "]":
                in_class = False
        elif character == "[":
            in_class = True
        elif character == "/":
            index += 1
            while index < length and (text[index].isalpha()):
                index += 1
            return index
        index += 1
    return position + 1


def _scan_quoted(text: str, position: int, quote: str) -> int:
    """Offset after the closing quote (or end of line for broken strings)."""
    index = position + 1
    length = len(text)
    while index < length:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == quote:
            return index + 1
        if character == "\n":
            return index
        index += 1
    return length


def _scan_template(text: str, position: int, literals: list[Literal]) -> int:
    """Scan a template literal starting at ``position`` (the backtick).

    Nested template literals and strings inside ``${...}`` are lexed
    recursively so their literals are emitted too.
    """
    index = position + 1
    length = len(text)
    parts: list[str] = []
    expressions: list[str] = []
    chunk_start = index
    while index < length:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == "`":
            parts.append(_decode_escapes(text[chunk_start:index]))
            literals.append(Literal("".join(parts), position, index + 1, "template", expressions))
            return index + 1
        if character == "$" and index + 1 < length and text[index + 1] == "{":
            parts.append(_decode_escapes(text[chunk_start:index]))
            depth = 1
            expression_start = index + 2
            index += 2
            while index < length and depth:
                inner = text[index]
                if inner in "\"'":
                    end = _scan_quoted(text, index, inner)
                    literals.append(Literal(_decode_escapes(text[index + 1:end - 1]), index, end, "string"))
                    index = end
                    continue
                if inner == "`":
                    index = _scan_template(text, index, literals)
                    continue
                if inner == "{":
                    depth += 1
                elif inner == "}":
                    depth -= 1
                index += 1
            expressions.append(text[expression_start:index - 1][:200])
            parts.append(TEMPLATE_PLACEHOLDER)
            chunk_start = index
            continue
        index += 1
    return length


def lex_literals(text: str, include_comments: bool = True) -> list[Literal]:
    literals: list[Literal] = []
    position = 0
    length = len(text)
    while position < length:
        match = INTERESTING_CHARACTER.search(text, position)
        if match is None:
            break
        index = match.start()
        character = text[index]
        if character in "\"'":
            end = _scan_quoted(text, index, character)
            if end > index + 1 and end <= length and text[end - 1] == character:
                literals.append(Literal(_decode_escapes(text[index + 1:end - 1]), index, end, "string"))
            position = max(end, index + 1)
        elif character == "`":
            position = _scan_template(text, index, literals)
        else:  # "/"
            following = text[index + 1] if index + 1 < length else ""
            if following == "/":
                end = text.find("\n", index)
                end = length if end == -1 else end
                if include_comments:
                    literals.append(Literal(text[index + 2:end], index, end, "comment"))
                position = end
            elif following == "*":
                end = text.find("*/", index + 2)
                end = length if end == -1 else end + 2
                if include_comments:
                    literals.append(Literal(text[index + 2:end - 2], index, end, "comment"))
                position = end
            elif _regex_allowed(text, index):
                position = _skip_regex(text, index)
            else:
                position = index + 1
    return literals
