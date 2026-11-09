"""Deterministic extraction of URL-like references from JavaScript source.

Input: lexed literals (see :mod:`javascript_lexer`).  Output: candidate
references with their syntactic kind and extraction context.  Kinds describe
*what the string looks like and where it sits in the code*, never what the
resource is; classification belongs to the URL validator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .javascript_lexer import TEMPLATE_PLACEHOLDER, Literal, lex_literals

ABSOLUTE_URL_IN_TEXT = re.compile(r"""(?:https?:)?//(?:[a-z0-9\-_]+\.)+[a-z]{2,24}(?::\d{2,5})?(?:[/?#][^\s"'<>`\\^{}|]*)?""", re.IGNORECASE)
ABSOLUTE_URL_EXACT = re.compile(r"""^(?:https?:)?//(?:[a-z0-9\-_{}]+\.)+[a-z{}]{2,24}(?::\d{2,5})?(?:[/?#].*)?$""", re.IGNORECASE)
PATH_CHARACTERS = re.compile(r"^[A-Za-z0-9_\-.~%!$&'()*+,;=:@/?#\[\]{}]+$")
MIME_TYPE = re.compile(r"^(?:application|text|image|audio|video|font|multipart|model|message|x-[\w-]+)/[\w.+\-*]+(?:\s*;.*)?$", re.IGNORECASE)
DATE_FORMAT = re.compile(r"^[DMYHhmsa]{1,4}(?:[/\-.][DMYHhmsa]{1,4})+$")
FRACTION = re.compile(r"^[\d\s./]+$")
JAVASCRIPT_FILE = re.compile(r"\.(?:m?js|cjs)(?:\?[^#]*)?$", re.IGNORECASE)
FILE_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,8}(?:\?[^#]*)?$")
QUERY_PARAMETER_FRAGMENT = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-.\[\]]{0,63})=")
SOURCE_MAP_COMMENT = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)")
NON_URL_PREFIXES = ("@", "node_modules", "webpack/", "webpack:", "core-js/", "regenerator-runtime", "@babel", "babel-runtime",
                    "react/", "react-dom/", "lodash/", "rxjs/", "tslib", "zone.js")
NON_URL_SUBSTRINGS = ("</", "/>", "<", ">", "\\", "\n", " ", "||", "&&", "=>", "*/", "/*")
XML_NAMESPACE_HOSTS = ("www.w3.org", "schemas.xmlsoap.org", "schemas.microsoft.com", "ns.adobe.com", "purl.org", "xmlns.com")

# Context patterns found immediately before a literal.
CALL_CONTEXT = re.compile(
    r"(?P<call>fetch|axios(?:\.(?:get|post|put|patch|delete|head|options|request))?|\$\.(?:get|post|ajax|getJSON)|"
    r"\.(?:get|post|put|patch|delete|head|options|request|open|send|ajax|load|navigate|push|replace|redirect|"
    r"navigateByUrl|sendBeacon|importScripts|assign)|import|require|new\s+(?:Worker|SharedWorker|EventSource|WebSocket|URL|Request)|"
    r"importScripts|sendBeacon|location\.(?:href|assign|replace))\s*\(\s*(?:[\"'`]?(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"'`]\s*,\s*)?$",
    re.IGNORECASE,
)
PROPERTY_CONTEXT = re.compile(r"(?P<property>[A-Za-z_$][\w$]*|\"[\w$\-]+\"|'[\w$\-]+')\s*[:=]\s*$")
JSX_PROPERTY_CONTEXT = re.compile(r"(?P<property>path|to|href|src|action|from|redirect|redirectTo)\s*=\s*\{?\s*$")
ROUTE_PROPERTIES = {"path", "to", "redirect", "redirectto", "from", "route", "routepath", "pathname", "alias", "loginpath", "fallbackpath"}
URL_PROPERTIES = {"url", "uri", "href", "src", "endpoint", "baseurl", "base_url", "apiurl", "api_url", "apibase", "baseuri", "host",
                  "action", "link", "api", "path", "redirecturl", "redirect_uri", "callbackurl", "returnurl", "origin", "domain"}


@dataclass
class ExtractedReference:
    raw_value: str
    reference_kind: str          # absolute_url | protocol_relative_url | root_relative_path | relative_path | javascript_resource | source_map | query_parameter_fragment
    literal_kind: str            # string | template | comment
    offset: int
    context: dict = field(default_factory=dict)
    contains_template_expression: bool = False


def _context_before(text: str, offset: int, width: int = 80) -> str:
    return text[max(0, offset - width):offset]


def describe_context(text: str, literal: Literal) -> dict:
    before = _context_before(text, literal.start)
    context: dict = {}
    call = CALL_CONTEXT.search(before)
    if call:
        context["call"] = re.sub(r"\s+", " ", call.group("call"))
        method = re.search(r"[\"'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"'`]\s*,\s*$", before, re.IGNORECASE)
        if method:
            context["http_method"] = method.group(1).upper()
        elif re.search(r"\.(get|post|put|patch|delete|head|options)$", context["call"], re.IGNORECASE):
            context["http_method"] = context["call"].rsplit(".", 1)[-1].upper()
    else:
        jsx = JSX_PROPERTY_CONTEXT.search(before)
        prop = jsx or PROPERTY_CONTEXT.search(before)
        if prop:
            name = prop.group("property").strip("\"'")
            context["property"] = name
    # Concatenation hints: literal joined with an expression.
    after = text[literal.end:literal.end + 3].lstrip()
    if after.startswith("+") or before.rstrip().endswith("+"):
        context["concatenated"] = True
    start = max(0, literal.start - 60)
    end = min(len(text), literal.end + 60)
    context["snippet"] = text[start:end].replace("\n", " ")[:260]
    return context


def _looks_like_path(value: str) -> bool:
    if not value or len(value) > 2048 or len(value) < 2:
        return False
    if any(token in value for token in NON_URL_SUBSTRINGS):
        return False
    if not PATH_CHARACTERS.match(value):
        return False
    if MIME_TYPE.match(value) or DATE_FORMAT.match(value) or FRACTION.match(value):
        return False
    if value.startswith(NON_URL_PREFIXES):
        return False
    if value.count("/") == 0 and "?" not in value:
        return False
    if not re.search(r"[A-Za-z]{2,}", value.replace(TEMPLATE_PLACEHOLDER, "")):
        return False
    return True


CSS_URL_FUNCTION = re.compile(r"url\(\s*([\"']?)([^\"')\s]+)\1\s*\)", re.IGNORECASE)


def classify_literal_value(value: str) -> str | None:
    """Syntactic kind of a whole literal value, or None if not URL-like."""
    stripped = value.strip()
    if not stripped:
        return None
    if "data:" in stripped[:64] or "url(" in stripped.lower() or "base64," in stripped:
        return None  # data URIs and CSS url() wrappers (handled separately)
    if any(len(segment) > 160 and not FILE_EXTENSION.search(segment) for segment in stripped.split("/")):
        return None  # encoded blobs, not path segments
    if ABSOLUTE_URL_EXACT.match(stripped):
        if any(host in stripped for host in XML_NAMESPACE_HOSTS):
            return None
        return "protocol_relative_url" if stripped.startswith("//") else "absolute_url"
    if stripped.startswith("/"):
        if stripped.startswith("//") or stripped in ("/", "/*", "/**"):
            return None
        if re.match(r"^/[\^(\\]", stripped):  # regex source
            return None
        return "root_relative_path" if _looks_like_path(stripped) else None
    if stripped.startswith(("./", "../")):
        # Bundler module requests ("./pages/dashboard") are not URLs unless
        # they name an actual file.
        return "relative_path" if FILE_EXTENSION.search(stripped) and _looks_like_path(stripped) else None
    if _looks_like_path(stripped):
        first_segment = stripped.split("/", 1)[0]
        if "." in first_segment and not FILE_EXTENSION.search(first_segment):
            return None  # "foo.bar/baz" (dotted identifiers, i18n keys)
        if re.fullmatch(r"[a-z]+/[a-z]+", stripped) and not FILE_EXTENSION.search(stripped):
            return None  # "and/or", "true/false", single word pairs
        return "relative_path"
    return None


def extract_references(text: str) -> tuple[list[ExtractedReference], list[Literal]]:
    literals = lex_literals(text, include_comments=True)
    references: list[ExtractedReference] = []
    for literal in literals:
        value = literal.value
        if literal.kind == "comment":
            source_map = SOURCE_MAP_COMMENT.search(value)
            if source_map:
                references.append(ExtractedReference(source_map.group(1), "source_map", "comment", literal.start,
                                                     {"snippet": value.strip()[:200]}))
                continue
            for match in ABSOLUTE_URL_IN_TEXT.finditer(value):
                if match.group(0).startswith("//") and not match.group(0).startswith("///"):
                    continue  # "//" inside a comment is usually not a URL
                if any(host in match.group(0) for host in XML_NAMESPACE_HOSTS):
                    continue
                references.append(ExtractedReference(match.group(0), "absolute_url", "comment", literal.start,
                                                     {"snippet": value.strip()[:200], "in_comment": True}))
            continue
        if len(value) > 20000:
            continue
        kind = classify_literal_value(value)
        if kind == "relative_path" and value.startswith(("./", "../")) and text[literal.end:literal.end + 2].lstrip().startswith(":"):
            # Object key of a bundler module map ({"./en.json": 1234}): a
            # module identifier, not a URL.
            kind = None
            if not QUERY_PARAMETER_FRAGMENT.search(value):
                continue
        is_template = literal.kind == "template" and TEMPLATE_PLACEHOLDER in value
        if kind:
            context = describe_context(text, literal)
            if kind in ("relative_path", "root_relative_path") and JAVASCRIPT_FILE.search(value.replace(TEMPLATE_PLACEHOLDER, "x")):
                context["javascript_file_reference"] = True
            property_name = (context.get("property") or "").lower()
            # A generic "path" property is only route-like for root-relative
            # values ({path: "/orders/:id"}); "path: 'styles/v1'" is usually an
            # API/library path.  Router-specific properties always count.
            if kind in ("root_relative_path", "relative_path") and property_name in ROUTE_PROPERTIES and (
                    property_name != "path" or kind == "root_relative_path"):
                context["route_definition"] = True
            references.append(ExtractedReference(value.strip(), kind, literal.kind, literal.start, context, is_template))
        else:
            # CSS url(...) references inside JavaScript strings.
            for match in CSS_URL_FUNCTION.finditer(value):
                inner = match.group(2)
                inner_kind = classify_literal_value(inner) if not inner.lower().startswith("data:") else None
                if inner_kind:
                    references.append(ExtractedReference(inner, inner_kind, literal.kind, literal.start,
                                                         {"css_url_function": True,
                                                          "snippet": value[max(0, match.start() - 40):match.end() + 40][:200]}))
            # URLs embedded inside longer strings (messages, HTML snippets, CSS).
            for match in ABSOLUTE_URL_IN_TEXT.finditer(value):
                found = match.group(0).rstrip(".,;:)")
                if not found.lower().startswith(("http://", "https://")):
                    continue
                if any(host in found for host in XML_NAMESPACE_HOSTS):
                    continue
                references.append(ExtractedReference(found, "absolute_url", literal.kind, literal.start,
                                                     {"embedded_in_longer_string": True,
                                                      "snippet": value[max(0, match.start() - 40):match.end() + 40][:200]},
                                                     TEMPLATE_PLACEHOLDER in found))
        for match in QUERY_PARAMETER_FRAGMENT.finditer(value):
            references.append(ExtractedReference(match.group(1), "query_parameter_fragment", literal.kind, literal.start,
                                                 {"snippet": value[:200]}))
    return references, literals
