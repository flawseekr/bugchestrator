"""URL normalization, deduplication keys and path templates.

Every module normalizes URLs through this file so that the same resource is
represented by the same string everywhere in the pipeline.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

NON_NAVIGABLE_SCHEMES = (
    "javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "sms:",
    "whatsapp:", "intent:", "file:", "ftp:", "chrome:", "market:", "itms",
    "fb:", "skype:", "geo:", "maps:", "callto:", "webcal:", "line:",
)
DEFAULT_PORTS = {"http": 80, "https": 443}

# Characters that may stay unescaped in a path / query (RFC 3986 unreserved +
# sub-delims + ":" "@" "/" and "%" so existing escapes are preserved).
PATH_SAFE_CHARACTERS = "/:@!$&'()*+,;=-._~%"
QUERY_SAFE_CHARACTERS = "/:@!$&'()*+,;=-._~%?"

UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LONG_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,}$")
NUMBER_PATTERN = re.compile(r"^\d+$")


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 dot-segment removal."""
    if not path:
        return "/"
    segments = path.split("/")
    output: list[str] = []
    for segment in segments:
        if segment == ".":
            continue
        if segment == "..":
            if len(output) > 1:
                output.pop()
            continue
        output.append(segment)
    result = "/".join(output)
    if path.endswith(("/.", "/..")):
        result += "/"
    if not result.startswith("/"):
        result = "/" + result
    return result


def _normalize_host(host: str) -> str | None:
    host = host.strip().rstrip(".").lower()
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not re.fullmatch(r"[a-z0-9.\-_\[\]:]+", host):
        return None
    if ".." in host or host.startswith(("-", ".")):
        return None
    return host


def normalize_url(raw_url: str, base_url: str | None = None) -> str | None:
    """Return a canonical absolute http(s) URL or None when not navigable.

    * resolves relative references against ``base_url``
    * lower-cases scheme and host, IDNA-encodes the host, drops default ports
    * removes fragments and dot segments, guarantees a non-empty path
    * percent-encodes unsafe characters while preserving existing escapes
    * keeps the query string and its parameter order intact
    """
    if raw_url is None:
        return None
    candidate = raw_url.strip().replace("\\/", "/")
    candidate = re.sub(r"[\t\r\n]", "", candidate)
    if not candidate or candidate.startswith("#"):
        return None
    lowered = candidate.lower()
    if lowered.startswith(NON_NAVIGABLE_SCHEMES):
        return None
    if base_url:
        try:
            candidate = urljoin(base_url, candidate)
        except ValueError:
            return None
    elif candidate.startswith("//"):
        candidate = "https:" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not hostname:
        return None
    host = _normalize_host(hostname)
    if host is None:
        return None
    netloc = host
    if port and DEFAULT_PORTS.get(scheme) != port:
        netloc = f"{host}:{port}"
    path = _remove_dot_segments(parts.path or "/")
    path = quote(path, safe=PATH_SAFE_CHARACTERS)
    query = quote(parts.query, safe=QUERY_SAFE_CHARACTERS) if parts.query else ""
    return urlunsplit((scheme, netloc, path, query, ""))


def deduplication_key(normalized_url: str) -> str:
    """Key that treats URLs differing only by query-parameter order as equal."""
    parts = urlsplit(normalized_url)
    if not parts.query:
        return normalized_url
    sorted_query = "&".join(
        f"{name}={value}" for name, value in sorted(parse_qsl(parts.query, keep_blank_values=True))
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, sorted_query, ""))


def query_parameter_names(url: str) -> list[str]:
    """Ordered, unique query parameter names of ``url``."""
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []
    seen: dict[str, None] = {}
    for name, _value in pairs:
        if name:
            seen.setdefault(name, None)
    return list(seen)


def query_parameters(url: str) -> dict[str, list[str]]:
    """All query parameters of ``url`` with every observed value."""
    result: dict[str, list[str]] = {}
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return result
    for name, value in pairs:
        result.setdefault(name, []).append(value)
    return result


def _template_segment(segment: str) -> str:
    decoded = unquote(segment)
    if NUMBER_PATTERN.match(decoded):
        return "{number}"
    if UUID_PATTERN.match(decoded):
        return "{uuid}"
    if LONG_HEX_PATTERN.match(decoded):
        return "{hex}"
    return segment


def path_template(normalized_url: str) -> str:
    """Structural template: numeric/uuid/hash path segments and query values
    replaced so that ``/item/1?page=2`` and ``/item/7?page=9`` share a template."""
    parts = urlsplit(normalized_url)
    path = "/".join(_template_segment(segment) for segment in parts.path.split("/"))
    names = sorted(query_parameter_names(normalized_url))
    query = "&".join(f"{name}=*" for name in names)
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"
