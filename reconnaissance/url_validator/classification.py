"""Evidence-based classification of a validated URL.

Two independent axes, both derived from the observed HTTP exchange:

``accessibility``  accessible | restricted | not_found | method_not_allowed |
                   server_error | redirect_out_of_scope | client_error |
                   unreachable
``resource_type``  html_page | api_endpoint | spa_route | spa_catch_all |
                   soft_404 | file:<subtype> | redirect | empty_response |
                   error_response | unknown

Rules (never URL patterns, names or status code alone):
* body content sniffing (magic bytes, JSON/XML/HTML parse), response headers
* comparison against randomized nonexistent paths on the same host and with
  the same shape in the same parent directory (catch-all detection)
* comparison against the host root document, and whether that root is an
  application shell (SPA shell detection)
Every decision appends a human-readable line to ``evidence``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..shared.http_client import FetchResult
from .response_fingerprint import Fingerprint, same_response

MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "image_png"), (b"\xff\xd8\xff", "image_jpeg"), (b"GIF87a", "image_gif"), (b"GIF89a", "image_gif"),
    (b"%PDF-", "document_pdf"), (b"PK\x03\x04", "archive_zip"), (b"\x1f\x8b", "archive_gzip"), (b"wOFF", "font_woff"),
    (b"wOF2", "font_woff2"), (b"\x00\x00\x01\x00", "image_icon"), (b"OggS", "media_ogg"), (b"ID3", "audio_mp3"),
    (b"\x1aE\xdf\xa3", "media_webm"), (b"Rar!", "archive_rar"), (b"7z\xbc\xaf", "archive_7z"), (b"\x00asm", "binary_webassembly"),
    (b"BM", "image_bmp"), (b"\x00\x01\x00\x00", "font_truetype"), (b"OTTO", "font_opentype"),
]
STATIC_FILE_HEADERS = ("last-modified", "x-amz-request-id", "x-amz-version-id", "x-goog-generation", "x-goog-hash", "x-ms-blob-type")
XSSI_PREFIXES = (")]}'", ")]}',", "while(1);", "for(;;);")


@dataclass
class Classification:
    accessibility: str
    resource_type: str
    evidence: list[str] = field(default_factory=list)


def _sniff_magic(body: bytes) -> str | None:
    head = body[:16]
    if head[4:8] == b"ftyp":
        return "media_mp4"
    if head[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image_webp"
    for signature, name in MAGIC_SIGNATURES:
        if head.startswith(signature):
            if name == "image_bmp" and len(body) < 26:
                continue
            if name == "font_truetype" and not body[4:6]:
                continue
            return name
    return None


def _parse_json(text: str):
    stripped = text.lstrip()
    for prefix in XSSI_PREFIXES:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):].lstrip()
    if not stripped or stripped[0] not in "{[\"" and not stripped[:4] in ("true", "null") and not stripped[:5] == "false":
        return None, False
    try:
        return json.loads(stripped), True
    except (json.JSONDecodeError, ValueError):
        return None, False


def _static_file_indicators(result: FetchResult) -> list[str]:
    indicators = [header for header in STATIC_FILE_HEADERS if header in result.headers]
    if result.headers.get("accept-ranges", "").lower() == "bytes":
        indicators.append("accept-ranges: bytes")
    return indicators


def content_type_of_body(result: FetchResult) -> tuple[str, list[str]]:
    """Return a body kind and the evidence used: html, json, xml, javascript,
    stylesheet, text, file:<magic>, empty, binary."""
    body = result.body
    mime = result.mime_type
    evidence: list[str] = []
    if not body.strip():
        return "empty", [f"empty body ({result.body_size} bytes)"]
    magic = _sniff_magic(body)
    if magic:
        return f"file:{magic}", [f"magic bytes identify {magic}"]
    text = result.text()[:200_000]
    head = text[:1024].lstrip().lower()
    if head.startswith(("<!doctype html", "<html")) or ("<head" in head[:400] and "<" == head[:1]) or (
            "html" in mime and re.search(r"<(body|div|head|title|script)\b", text[:5000], re.IGNORECASE)):
        return "html", [f"body is an HTML document (content-type {mime or 'none'})"]
    if head.startswith("<svg") or (head.startswith("<?xml") and "<svg" in head):
        return "file:image_svg", ["body is an SVG document"]
    parsed, is_json = _parse_json(text)
    if is_json:
        if isinstance(parsed, dict) and parsed.get("version") == 3 and "mappings" in parsed:
            return "file:source_map", ["body is a version 3 source map"]
        return "json", [f"body parses as JSON ({type(parsed).__name__}, content-type {mime or 'none'})"]
    if head.startswith("<?xml") or ("xml" in mime and head.startswith("<")):
        return "xml", [f"body is XML (content-type {mime or 'none'})"]
    if "javascript" in mime or "ecmascript" in mime:
        return "javascript", [f"content-type {mime} with non-HTML, non-JSON body"]
    if mime == "text/css":
        return "stylesheet", ["content-type text/css with non-HTML body"]
    if mime.startswith("text/") or all(32 <= byte < 127 or byte in (9, 10, 13) for byte in body[:2048]):
        return "text", [f"printable text body (content-type {mime or 'none'})"]
    evidence.append(f"unrecognized binary body (content-type {mime or 'none'})")
    return "binary", evidence


def looks_like_application_shell(result: FetchResult) -> bool:
    """A single-page-application shell: an HTML document that loads scripts
    and carries almost no server-rendered visible text."""
    if not result.ok or "html" not in (result.mime_type or "text/html"):
        return False
    text = result.text()[:500_000]
    if not re.search(r"<script\b[^>]*\bsrc=", text, re.IGNORECASE):
        return False
    visible = re.sub(r"<(script|style|noscript|template|svg)\b.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    visible = re.sub(r"<[^>]+>", " ", visible)
    visible = re.sub(r"\s+", " ", visible).strip()
    return len(visible) < 1500


def classify(result: FetchResult, path: str, fingerprint_of_url: Fingerprint | None,
             directory_baseline: Fingerprint | None, host_baseline: Fingerprint | None,
             root_document: Fingerprint | None, defined_as_client_route: bool,
             root_is_application_shell: bool = True) -> Classification:
    evidence: list[str] = []
    if not result.ok:
        return Classification("unreachable", "unknown", [f"no HTTP response: {result.error}"])
    if result.redirect_blocked_url:
        return Classification("redirect_out_of_scope", "redirect",
                              [f"redirect chain leaves scope to {result.redirect_blocked_url}; not followed"])
    status = result.status_code
    if result.redirect_chain:
        evidence.append(f"followed {len(result.redirect_chain)} in-scope redirect(s) to {result.final_url}")

    # ---- accessibility, from status code *and* body context
    if 200 <= status < 300:
        accessibility = "accessible"
    elif status in (401, 403, 407):
        accessibility = "restricted"
    elif status in (404, 410):
        accessibility = "not_found"
    elif status == 405:
        accessibility = "method_not_allowed"
    elif status >= 500:
        accessibility = "server_error"
    elif 300 <= status < 400:
        accessibility = "accessible"
        evidence.append(f"terminal {status} without a followable in-scope Location")
    else:
        accessibility = "client_error"
    evidence.append(f"HTTP {status}")

    body_kind, body_evidence = content_type_of_body(result)
    evidence.extend(body_evidence)

    # ---- catch-all comparison
    is_root = path in ("", "/")
    baseline = directory_baseline or host_baseline
    if fingerprint_of_url is not None and baseline is not None and not is_root:
        matched, score = same_response(fingerprint_of_url, baseline)
        label = "same-shape" if baseline is directory_baseline else "host"
        if matched:
            evidence.append(f"response matches the {label} random-nonexistent-path baseline "
                            f"(same status {status}, same content-type, body similarity {score})")
            if 200 <= status < 300:
                shell_match = False
                if root_document is not None:
                    shell_match, shell_score = same_response(fingerprint_of_url, root_document)
                    evidence.append(f"similarity to host root document {shell_score}")
                if body_kind == "html" and shell_match and not root_is_application_shell:
                    evidence.append("the host root is a server-rendered page (not an application shell): "
                                    "nonexistent paths receive the homepage")
                    return Classification("not_found", "soft_404", evidence)
                if body_kind == "html" and shell_match:
                    evidence.append("the host root document is a single-page-application shell")
                    if defined_as_client_route:
                        evidence.append("a JavaScript source references this path in a client-route context; "
                                        "the server answers with the SPA shell")
                        return Classification("accessible", "spa_route", evidence)
                    return Classification("accessible", "spa_catch_all", evidence)
                return Classification("not_found", "soft_404", evidence + ["2xx response indistinguishable from a nonexistent path"])
            if accessibility == "accessible":  # 3xx identical to the nonexistent-path answer
                accessibility = "not_found"
            evidence.append("indistinguishable from a nonexistent path")
            return Classification(accessibility, "error_response" if accessibility != "restricted" else "unknown", evidence)
        evidence.append(f"response differs from the {label} random-nonexistent-path baseline "
                        f"(status {status} vs {baseline.status_code}, content-type {fingerprint_of_url.mime_type or 'none'} vs "
                        f"{baseline.mime_type or 'none'}, body similarity {score})")

    if 300 <= status < 400:
        return Classification(accessibility, "redirect", evidence)

    # Distinct from catch-all but identical to the root SPA shell: the server
    # deliberately serves the application shell for this path.
    if (body_kind == "html" and fingerprint_of_url is not None and root_document is not None and not is_root
            and 200 <= status < 300):
        shell_match, shell_score = same_response(fingerprint_of_url, root_document, threshold=0.95)
        if shell_match and not root_is_application_shell:
            evidence.append(f"server returns the homepage for this path (similarity {shell_score}) while random paths "
                            "of the same shape are handled differently: homepage fallback, no distinct content")
            return Classification("not_found", "soft_404", evidence)
        if shell_match:
            evidence.append(f"server returns the root application shell for this path (similarity {shell_score}) "
                            "although random paths are handled differently")
            return Classification(accessibility, "spa_route", evidence)

    error_response = accessibility in ("not_found", "server_error", "client_error")
    distinct_from_baseline = baseline is not None and fingerprint_of_url is not None and not is_root
    if body_kind == "empty" and accessibility in ("restricted", "method_not_allowed") and distinct_from_baseline and (
            "json" in result.mime_type or "xml" in result.mime_type):
        evidence.append(f"declared content-type {result.mime_type} with {status}, distinct from nonexistent paths: "
                        "an existing endpoint refusing the anonymous GET")
        return Classification(accessibility, "api_endpoint", evidence)
    if error_response:
        evidence.append("error response; the resource type behind it cannot be determined")
        return Classification(accessibility, "error_response", evidence)
    return Classification(accessibility, _resource_type_for(body_kind, result, evidence, defined_as_client_route,
                                                            error_response), evidence)


def _resource_type_for(body_kind: str, result: FetchResult, evidence: list[str], defined_as_client_route: bool,
                       error_response: bool) -> str:
    if body_kind == "html":
        return "html_page"
    if body_kind in ("json", "xml"):
        indicators = _static_file_indicators(result)
        text_head = result.text()[:600].lower()
        if body_kind == "xml" and re.search(r"<(rss|feed|urlset|sitemapindex)\b", text_head):
            evidence.append("XML feed/sitemap document")
            return "file:xml_document"
        if body_kind == "xml" and "envelope" in text_head and "soap" in text_head:
            evidence.append("SOAP envelope")
            return "api_endpoint"
        if indicators and not error_response:
            evidence.append(f"static file delivery headers present: {', '.join(indicators)}")
            return f"file:{body_kind}_document"
        if not indicators:
            evidence.append("no static-file delivery headers (no Last-Modified/Accept-Ranges/object-storage headers)")
        return "api_endpoint"
    if body_kind == "empty":
        return "empty_response"
    if body_kind in ("javascript", "stylesheet", "text", "binary"):
        return f"file:{body_kind}"
    if body_kind.startswith("file:"):
        return body_kind
    return "unknown"
