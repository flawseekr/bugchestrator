"""AI-assisted static analysis through the opencode CLI.

The deterministic extractor sees one literal at a time, so it cannot join
``"https://api.grab.com" + "/karta/crowdsourcing/v2" + "/submission/list"``
or resolve ``baseURL`` + relative path pairs, HTTP methods and parameters.
This step sends *excerpts* of a JavaScript file (windows around request
building code) to the configured model and asks for the URLs the code builds.

Anti-fabrication contract, enforced in :func:`verify_candidate`:
* the model must quote an ``evidence`` string copied from the excerpt; it must
  occur verbatim (whitespace-insensitive) in the excerpt text
* every static path segment and the host of the proposed URL must occur in
  the excerpt text; dynamic parts must be written as ``{placeholder}``
Anything failing verification is rejected and logged with the reason, never
written as a discovery.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from urllib.parse import urlsplit

TRIGGER_PATTERN = re.compile(
    r"baseURL|baseUrl|base_url|BASE_URL|apiUrl|API_URL|apiBase|apiHost|endpoint|ENDPOINT|fetch\(|axios|\.get\(|\.post\(|\.put\(|"
    r"\.patch\(|\.delete\(|\.request\(|XMLHttpRequest|\.open\(|url\s*:|path\s*:|\"/api|'/api|/v\d+/|remoteEntry|"
    r"https?://[\w.\-]+|graphql|websocket|WebSocket|EventSource|importScripts|sendBeacon|routes?\s*[:=]|createBrowserRouter|"
    r"\$\{[^}]{1,40}\}/",
)
WINDOW_RADIUS = 350
MAXIMUM_BATCH_CHARACTERS = 24000
MAXIMUM_BATCHES_PER_FILE = 6
PLACEHOLDER = re.compile(r"\{[^{}/]*\}|:[A-Za-z_]\w*|\$\{[^}]*\}")

PROMPT_TEMPLATE = """You are a static-analysis assistant for an authorized security reconnaissance tool.
Below are verbatim excerpts of the JavaScript file {file_url}.
List every URL, API endpoint path, WebSocket/GraphQL endpoint and client-side route that this code
builds or requests, INCLUDING ones assembled by string concatenation, template literals, base URL
plus path joins, or object properties (baseURL + url). Resolve joins only when the parts are visible
in the excerpts.

Rules:
- Never invent anything. Every host and path segment you output must appear in the excerpts.
- Write dynamic parts as {{placeholder}} (e.g. /api/users/{{userId}}).
- "evidence" must be a short substring (max 200 characters) copied EXACTLY from the excerpts that shows
  where the URL comes from.
- Output ONLY a JSON array, no prose, no markdown fences. Each element:
  {{"url": "...", "kind": "api_endpoint|client_route|absolute_url|websocket|graphql|asset|other",
   "http_method": "GET|POST|PUT|PATCH|DELETE|unknown", "parameters": ["name", ...], "evidence": "..."}}
- If there is nothing, output [].

Excerpts:
{excerpts}
"""


@dataclass
class AiCandidate:
    url: str
    kind: str
    http_method: str
    parameters: list[str]
    evidence: str


DYNAMIC_BASE = re.compile(r"^\{\s*(?:[\w$]+\.)*(?P<variable>[A-Za-z_$][\w$]*)\s*\}(?P<remainder>/.*)$")


def split_dynamic_base(url: str) -> tuple[str, str] | None:
    """``{window.config.apiBase}/v1/users`` -> (``apiBase``, ``/v1/users``)."""
    match = DYNAMIC_BASE.match(url.strip())
    if not match:
        return None
    return match.group("variable"), match.group("remainder")


@dataclass
class DynamicBaseCandidate:
    candidate: AiCandidate
    base_variable: str
    remainder: str


@dataclass
class AiCallRecord:
    javascript_file: str
    batch_index: int
    excerpt_characters: int
    model: str
    status: str = "ok"
    error: str | None = None
    duration_seconds: float = 0.0
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    dynamic_base: list[dict] = field(default_factory=list)


def opencode_available() -> bool:
    return shutil.which("opencode") is not None


def select_excerpts(text: str) -> list[tuple[int, str]]:
    """Merged windows around request-building code, packed into batches."""
    windows: list[list[int]] = []
    for match in TRIGGER_PATTERN.finditer(text):
        start = max(0, match.start() - WINDOW_RADIUS)
        end = min(len(text), match.end() + WINDOW_RADIUS)
        if windows and start <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], end)
        else:
            windows.append([start, end])
    batches: list[tuple[int, str]] = []
    current: list[str] = []
    current_size = 0
    for start, end in windows:
        piece = f"--- offset {start} ---\n{text[start:end]}\n"
        if current_size + len(piece) > MAXIMUM_BATCH_CHARACTERS and current:
            batches.append((len(batches), "".join(current)))
            current, current_size = [], 0
            if len(batches) >= MAXIMUM_BATCHES_PER_FILE:
                break
        current.append(piece[:MAXIMUM_BATCH_CHARACTERS])
        current_size += len(piece)
    if current and len(batches) < MAXIMUM_BATCHES_PER_FILE:
        batches.append((len(batches), "".join(current)))
    return batches


def _squash(value: str) -> str:
    return re.sub(r"\s+", "", value)


def verify_candidate(candidate: AiCandidate, excerpt: str) -> str | None:
    """Return None if verified, else the rejection reason."""
    if not candidate.url or len(candidate.url) > 2000:
        return "empty_or_oversized_url"
    if not candidate.evidence:
        return "missing_evidence"
    squashed_excerpt = _squash(excerpt)
    if _squash(candidate.evidence) not in squashed_excerpt:
        return "evidence_not_found_in_excerpt"
    url = candidate.url.strip()
    if url.startswith(("data:", "blob:", "javascript:", "mailto:")):
        return "non_navigable_scheme"
    if re.match(r"^(?:(?:https?|wss?):)?/*\{", url) or re.match(r"^(?:https?|wss?)://[^/]*\{", url):
        return "unresolved_dynamic_host"
    first_segment = url.split("?", 1)[0].split("/", 1)[0]
    if "://" not in url and not url.startswith("/") and "." in first_segment and PLACEHOLDER.search(first_segment):
        return "host_pattern_without_scheme"
    if url.startswith(("ws://", "wss://")):
        url = "http" + url[2:]
    try:
        parts = urlsplit(url if "://" in url or url.startswith("//") else "http://placeholder.invalid" + ("" if url.startswith("/") else "/") + url)
    except ValueError:
        return "unparseable_url"
    host = parts.hostname or ""
    if host and host != "placeholder.invalid" and host not in excerpt and not PLACEHOLDER.search(parts.netloc):
        return f"host_not_in_excerpt:{host}"
    for segment in parts.path.split("/"):
        if not segment or PLACEHOLDER.fullmatch(segment):
            continue
        literal_parts = [piece for piece in PLACEHOLDER.split(segment) if len(piece) >= 2]
        for piece in literal_parts:
            if piece not in excerpt:
                return f"path_segment_not_in_excerpt:{piece}"
    for name, _value in [pair.split("=", 1) if "=" in pair else (pair, "") for pair in parts.query.split("&") if pair]:
        if name and not PLACEHOLDER.fullmatch(name) and name not in excerpt:
            return f"query_parameter_not_in_excerpt:{name}"
    return None


def _parse_opencode_output(stdout: str) -> str:
    text_parts = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        part = event.get("part") or {}
        if event.get("type") == "text" and part.get("text"):
            text_parts.append(part["text"])
    return "".join(text_parts)


def _parse_candidates(answer: str) -> list[AiCandidate]:
    answer = answer.strip()
    answer = re.sub(r"^```(?:json)?|```$", "", answer, flags=re.MULTILINE).strip()
    start, end = answer.find("["), answer.rfind("]")
    if start == -1 or end == -1:
        raise ValueError("no JSON array in model answer")
    data = json.loads(answer[start:end + 1])
    candidates = []
    for item in data:
        if not isinstance(item, dict):
            continue
        candidates.append(AiCandidate(
            url=str(item.get("url") or "").strip(),
            kind=str(item.get("kind") or "other"),
            http_method=str(item.get("http_method") or "unknown").upper(),
            parameters=[str(name) for name in (item.get("parameters") or []) if isinstance(name, (str, int))][:50],
            evidence=str(item.get("evidence") or "")[:400],
        ))
    return candidates


def analyze_batch(file_url: str, batch_index: int, excerpt: str, model: str,
                  timeout_seconds: int = 240) -> tuple[AiCallRecord, list[AiCandidate], list[DynamicBaseCandidate]]:
    import time

    record = AiCallRecord(file_url, batch_index, len(excerpt), model)
    prompt = PROMPT_TEMPLATE.format(file_url=file_url, excerpts=excerpt)
    started = time.monotonic()
    accepted: list[AiCandidate] = []
    with tempfile.TemporaryDirectory(prefix="bugchestrator-opencode-") as working_directory:
        try:
            completed = subprocess.run(
                ["opencode", "run", "--model", model, "--format", "json", prompt],
                cwd=working_directory, capture_output=True, text=True, timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            record.status, record.error = "timeout", f"opencode exceeded {timeout_seconds}s"
            record.duration_seconds = round(time.monotonic() - started, 1)
            return record, [], []
        except OSError as error:
            record.status, record.error = "failed", str(error)
            return record, [], []
    record.duration_seconds = round(time.monotonic() - started, 1)
    answer = _parse_opencode_output(completed.stdout)
    if completed.returncode != 0 and not answer:
        record.status = "failed"
        record.error = (completed.stderr or completed.stdout)[-500:]
        return record, [], []
    try:
        candidates = _parse_candidates(answer)
    except (ValueError, json.JSONDecodeError) as error:
        record.status = "unparseable_answer"
        record.error = f"{error}: {answer[:300]}"
        return record, [], []
    dynamic: list[DynamicBaseCandidate] = []
    for candidate in candidates:
        reason = verify_candidate(candidate, excerpt)
        entry = {"url": candidate.url, "kind": candidate.kind, "http_method": candidate.http_method,
                 "parameters": candidate.parameters, "evidence": candidate.evidence}
        if reason == "unresolved_dynamic_host":
            split = split_dynamic_base(candidate.url)
            if split:
                variable, remainder = split
                remainder_candidate = AiCandidate(remainder, candidate.kind, candidate.http_method,
                                                  candidate.parameters, candidate.evidence)
                remainder_reason = verify_candidate(remainder_candidate, excerpt)
                if remainder_reason is None and variable in excerpt:
                    # Path verified; the base is resolved later only from a
                    # literal assignment found in the analysed sources.
                    record.dynamic_base.append({**entry, "base_variable": variable, "remainder": remainder})
                    dynamic.append(DynamicBaseCandidate(candidate, variable, remainder))
                    continue
                reason = remainder_reason or "base_variable_not_in_excerpt"
        if reason:
            record.rejected.append({**entry, "rejection_reason": reason})
        else:
            record.accepted.append(entry)
            accepted.append(candidate)
    return record, accepted, dynamic
