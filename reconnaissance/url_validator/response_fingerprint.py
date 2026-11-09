"""Response fingerprints and similarity, used to compare a URL's response
with the responses to randomized nonexistent paths (catch-all detection)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from ..shared.http_client import FetchResult

VOLATILE_PATTERNS = [
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),  # uuids
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),                     # hashes, request ids
    re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}"),              # tokens / nonces
    re.compile(r"\b\d{5,}\b"),                               # timestamps, counters
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"),
]
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]{1,40}")
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class Fingerprint:
    status_code: int | None
    mime_type: str
    length: int
    normalized_sha256: str
    tokens: frozenset
    title: str

    def as_dict(self) -> dict:
        return {"status_code": self.status_code, "mime_type": self.mime_type, "length": self.length,
                "normalized_sha256": self.normalized_sha256, "token_count": len(self.tokens), "title": self.title}


def normalize_body(text: str, reflected_values: list[str]) -> str:
    for value in reflected_values:
        if value:
            text = text.replace(value, "{reflected}")
    for pattern in VOLATILE_PATTERNS:
        text = pattern.sub("{volatile}", text)
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(result: FetchResult, reflected_values: list[str] | None = None) -> Fingerprint:
    text = result.text()[:400_000]
    normalized = normalize_body(text, reflected_values or [])
    title_match = TITLE.search(text[:20000])
    return Fingerprint(
        status_code=result.status_code,
        mime_type=result.mime_type,
        length=len(normalized),
        normalized_sha256=hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest(),
        tokens=frozenset(TOKEN.findall(normalized[:200_000])),
        title=" ".join(title_match.group(1).split())[:200] if title_match else "",
    )


def similarity(first: Fingerprint, second: Fingerprint) -> float:
    """1.0 for identical normalized bodies; otherwise token Jaccard scaled by length ratio."""
    if first.normalized_sha256 == second.normalized_sha256:
        return 1.0
    if not first.tokens and not second.tokens:
        return 1.0 if first.length == second.length else 0.0
    union = len(first.tokens | second.tokens)
    jaccard = len(first.tokens & second.tokens) / union if union else 0.0
    longest = max(first.length, second.length) or 1
    length_ratio = min(first.length, second.length) / longest
    return round(jaccard * (0.5 + 0.5 * length_ratio), 4)


def same_response(first: Fingerprint, second: Fingerprint, threshold: float = 0.9) -> tuple[bool, float]:
    score = similarity(first, second)
    return (first.status_code == second.status_code and first.mime_type == second.mime_type and score >= threshold), score
