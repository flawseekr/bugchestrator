"""HTTP client shared by every module.

* thread-local ``requests`` sessions with connection pooling
* per-host concurrency limits and a minimum delay between requests per host
* retries with exponential backoff for connection errors, timeouts and
  429/502/503/504 (``Retry-After`` honoured, capped)
* manual redirect following so every hop is recorded and scope-checked
* bounded body download (streamed) so huge files cannot exhaust memory
* a structured :class:`FetchResult` that doubles as HTTP evidence
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

import requests
import urllib3

from .url_normalization import host_of, normalize_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 bugchestrator-reconnaissance/1.0"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Accept-Encoding": "gzip, deflate",
}
RETRYABLE_STATUS_CODES = {429, 502, 503, 504}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

logger = logging.getLogger("bugchestrator.http")


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None

    def as_dict(self) -> dict:
        return {"url": self.url, "status_code": self.status_code, "location": self.location}


@dataclass
class FetchResult:
    method: str
    requested_url: str
    final_url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_size: int = 0
    body_truncated: bool = False
    elapsed_milliseconds: int = 0
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    redirect_blocked_url: str | None = None
    error: str | None = None
    attempts: int = 0
    fetched_at: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def mime_type(self) -> str:
        return self.content_type.split(";", 1)[0].strip().lower()

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def text(self) -> str:
        return decode_body(self.body, self.content_type)

    def evidence(self, include_snippet: int = 0, include_headers: bool = False) -> dict:
        """Serializable HTTP evidence for JSONL records."""
        record = {
            "request_method": self.method,
            "request_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_size": self.body_size,
            "response_size_truncated": self.body_truncated,
            "elapsed_milliseconds": self.elapsed_milliseconds,
            "redirect_chain": [hop.as_dict() for hop in self.redirect_chain],
            "fetched_at": self.fetched_at,
            "attempts": self.attempts,
        }
        if self.redirect_blocked_url:
            record["redirect_blocked_out_of_scope"] = self.redirect_blocked_url
        if self.error:
            record["error"] = self.error
        if include_headers:
            record["request_headers"] = self.request_headers
            record["response_headers"] = self.headers
        if include_snippet:
            record["body_sha256"] = self.body_sha256
            record["body_snippet"] = self.text()[:include_snippet]
        return record


def decode_body(body: bytes, content_type: str = "") -> str:
    match = re.search(r"charset=([\w\-]+)", content_type or "", re.IGNORECASE)
    encodings = [match.group(1)] if match else []
    encodings += ["utf-8", "latin-1"]
    for encoding in encodings:
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class HttpClient:
    def __init__(
        self,
        timeout_seconds: float = 20.0,
        maximum_retries: int = 3,
        maximum_body_bytes: int = 15 * 1024 * 1024,
        per_host_concurrency: int = 4,
        per_host_delay_seconds: float = 0.1,
        maximum_redirects: int = 10,
        verify_tls: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.maximum_retries = maximum_retries
        self.maximum_body_bytes = maximum_body_bytes
        self.per_host_concurrency = per_host_concurrency
        self.per_host_delay_seconds = per_host_delay_seconds
        self.maximum_redirects = maximum_redirects
        self.verify_tls = verify_tls
        self.headers = dict(DEFAULT_HEADERS)
        if extra_headers:
            self.headers.update(extra_headers)
        self._local = threading.local()
        self._host_semaphores: dict[str, threading.Semaphore] = {}
        self._host_last_request: dict[str, float] = {}
        self._lock = threading.Lock()
        self.request_count = 0

    # ------------------------------------------------------------------ internals
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            session.headers.update(self.headers)
            self._local.session = session
        return session

    def _semaphore(self, host: str) -> threading.Semaphore:
        with self._lock:
            semaphore = self._host_semaphores.get(host)
            if semaphore is None:
                semaphore = threading.Semaphore(self.per_host_concurrency)
                self._host_semaphores[host] = semaphore
            return semaphore

    def _respect_host_delay(self, host: str) -> None:
        if self.per_host_delay_seconds <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                last = self._host_last_request.get(host, 0.0)
                wait = last + self.per_host_delay_seconds - now
                if wait <= 0:
                    self._host_last_request[host] = now
                    return
            time.sleep(wait)

    @staticmethod
    def _retry_after_seconds(response: requests.Response, attempt: int) -> float:
        header = response.headers.get("Retry-After", "")
        if header.isdigit():
            return min(float(header), 30.0)
        return min(2 ** attempt + random.random(), 30.0)

    def _single_request(self, method: str, url: str, headers: dict | None, data) -> tuple[requests.Response | None, bytes, bool, str | None, int, int]:
        """One logical request (with retries), no redirect following."""
        host = host_of(url)
        last_error = None
        attempt = 0
        for attempt in range(1, self.maximum_retries + 2):
            semaphore = self._semaphore(host)
            with semaphore:
                self._respect_host_delay(host)
                started = time.monotonic()
                try:
                    with self._lock:
                        self.request_count += 1
                    response = self._session().request(
                        method, url, headers=headers, data=data, timeout=self.timeout_seconds,
                        allow_redirects=False, stream=True, verify=self.verify_tls,
                    )
                    body, truncated = self._read_body(response)
                    elapsed = int((time.monotonic() - started) * 1000)
                except requests.exceptions.SSLError as error:
                    last_error = f"tls_error: {error.__class__.__name__}: {str(error)[:300]}"
                    break  # retrying a TLS failure never helps
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                        requests.exceptions.ChunkedEncodingError) as error:
                    last_error = f"{error.__class__.__name__}: {str(error)[:300]}"
                    logger.debug("attempt %s failed for %s: %s", attempt, url, last_error)
                    if attempt <= self.maximum_retries:
                        time.sleep(min(2 ** (attempt - 1) + random.random(), 20.0))
                    continue
                except requests.exceptions.RequestException as error:
                    last_error = f"{error.__class__.__name__}: {str(error)[:300]}"
                    break
            if response.status_code in RETRYABLE_STATUS_CODES and attempt <= self.maximum_retries:
                delay = self._retry_after_seconds(response, attempt)
                logger.debug("status %s for %s, retrying in %.1fs", response.status_code, url, delay)
                time.sleep(delay)
                continue
            return response, body, truncated, None, elapsed, attempt
        return None, b"", False, last_error, 0, attempt

    def _read_body(self, response: requests.Response) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= self.maximum_body_bytes:
                    truncated = True
                    break
        finally:
            response.close()
        return b"".join(chunks)[: self.maximum_body_bytes], truncated

    # ------------------------------------------------------------------ public API
    def fetch(
        self,
        url: str,
        method: str = "GET",
        follow_redirects: bool = True,
        redirect_allowed: Callable[[str], bool] | None = None,
        headers: dict | None = None,
        data=None,
    ) -> FetchResult:
        """Request ``url`` and follow redirects manually.

        ``redirect_allowed`` is called for every redirect target; when it
        returns False the chain stops and the blocked target is recorded.
        """
        result = FetchResult(method=method, requested_url=url, final_url=url, fetched_at=utc_timestamp())
        session_headers = dict(self.headers)
        if headers:
            session_headers.update(headers)
        result.request_headers = session_headers
        current_url = url
        total_elapsed = 0
        for _hop in range(self.maximum_redirects + 1):
            response, body, truncated, error, elapsed, attempts = self._single_request(method, current_url, headers, data)
            result.attempts += attempts
            total_elapsed += elapsed
            if response is None:
                result.error = error
                result.final_url = current_url
                break
            result.status_code = response.status_code
            result.headers = {key.lower(): value for key, value in response.headers.items()}
            result.body = body
            result.body_size = len(body)
            result.body_truncated = truncated
            result.final_url = current_url
            location = response.headers.get("Location")
            if follow_redirects and response.status_code in REDIRECT_STATUS_CODES and location:
                next_url = normalize_url(urljoin(current_url, location))
                result.redirect_chain.append(RedirectHop(current_url, response.status_code, location))
                if not next_url:
                    break
                if redirect_allowed is not None and not redirect_allowed(next_url):
                    result.redirect_blocked_url = next_url
                    break
                if any(hop.url == next_url for hop in result.redirect_chain):
                    result.error = "redirect_loop"
                    break
                if response.status_code == 303:
                    method, data = "GET", None
                current_url = next_url
                continue
            break
        else:
            result.error = "too_many_redirects"
        result.elapsed_milliseconds = total_elapsed
        return result
