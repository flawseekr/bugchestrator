"""Real OSINT sources.

Each source is a function ``(context) -> SourceResult``.  A source never
invents data: every URL or hostname it returns was parsed out of a response
body whose request is logged in ``SourceResult.requests`` (URL, status code,
size), so each record can be traced back to the exact query that produced it.

Sources that need credentials (GitHub code search) are skipped with an
explicit status when the credential is not present in the environment.
Search engines that answer with a CAPTCHA / bot wall are reported as
``blocked`` rather than as "no results".
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from ..shared.http_client import FetchResult, HttpClient, utc_timestamp
from ..shared.scope import TargetScope

logger = logging.getLogger("bugchestrator.url_osint_gatherer")
URL_IN_TEXT = re.compile(r"""https?://[^\s"'<>\\)\]}`,]+""", re.IGNORECASE)


@dataclass
class SourceContext:
    scope: TargetScope
    client: HttpClient
    query_hosts: list[str]          # hosts whose URLs are collected
    time_budget_seconds: float = 420.0


@dataclass
class SourceResult:
    source: str
    status: str = "ok"               # ok | partial | blocked | skipped | failed | empty
    detail: str | None = None
    urls: list[tuple[str, dict]] = field(default_factory=list)
    subdomains: list[tuple[str, dict]] = field(default_factory=list)
    requests: list[dict] = field(default_factory=list)
    started_at: str = field(default_factory=utc_timestamp)
    last_error: str | None = None

    def log_request(self, result: FetchResult, note: str | None = None) -> None:
        entry = {
            "request_method": result.method,
            "request_url": result.requested_url,
            "status_code": result.status_code,
            "content_type": result.content_type,
            "response_size": result.body_size,
            "elapsed_milliseconds": result.elapsed_milliseconds,
            "fetched_at": result.fetched_at,
        }
        if result.error:
            entry["error"] = result.error
            self.last_error = result.error
        if note:
            entry["note"] = note
        self.requests.append(entry)
        outcome = f"HTTP {result.status_code} ({_human_size(result.body_size)})" if result.status_code else f"no response: {result.error}"
        logger.info("%s: %s %s -> %s%s", self.source, result.method, _short(result.requested_url), _short(outcome, 140),
                    f" [{note}]" if note else "")


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size} B"


def _short(text: str, length: int = 120) -> str:
    return text if len(text) <= length else text[: length - 3] + "..."


class Deadline:
    def __init__(self, seconds: float) -> None:
        self.end = time.monotonic() + seconds

    def expired(self) -> bool:
        return time.monotonic() > self.end


def _finalize(result: SourceResult, any_success: bool, any_failure: bool) -> SourceResult:
    if result.status in ("blocked", "skipped"):
        return result
    if not any_success:
        if result.last_error and not any(request.get("status_code") for request in result.requests):
            # No HTTP response at all: the source is unreachable from this network.
            result.status = "unreachable"
            result.detail = result.detail or result.last_error
        elif result.requests and all(request.get("status_code") in (403, 429) for request in result.requests):
            result.status = "rate_limited"
            codes = sorted({request["status_code"] for request in result.requests})
            result.detail = f"source refused every request with HTTP {codes} (rate limit / bot protection)"
        else:
            result.status = "failed" if any_failure else "empty"
    elif any_failure:
        result.status = "partial"
    elif not result.urls and not result.subdomains:
        result.status = "empty"
    return result


def _json(result: FetchResult):
    try:
        return json.loads(result.text())
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------- Wayback Machine
def wayback_machine(context: SourceContext) -> SourceResult:
    """Wayback Machine CDX API: every archived URL (collapsed by URL key) of the target host(s)."""
    result = SourceResult("wayback_machine_cdx")
    deadline = Deadline(context.time_budget_seconds)
    any_success = any_failure = False
    page_size = 25000
    for host in context.query_hosts:
        resume_key = None
        for _page in range(40):
            if deadline.expired():
                result.detail = "time budget exhausted"
                any_failure = True
                break
            parameters = {
                "url": f"{host}/*", "output": "json", "fl": "original,timestamp,statuscode,mimetype",
                "collapse": "urlkey", "limit": str(page_size), "showResumeKey": "true",
            }
            if resume_key:
                parameters["resumeKey"] = resume_key
            response = context.client.fetch("https://web.archive.org/cdx/search/cdx?" + urlencode(parameters))
            result.log_request(response)
            rows = _json(response) if response.status_code == 200 else None
            if not isinstance(rows, list):
                any_failure = True
                result.detail = f"unexpected response for {host}: {response.status_code} {response.error or ''}".strip()
                break
            any_success = True
            resume_key = None
            for index, row in enumerate(rows):
                if index == 0 and row and row[0] == "original":
                    continue
                if not row:
                    continue
                if len(row) == 1 and index >= len(rows) - 1:
                    resume_key = row[0]
                    continue
                if len(row) < 4:
                    continue
                original, timestamp, status, mime = row[:4]
                result.urls.append((original, {"archived_timestamp": timestamp, "archived_status": status,
                                               "archived_mime_type": mime, "query_host": host}))
            logger.info("wayback_machine_cdx: %s -> %s archived URLs collected so far%s", host, len(result.urls),
                        " (more pages follow)" if resume_key else "")
            if not resume_key:
                break
    # Note: domain-wide host enumeration via CDX (matchType=domain) is not
    # used: results are SURT-ordered, so any row limit is consumed by the apex
    # domain and the host list is silently truncated.
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- Common Crawl
def common_crawl(context: SourceContext) -> SourceResult:
    result = SourceResult("common_crawl_index")
    deadline = Deadline(context.time_budget_seconds)
    any_success = any_failure = False
    collections = context.client.fetch("https://index.commoncrawl.org/collinfo.json")
    result.log_request(collections)
    indexes = _json(collections) if collections.status_code == 200 else None
    if not isinstance(indexes, list) or not indexes:
        result.detail = f"collection list unavailable ({collections.status_code} {collections.error or ''})".strip()
        return _finalize(result, False, True)
    for index in indexes[:3]:
        endpoint = index.get("cdx-api")
        if not endpoint:
            continue
        for host in context.query_hosts:
            for page in range(10):
                if deadline.expired():
                    result.detail = "time budget exhausted"
                    return _finalize(result, any_success, True)
                parameters = {"url": f"{host}/*", "output": "json", "fl": "url,timestamp,status,mime", "page": str(page)}
                response = context.client.fetch(endpoint + "?" + urlencode(parameters))
                result.log_request(response)
                if response.status_code == 404:  # "No Captures found"
                    any_success = True
                    break
                if response.status_code != 200:
                    any_failure = True
                    result.detail = f"{index.get('id')}: {response.status_code} {response.error or ''}".strip()
                    break
                any_success = True
                lines = response.text().splitlines()
                for line in lines:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if row.get("url"):
                        result.urls.append((row["url"], {"crawl_index": index.get("id"), "captured_timestamp": row.get("timestamp"),
                                                         "captured_status": row.get("status"), "captured_mime_type": row.get("mime")}))
                if "Page" in response.text()[:200] or len(lines) < 10:
                    break
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- AlienVault OTX
def alienvault_otx(context: SourceContext) -> SourceResult:
    result = SourceResult("alienvault_otx")
    deadline = Deadline(context.time_budget_seconds)
    any_success = any_failure = False
    for host in context.query_hosts:
        for page in range(1, 51):
            if deadline.expired():
                any_failure = True
                result.detail = "time budget exhausted"
                break
            url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{host}/url_list?limit=500&page={page}"
            response = context.client.fetch(url)
            result.log_request(response)
            data = _json(response) if response.status_code == 200 else None
            if not isinstance(data, dict):
                any_failure = True
                result.detail = f"url_list {host}: {response.status_code} {response.error or ''}".strip()
                break
            any_success = True
            for item in data.get("url_list", []):
                if item.get("url"):
                    result.urls.append((item["url"], {"otx_date": item.get("date"),
                                                      "otx_http_code": (item.get("result") or {}).get("urlworker", {}).get("http_code")}))
            if not data.get("has_next"):
                break
    if not deadline.expired():
        response = context.client.fetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{context.scope.domain}/passive_dns")
        result.log_request(response, "passive DNS")
        data = _json(response) if response.status_code == 200 else None
        if isinstance(data, dict):
            any_success = True
            for item in data.get("passive_dns", []):
                if item.get("hostname"):
                    result.subdomains.append((item["hostname"], {"evidence": "passive DNS", "record_type": item.get("record_type"),
                                                                 "first_seen": item.get("first"), "last_seen": item.get("last")}))
        else:
            any_failure = True
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- urlscan.io
def urlscan(context: SourceContext) -> SourceResult:
    result = SourceResult("urlscan_io")
    deadline = Deadline(context.time_budget_seconds)
    any_success = any_failure = False
    headers = {"Accept": "application/json"}
    if os.environ.get("URLSCAN_API_KEY"):
        headers["API-Key"] = os.environ["URLSCAN_API_KEY"]
    queries = [f"page.domain:{host}" for host in context.query_hosts] + [f"domain:{context.scope.domain}"]
    for query in queries:
        search_after = None
        for _page in range(10):
            if deadline.expired():
                any_failure = True
                break
            parameters = {"q": query, "size": "100"}
            if search_after:
                parameters["search_after"] = search_after
            response = context.client.fetch("https://urlscan.io/api/v1/search/?" + urlencode(parameters), headers=headers)
            result.log_request(response, query)
            data = _json(response) if response.status_code == 200 else None
            if not isinstance(data, dict):
                any_failure = True
                result.detail = f"{query}: {response.status_code} {response.error or ''}".strip()
                break
            any_success = True
            entries = data.get("results", [])
            for entry in entries:
                page = entry.get("page") or {}
                task = entry.get("task") or {}
                metadata = {"urlscan_result": entry.get("result"), "scan_time": task.get("time"), "query": query}
                for candidate in (task.get("url"), page.get("url")):
                    if candidate:
                        result.urls.append((candidate, metadata))
                if page.get("domain"):
                    result.subdomains.append((page["domain"], {"evidence": "urlscan page.domain", "query": query}))
            if not data.get("has_more") or not entries:
                break
            last_sort = entries[-1].get("sort")
            if not last_sort:
                break
            search_after = ",".join(str(value) for value in last_sort)
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- search engines
def _search_queries(context: SourceContext) -> list[str]:
    queries = [f"site:{host}" for host in context.query_hosts]
    queries.append(f"site:{context.scope.domain} -www")
    return queries


def duckduckgo(context: SourceContext) -> SourceResult:
    result = SourceResult("duckduckgo")
    deadline = Deadline(min(context.time_budget_seconds, 180))
    any_success = any_failure = False
    for query in _search_queries(context):
        form = {"q": query, "kl": "wt-wt"}
        for _page in range(5):
            if deadline.expired():
                break
            response = context.client.fetch("https://html.duckduckgo.com/html/", method="POST", data=form,
                                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                                     "Referer": "https://html.duckduckgo.com/"})
            result.log_request(response, query)
            body = response.text()
            if response.status_code in (202, 403, 429) or "anomaly-modal" in body or "challenge-form" in body:
                result.status = "blocked"
                result.detail = f"bot challenge (HTTP {response.status_code}) for {query!r}"
                return result
            if response.status_code != 200:
                any_failure = True
                break
            any_success = True
            found = 0
            for match in re.finditer(r'class="result__a"[^>]*href="([^"]+)"|href="([^"]+)"[^>]*class="result__a"', body):
                href = html.unescape(match.group(1) or match.group(2))
                if "uddg=" in href:
                    href = unquote(parse_qs(urlsplit(href).query).get("uddg", [""])[0])
                if href.startswith("http"):
                    result.urls.append((href, {"query": query, "engine_page": _page + 1}))
                    found += 1
            next_form = re.search(r'<form[^>]*action="/html/"[^>]*>(.*?)</form>', body.split('class="nav-link"', 1)[-1], re.S)
            if not found or not next_form:
                break
            form = dict(re.findall(r'name="([^"]+)"\s+value="([^"]*)"', next_form.group(1)))
            form = {key: html.unescape(value) for key, value in form.items()}
            if "q" not in form:
                break
            time.sleep(1.5)
    return _finalize(result, any_success, any_failure)


def google(context: SourceContext) -> SourceResult:
    result = SourceResult("google_search")
    deadline = Deadline(min(context.time_budget_seconds, 120))
    any_success = any_failure = False
    for query in _search_queries(context):
        for start in (0, 100, 200):
            if deadline.expired():
                break
            url = "https://www.google.com/search?" + urlencode({"q": query, "num": "100", "start": str(start),
                                                                 "hl": "en", "filter": "0", "gbv": "1"})
            response = context.client.fetch(url, headers={"Cookie": "CONSENT=YES+"})
            result.log_request(response, query)
            body = response.text()
            if (response.status_code == 429 or "/sorry/" in response.final_url or "unusual traffic" in body
                    or "/httpservice/retry/enablejs" in body or "detected unusual" in body):
                result.status = "blocked"
                result.detail = f"Google bot wall (HTTP {response.status_code}) for {query!r}"
                return result
            if response.status_code != 200:
                any_failure = True
                break
            any_success = True
            found = 0
            for match in re.finditer(r'href="/url\?q=([^"&]+)', body):
                result.urls.append((unquote(html.unescape(match.group(1))), {"query": query, "start": start}))
                found += 1
            for match in re.finditer(r'href="(https?://[^"]+)"', body):
                href = html.unescape(match.group(1))
                if "google." not in (urlsplit(href).hostname or ""):
                    result.urls.append((href, {"query": query, "start": start}))
                    found += 1
            if found < 10:
                break
            time.sleep(2)
    return _finalize(result, any_success, any_failure)


def bing(context: SourceContext) -> SourceResult:
    result = SourceResult("bing_search")
    deadline = Deadline(min(context.time_budget_seconds, 180))
    any_success = any_failure = False
    for query in _search_queries(context):
        previous_page_urls: set[str] = set()
        for first in range(1, 302, 50):
            if deadline.expired():
                break
            url = "https://www.bing.com/search?" + urlencode({"q": query, "first": str(first), "count": "50",
                                                               "setlang": "en", "cc": "us"})
            response = context.client.fetch(url, headers={"Cookie": "SRCHHPGUSR=ADLT=OFF&NRSLT=50"})
            result.log_request(response, query)
            body = response.text()
            if response.status_code != 200:
                any_failure = True
                break
            if "b_captcha" in body or "/challenge" in response.final_url:
                result.status = "blocked"
                result.detail = f"Bing challenge for {query!r}"
                return result
            any_success = True
            page_urls = set()
            for block in re.findall(r'<li class="b_algo".*?</li>', body, re.S):
                for href in re.findall(r'<h2[^>]*>\s*<a[^>]*href="([^"]+)"', block):
                    href = html.unescape(href)
                    if "bing.com/ck/a" in href:
                        encoded = parse_qs(urlsplit(href).query).get("u", [""])[0]
                        if encoded.startswith("a1"):
                            import base64
                            try:
                                href = base64.urlsafe_b64decode(encoded[2:] + "=" * (-len(encoded[2:]) % 4)).decode()
                            except (ValueError, UnicodeDecodeError):
                                continue
                    if href.startswith("http"):
                        page_urls.add(href)
                for cite in re.findall(r"<cite>(.*?)</cite>", block):
                    text = re.sub(r"<[^>]+>", "", html.unescape(cite)).replace(" › ", "/").strip()
                    if text.startswith("http"):
                        page_urls.add(text)
            new_urls = page_urls - previous_page_urls
            for href in new_urls:
                result.urls.append((href, {"query": query, "first": first}))
            if not new_urls:
                break
            previous_page_urls |= page_urls
            time.sleep(1.5)
    return _finalize(result, any_success, any_failure)


def yahoo(context: SourceContext) -> SourceResult:
    result = SourceResult("yahoo_search")
    deadline = Deadline(min(context.time_budget_seconds, 180))
    any_success = any_failure = False
    for query in _search_queries(context):
        previous: set[str] = set()
        for offset in range(1, 252, 10):
            if deadline.expired():
                break
            url = "https://search.yahoo.com/search?" + urlencode({"p": query, "b": str(offset), "n": "10"})
            response = context.client.fetch(url)
            result.log_request(response, query)
            body = response.text()
            if response.status_code != 200:
                any_failure = True
                break
            if "captcha" in response.final_url.lower() or "consent.yahoo.com" in response.final_url:
                result.status = "blocked"
                result.detail = f"Yahoo consent/captcha wall for {query!r}"
                return result
            any_success = True
            page_urls = set()
            for href in re.findall(r'<a[^>]+href="([^"]+)"', body):
                href = html.unescape(href)
                if "/RU=" in href:
                    href = unquote(href.split("/RU=", 1)[1].split("/R", 1)[0])
                host = urlsplit(href).hostname or ""
                if href.startswith("http") and "yahoo." not in host and "bing." not in host:
                    page_urls.add(href)
            new_urls = page_urls - previous
            for href in new_urls:
                result.urls.append((href, {"query": query, "offset": offset}))
            if not new_urls:
                break
            previous |= page_urls
            time.sleep(1.5)
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- code search
def github_code_search(context: SourceContext) -> SourceResult:
    result = SourceResult("github_code_search")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        result.status = "skipped"
        result.detail = "GitHub code search API requires authentication; set GITHUB_TOKEN to enable"
        return result
    deadline = Deadline(context.time_budget_seconds)
    any_success = any_failure = False
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.text-match+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    for host in context.query_hosts:
        for page in range(1, 11):
            if deadline.expired():
                break
            url = "https://api.github.com/search/code?" + urlencode({"q": f'"{host}"', "per_page": "100", "page": str(page)})
            response = context.client.fetch(url, headers=headers)
            result.log_request(response, host)
            data = _json(response) if response.status_code == 200 else None
            if not isinstance(data, dict):
                any_failure = True
                result.detail = f"{response.status_code}: {response.text()[:200]}"
                break
            any_success = True
            for item in data.get("items", []):
                repository = (item.get("repository") or {}).get("full_name")
                for text_match in item.get("text_matches", []):
                    for found in URL_IN_TEXT.findall(text_match.get("fragment", "")):
                        result.urls.append((found, {"repository": repository, "file_path": item.get("path"),
                                                    "file_url": item.get("html_url")}))
            if len(data.get("items", [])) < 100:
                break
            time.sleep(6)  # code search allows ~10 requests per minute
    return _finalize(result, any_success, any_failure)


def grep_app(context: SourceContext) -> SourceResult:
    """grep.app public code search across ~1M public GitHub repositories."""
    result = SourceResult("grep_app_code_search")
    deadline = Deadline(min(context.time_budget_seconds, 240))
    any_success = any_failure = False
    for host in context.query_hosts:
        for page in range(1, 11):
            if deadline.expired():
                break
            url = "https://grep.app/api/search?" + urlencode({"q": host, "page": str(page)})
            response = context.client.fetch(url, headers={"Accept": "application/json"})
            result.log_request(response, host)
            if "Security Checkpoint" in response.text()[:2000]:
                result.status = "blocked"
                result.detail = f"Vercel security checkpoint (HTTP {response.status_code})"
                return result
            data = _json(response) if response.status_code == 200 else None
            if not isinstance(data, dict):
                any_failure = True
                result.detail = f"{host}: {response.status_code} {response.error or ''}".strip()
                break
            any_success = True
            hits = (data.get("hits") or {}).get("hits", [])
            for hit in hits:
                snippet = html.unescape(re.sub(r"<[^>]+>", "", ((hit.get("content") or {}).get("snippet") or "")))
                for found in URL_IN_TEXT.findall(snippet):
                    result.urls.append((found, {"repository": (hit.get("repo") or {}).get("raw") or hit.get("repo"),
                                                "file_path": (hit.get("path") or {}).get("raw") or hit.get("path")}))
            total = (data.get("hits") or {}).get("total", 0)
            if not hits or page * 10 >= total:
                break
            time.sleep(1)
    return _finalize(result, any_success, any_failure)


# ---------------------------------------------------------------- subdomain sources
def certificate_transparency(context: SourceContext) -> SourceResult:
    result = SourceResult("crt_sh_certificate_transparency")
    data = None
    # crt.sh is frequently overloaded and answers 404/502/503 transiently.
    for attempt in range(4):
        response = context.client.fetch(f"https://crt.sh/?q={quote('%.' + context.scope.domain)}&output=json")
        result.log_request(response, f"attempt {attempt + 1}")
        data = _json(response) if response.status_code == 200 else None
        if isinstance(data, list):
            break
        time.sleep(15 * (attempt + 1))
    if not isinstance(data, list):
        result.detail = f"{response.status_code} {response.error or ''}".strip()
        return _finalize(result, False, True)
    seen: dict[str, dict] = {}
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and name not in seen:
                seen[name] = {"evidence": "certificate SAN/CN", "certificate_id": entry.get("id"),
                              "issuer": entry.get("issuer_name"), "not_before": entry.get("not_before")}
    result.subdomains = list(seen.items())
    return _finalize(result, True, False)


def hackertarget(context: SourceContext) -> SourceResult:
    result = SourceResult("hackertarget_hostsearch")
    response = context.client.fetch(f"https://api.hackertarget.com/hostsearch/?q={context.scope.domain}")
    result.log_request(response)
    body = response.text()
    if response.status_code != 200 or "error" in body[:100].lower() or "API count exceeded" in body:
        result.detail = body[:200] or response.error
        return _finalize(result, False, True)
    for line in body.splitlines():
        host, _separator, address = line.partition(",")
        if host.strip():
            result.subdomains.append((host.strip(), {"evidence": "DNS host search", "address": address.strip()}))
    return _finalize(result, True, False)


def anubis(context: SourceContext) -> SourceResult:
    result = SourceResult("anubis_subdomain_database")
    response = context.client.fetch(f"https://jldc.me/anubis/subdomains/{context.scope.domain}")
    result.log_request(response)
    data = _json(response) if response.status_code == 200 else None
    if not isinstance(data, list):
        result.detail = f"{response.status_code} {response.error or ''}".strip()
        return _finalize(result, False, True)
    for host in data:
        result.subdomains.append((str(host), {"evidence": "anubis subdomain database"}))
    return _finalize(result, True, False)


ALL_SOURCES = [
    wayback_machine, common_crawl, alienvault_otx, urlscan, duckduckgo, google, bing, yahoo,
    github_code_search, grep_app, certificate_transparency, hackertarget, anubis,
]
