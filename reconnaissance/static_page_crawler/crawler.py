"""Recursive static HTML crawler.

Responsibility: discover URLs by fetching static HTML pages (plus robots.txt
and XML sitemaps, which are static site documents) and extracting references
from HTML attributes.  It never parses JavaScript, never renders a DOM, never
queries OSINT sources and never classifies or validates URLs.

Recursion policy
* only pages on the *crawl hosts* are fetched: the target host and any
  in-scope host the target URL redirects to (e.g. ``ovo.id`` -> ``www.ovo.id``)
* every in-scope reference (any ``*.<registrable domain>`` host) is recorded
* out-of-scope references are counted but never requested or recorded as URLs
* static assets (images, scripts, fonts, archives...) are recorded but not
  fetched, because they cannot contain HTML links
* traps are bounded by a maximum depth, a maximum page count and a per
  path-template budget (``/news?page={n}`` cannot consume the crawl)
"""

from __future__ import annotations

import gzip
import re
import threading
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit, urlunsplit

from ..shared.http_client import FetchResult, HttpClient, utc_timestamp
from ..shared.module_runtime import ProgressThrottle, Stopwatch, build_url_record, configure_logging, shorten
from ..shared.output import JsonlWriter, module_output_directory, write_json
from ..shared.scope import TargetScope
from ..shared.url_normalization import normalize_url, path_template
from .html_link_extraction import (
    ExtractedReference,
    extract_from_html,
    extract_from_robots,
    extract_from_sitemap,
)

MODULE_NAME = "static_page_crawler"
MAXIMUM_DEPTH = 12
MAXIMUM_PAGES = 2500
MAXIMUM_PAGES_PER_TEMPLATE = 60
# Sitemaps are finite, publisher-declared lists, so their entries bypass the
# per-template trap budget (they still count toward MAXIMUM_PAGES).
TEMPLATE_BUDGET_EXEMPT_METHODS = {"sitemap_entry", "sitemap_text_entry", "sitemap_alternate"}
MAXIMUM_SITEMAP_DOCUMENTS = 60
MAXIMUM_SOURCES_PER_URL = 25
WORKER_COUNT = 8
NON_HTML_EXTENSIONS = re.compile(
    r"\.(?:js|mjs|cjs|map|css|json|xml|txt|csv|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|"
    r"woff2?|ttf|otf|eot|mp4|webm|ogg|ogv|mp3|wav|m4a|mov|avi|flv|pdf|docx?|xlsx?|pptx?|"
    r"zip|gz|tgz|rar|7z|tar|bz2|exe|dmg|apk|ipa|msi|bin|iso|swf|wasm)$",
    re.IGNORECASE,
)
ASSET_DISCOVERY_METHODS = {
    "script_source_reference", "image_source", "image_srcset", "media_source", "image_input_source",
    "link_stylesheet", "link_icon", "link_shortcut_icon", "link_apple_touch_icon", "link_preload",
    "link_modulepreload", "link_prefetch", "link_preconnect", "link_dns_prefetch", "link_mask_icon",
    "meta_og_image", "meta_twitter_image", "meta_msapplication_tileimage",
}


@dataclass
class CrawlTask:
    url: str
    depth: int
    source_url: str | None
    discovery_method: str
    kind: str = "page"  # page | robots | sitemap


@dataclass
class DiscoveredUrl:
    url: str
    first_depth: int
    sources: list[dict] = field(default_factory=list)
    source_count: int = 0
    discovery_methods: Counter = field(default_factory=Counter)
    http_methods: set = field(default_factory=set)
    form_fields: dict = field(default_factory=dict)
    crawl_status: str = "not_fetched"
    skip_reason: str | None = None
    http_evidence: dict | None = None


class StaticPageCrawler:
    def __init__(self, scope: TargetScope) -> None:
        self.scope = scope
        self.logger = configure_logging(MODULE_NAME)
        self.output_directory = module_output_directory(MODULE_NAME, scope.target_url)
        self.client = HttpClient(timeout_seconds=20, maximum_retries=2, maximum_body_bytes=8 * 1024 * 1024,
                                 per_host_concurrency=WORKER_COUNT, per_host_delay_seconds=0.05)
        self.crawl_hosts = {scope.target_host}
        self.discovered: dict[str, DiscoveredUrl] = {}
        self.enqueued: set[str] = set()
        self.template_counts: Counter = Counter()
        self.out_of_scope_references: Counter = Counter()
        self.statistics: Counter = Counter()
        self.sitemap_documents = 0
        self.lock = threading.Lock()
        self.pages_writer = JsonlWriter(self.output_directory / "pages.jsonl")
        self.errors_writer = JsonlWriter(self.output_directory / "errors.jsonl")

    # ------------------------------------------------------------------ recording
    def _record_reference(self, normalized: str, depth: int, source_url: str | None,
                          reference: ExtractedReference | None, method: str, http_method: str = "GET",
                          form_fields: dict | None = None) -> DiscoveredUrl:
        entry = self.discovered.get(normalized)
        if entry is None:
            entry = DiscoveredUrl(url=normalized, first_depth=depth)
            self.discovered[normalized] = entry
        entry.source_count += 1
        entry.discovery_methods[method] += 1
        entry.http_methods.add(http_method)
        if form_fields:
            entry.form_fields.update(form_fields)
        if len(entry.sources) < MAXIMUM_SOURCES_PER_URL:
            source = {"source_url": source_url, "discovery_method": method}
            if reference is not None:
                source.update({"element": reference.element, "attribute": reference.attribute,
                               "raw_reference": reference.raw_reference[:500]})
                context = {key: value for key, value in reference.context.items() if value}
                if context:
                    source["context"] = context
            if http_method != "GET":
                source["http_method"] = http_method
            if source not in entry.sources:
                entry.sources.append(source)
        return entry

    def _should_fetch(self, normalized: str, method: str) -> str | None:
        """Return None when the URL should be fetched, else the skip reason."""
        if urlsplit(normalized).hostname not in self.crawl_hosts:
            return "not_a_crawl_host"
        if method in ASSET_DISCOVERY_METHODS:
            return "static_asset_reference"
        if NON_HTML_EXTENSIONS.search(urlsplit(normalized).path):
            return "non_html_extension"
        return None

    def _enqueue(self, frontier: list[CrawlTask], normalized: str, depth: int, source_url: str | None,
                 method: str, kind: str = "page") -> None:
        if normalized in self.enqueued:
            return
        entry = self.discovered.get(normalized)
        if kind == "page":
            skip_reason = self._should_fetch(normalized, method)
            if skip_reason is None and depth > MAXIMUM_DEPTH:
                skip_reason = "maximum_depth_reached"
            if skip_reason is None and method not in TEMPLATE_BUDGET_EXEMPT_METHODS:
                template = path_template(normalized)
                if self.template_counts[template] >= MAXIMUM_PAGES_PER_TEMPLATE:
                    skip_reason = "path_template_budget_exhausted"
                else:
                    self.template_counts[template] += 1
            if skip_reason is None and len(self.enqueued) >= MAXIMUM_PAGES:
                skip_reason = "maximum_page_budget_reached"
            if skip_reason is not None:
                if entry is not None and entry.skip_reason is None:
                    entry.skip_reason = skip_reason
                self.statistics[f"skipped_{skip_reason}"] += 1
                return
        self.enqueued.add(normalized)
        frontier.append(CrawlTask(normalized, depth, source_url, method, kind))

    def _process_reference(self, frontier: list[CrawlTask], reference: ExtractedReference, base_url: str,
                           depth: int, source_url: str) -> None:
        normalized = normalize_url(reference.raw_reference, base_url)
        if normalized is None:
            self.statistics["non_navigable_references"] += 1
            return
        if not self.scope.url_in_scope(normalized):
            self.out_of_scope_references[urlsplit(normalized).hostname or "?"] += 1
            return
        self._record_reference(normalized, depth + 1, source_url, reference, reference.discovery_method)
        kind = "page"
        if reference.discovery_method in ("robots_sitemap", "sitemap_index_entry"):
            kind = "sitemap"
        self._enqueue(frontier, normalized, depth + 1, source_url, reference.discovery_method, kind)

    # ------------------------------------------------------------------ fetching
    def _fetch(self, task: CrawlTask) -> tuple[CrawlTask, FetchResult]:
        return task, self.client.fetch(task.url, redirect_allowed=self.scope.url_in_scope)

    @staticmethod
    def _looks_like_html(result: FetchResult) -> bool:
        if result.mime_type in ("text/html", "application/xhtml+xml"):
            return True
        if not result.mime_type:
            head = result.body[:512].lstrip().lower()
            return head.startswith((b"<!doctype html", b"<html"))
        return False

    def _handle_result(self, frontier: list[CrawlTask], task: CrawlTask, result: FetchResult) -> None:
        evidence = result.evidence()
        evidence["source_url"] = task.source_url
        evidence["discovery_method"] = task.discovery_method
        entry = self.discovered.get(task.url)
        if entry is None:  # seeds
            entry = self._record_reference(task.url, task.depth, task.source_url, None, task.discovery_method)
        entry.http_evidence = {key: evidence[key] for key in ("request_method", "request_url", "final_url",
                                                              "status_code", "content_type", "response_size",
                                                              "fetched_at") if key in evidence}
        if not result.ok:
            entry.crawl_status = "fetch_error"
            self.statistics["fetch_errors"] += 1
            self.logger.warning("fetch failed for %s after %s attempt(s): %s", shorten(task.url), result.attempts,
                                shorten(result.error or "", 160))
            self.errors_writer.write({"url": task.url, "source_url": task.source_url, "error": result.error,
                                      "attempts": result.attempts, "at": utc_timestamp()})
            return

        # Redirect targets are discoveries in their own right.
        final_url = result.final_url
        for hop in result.redirect_chain:
            target = normalize_url(hop.location or "", hop.url)
            if target and self.scope.url_in_scope(target):
                self._record_reference(target, task.depth, hop.url, None, f"http_redirect_{hop.status_code}")
        if result.redirect_blocked_url:
            self.out_of_scope_references[urlsplit(result.redirect_blocked_url).hostname or "?"] += 1
        if final_url != task.url:
            target_entry = self.discovered.get(final_url)
            if target_entry is not None and target_entry.http_evidence is None:
                target_entry.crawl_status = "fetched_as_redirect_target"
                target_entry.http_evidence = dict(entry.http_evidence)
        if final_url != task.url and final_url in self.enqueued and task.kind == "page":
            entry.crawl_status = "redirected_to_known_url"
            self._write_page(task, result, evidence, title=None, reference_count=0, form_count=0, parsed=False)
            return
        self.enqueued.add(final_url)
        if task.depth == 0 and self.scope.url_in_scope(final_url):
            self.crawl_hosts.add(urlsplit(final_url).hostname)

        body_text = result.text()
        if task.kind == "robots":
            entry.crawl_status = "fetched_robots"
            references = []
            if result.status_code == 200 and "html" not in result.mime_type:
                references = extract_from_robots(body_text)
                for reference in references:
                    self._process_reference(frontier, reference, final_url, task.depth, final_url)
            if references:
                self.logger.info("robots.txt %s: %s references (sitemaps, allow/disallow paths)", task.url, len(references))
            else:
                self.logger.info("robots.txt %s: HTTP %s %s, nothing to extract", task.url, result.status_code,
                                 result.mime_type or "")
            self._write_page(task, result, evidence, None, len(references), 0, parsed=bool(references) or "html" not in result.mime_type)
            return
        if task.kind == "sitemap":
            entry.crawl_status = "fetched_sitemap"
            if result.status_code == 200 and self.sitemap_documents < MAXIMUM_SITEMAP_DOCUMENTS:
                self.sitemap_documents += 1
                raw = result.body
                if raw[:2] == b"\x1f\x8b":
                    try:
                        raw = gzip.decompress(raw)
                    except OSError:
                        raw = b""
                text = raw.decode("utf-8", errors="replace")
                if "<html" not in text[:1000].lower():
                    references, _is_index = extract_from_sitemap(text)
                    self.logger.info("sitemap%s %s: %s entries", " index" if _is_index else "", shorten(task.url), len(references))
                    for reference in references:
                        self._process_reference(frontier, reference, final_url, task.depth, final_url)
                    self._write_page(task, result, evidence, None, len(references), 0, parsed=True)
                    return
            self.logger.info("sitemap %s: not a sitemap (HTTP %s, %s)", shorten(task.url), result.status_code,
                             result.mime_type or "no content-type")
            self._write_page(task, result, evidence, None, 0, 0, parsed=False)
            return

        if not self._looks_like_html(result):
            entry.crawl_status = "fetched_non_html"
            self._write_page(task, result, evidence, None, 0, 0, parsed=False)
            return

        parser = extract_from_html(body_text)
        base_url = normalize_url(parser.base_href, final_url) if parser.base_href else final_url
        base_url = base_url or final_url
        for reference in parser.references:
            self._process_reference(frontier, reference, base_url, task.depth, final_url)
        for form in parser.forms:
            self._process_form(frontier, form, base_url, task.depth, final_url)
        entry.crawl_status = "crawled"
        self.statistics["html_pages_parsed"] += 1
        self._write_page(task, result, evidence, parser.title, len(parser.references), len(parser.forms), parsed=True,
                         meta_robots=parser.meta_robots)

    def _process_form(self, frontier, form, base_url: str, depth: int, source_url: str) -> None:
        action = normalize_url(form.action or base_url, base_url)
        if action is None:
            return
        if not self.scope.url_in_scope(action):
            self.out_of_scope_references[urlsplit(action).hostname or "?"] += 1
            return
        fields = {"method": form.method, "enctype": form.enctype, "field_names": form.field_names,
                  "hidden_fields": form.hidden_fields}
        reference = ExtractedReference(form.action or "(empty action: submits to page)", "form_action", "form", "action",
                                       {"form_method": form.method, "field_names": form.field_names})
        self._record_reference(action, depth + 1, source_url, reference, "form_action", form.method,
                               form_fields={"form": fields})
        if form.method == "GET" and form.field_names:
            # The URL a GET submission produces, using the form's own field names
            # with empty values: the parameters are observed, never invented.
            parts = urlsplit(action)
            existing = parts.query
            added = urlencode([(name, "") for name in form.field_names])
            query = f"{existing}&{added}" if existing else added
            submission = normalize_url(urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
            if submission:
                self._record_reference(submission, depth + 1, source_url,
                                       ExtractedReference(form.action or "", "form_get_submission", "form", "action",
                                                          {"field_names": form.field_names}),
                                       "form_get_submission", "GET")
        if form.method == "GET":
            self._enqueue(frontier, action, depth + 1, source_url, "form_action")

    def _write_page(self, task: CrawlTask, result: FetchResult, evidence: dict, title, reference_count: int,
                    form_count: int, parsed: bool, meta_robots: str | None = None) -> None:
        record = {
            "module": MODULE_NAME,
            "document_kind": task.kind,
            "depth": task.depth,
            **evidence,
            "body_sha256": result.body_sha256,
            "parsed_as": ("html" if task.kind == "page" else task.kind) if parsed else None,
            "title": title,
            "references_extracted": reference_count,
            "forms_extracted": form_count,
        }
        if meta_robots:
            record["meta_robots"] = meta_robots
        self.pages_writer.write(record)
        self.statistics["documents_fetched"] += 1
        self.statistics[f"status_{result.status_code}"] += 1

    # ------------------------------------------------------------------ main loop
    def run(self) -> dict:
        stopwatch = Stopwatch()
        self.logger.info("starting static HTML crawl of %s (scope: %s and *.%s)", self.scope.target_url,
                         self.scope.domain, self.scope.domain)
        frontier: list[CrawlTask] = []
        self._record_reference(self.scope.target_url, 0, None, None, "input_url")
        self._enqueue(frontier, self.scope.target_url, 0, None, "input_url")
        origin = self.scope.target_origin
        for path, kind in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"), ("/sitemap_index.xml", "sitemap")):
            seed = normalize_url(origin + path)
            self._record_reference(seed, 0, None, None, f"well_known_{kind}_location")
            self._enqueue(frontier, seed, 0, None, f"well_known_{kind}_location", kind)

        # Resolve the input URL first so redirect hosts (ovo.id -> www.ovo.id)
        # become crawl hosts before anything else is scheduled.
        first_task = frontier.pop(0)
        first_result = self._fetch(first_task)
        self._handle_result(frontier, *first_result)
        response = first_result[1]
        self.logger.info("input URL %s -> HTTP %s %s (%s bytes)%s", self.scope.target_url, response.status_code,
                         response.mime_type or response.error or "", response.body_size,
                         f", redirected to {response.final_url}" if response.redirect_chain else "")
        self.logger.info("crawl hosts: %s; recording every reference in %s and *.%s",
                         ", ".join(sorted(self.crawl_hosts)), self.scope.domain, self.scope.domain)
        if self.scope.target_host not in self.crawl_hosts or len(self.crawl_hosts) > 1:
            for host in list(self.crawl_hosts):
                for path, kind in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap")):
                    seed = normalize_url(f"{urlsplit(self.scope.target_url).scheme}://{host}{path}")
                    if seed and seed not in self.enqueued:
                        self._record_reference(seed, 0, None, None, f"well_known_{kind}_location")
                        self._enqueue(frontier, seed, 0, None, f"well_known_{kind}_location", kind)

        progress = ProgressThrottle(5.0)
        self.logger.info("crawling with %s workers (limits: depth %s, %s pages, %s pages per path template)",
                         WORKER_COUNT, MAXIMUM_DEPTH, MAXIMUM_PAGES, MAXIMUM_PAGES_PER_TEMPLATE)
        with ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
            pending: set[Future] = set()
            while frontier or pending:
                while frontier and len(pending) < WORKER_COUNT * 2:
                    frontier.sort(key=lambda task: task.depth)
                    pending.add(executor.submit(self._fetch, frontier.pop(0)))
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        task, result = future.result()
                        self._handle_result(frontier, task, result)
                    except Exception as error:  # noqa: BLE001 - never let one page kill the crawl
                        self.logger.exception("unexpected error while processing a page")
                        self.errors_writer.write({"error": f"{error.__class__.__name__}: {error}", "at": utc_timestamp()})
                if progress.due():
                    self.logger.info("progress: %s documents fetched (%s HTML parsed), %s in flight, %s queued, "
                                     "%s unique URLs discovered, %s errors",
                                     self.statistics["documents_fetched"], self.statistics["html_pages_parsed"],
                                     len(pending), len(frontier), len(self.discovered), self.statistics["fetch_errors"])

        return self._finish(stopwatch)

    def _finish(self, stopwatch: Stopwatch) -> dict:
        self.pages_writer.close()
        self.errors_writer.close()
        with JsonlWriter(self.output_directory / "urls.jsonl") as writer:
            for url in sorted(self.discovered):
                entry = self.discovered[url]
                record = build_url_record(
                    MODULE_NAME, url,
                    discovery_methods=dict(entry.discovery_methods),
                    http_methods=sorted(entry.http_methods),
                    source_count=entry.source_count,
                    sources=entry.sources,
                    first_seen_depth=entry.first_depth,
                    crawl_status=entry.crawl_status,
                    on_crawl_host=urlsplit(url).hostname in self.crawl_hosts,
                )
                if entry.crawl_status == "not_fetched":
                    record["not_fetched_reason"] = entry.skip_reason or (
                        "not_a_crawl_host" if urlsplit(url).hostname not in self.crawl_hosts else "static_asset_reference")
                if entry.form_fields:
                    record["form"] = entry.form_fields.get("form")
                if entry.http_evidence:
                    record["http_evidence"] = entry.http_evidence
                writer.write(record)
        method_totals: Counter = Counter()
        for entry in self.discovered.values():
            method_totals.update(entry.discovery_methods.keys())
        hosts = Counter(urlsplit(url).hostname for url in self.discovered)
        summary = {
            "module": MODULE_NAME,
            "scope": self.scope.describe(),
            "crawl_hosts": sorted(self.crawl_hosts),
            "started_at": stopwatch.started_at,
            "finished_at": utc_timestamp(),
            "duration_seconds": stopwatch.seconds(),
            "http_requests_sent": self.client.request_count,
            "documents_fetched": self.statistics["documents_fetched"],
            "html_pages_parsed": self.statistics["html_pages_parsed"],
            "unique_in_scope_urls": len(self.discovered),
            "urls_by_host": dict(hosts.most_common()),
            "urls_with_query_parameters": sum(1 for url in self.discovered if "?" in url),
            "urls_by_discovery_method": dict(method_totals.most_common()),
            "out_of_scope_references_by_host": dict(self.out_of_scope_references.most_common(50)),
            "statistics": dict(self.statistics),
            "limits": {"maximum_depth": MAXIMUM_DEPTH, "maximum_pages": MAXIMUM_PAGES,
                       "maximum_pages_per_template": MAXIMUM_PAGES_PER_TEMPLATE},
            "outputs": {"urls": "urls.jsonl", "pages": "pages.jsonl", "errors": "errors.jsonl"},
        }
        write_json(self.output_directory / "summary.json", summary)
        skipped = {key.removeprefix("skipped_"): value for key, value in self.statistics.items() if key.startswith("skipped_")}
        self.logger.info("references not fetched: %s", ", ".join(f"{key}={value}" for key, value in skipped.items()) or "none")
        self.logger.info("top discovery methods: %s", ", ".join(f"{key}={value}" for key, value in method_totals.most_common(6)))
        self.logger.info("out-of-scope references ignored: %s across %s hosts", sum(self.out_of_scope_references.values()),
                         len(self.out_of_scope_references))
        self.logger.info("done in %ss: %s documents fetched (%s HTML parsed), %s unique in-scope URLs (%s with query "
                         "parameters) -> %s", summary["duration_seconds"], summary["documents_fetched"],
                         summary["html_pages_parsed"], summary["unique_in_scope_urls"],
                         summary["urls_with_query_parameters"], self.output_directory / "urls.jsonl")
        return summary
