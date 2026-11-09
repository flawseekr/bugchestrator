"""Recursive URL extraction from JavaScript resources.

Responsibility: find JavaScript resources and extract URL references from
them, recursively, until no new in-scope JavaScript is discovered.  Static
analysis only: no HTML crawling (the input page is read once, solely for its
``<script>`` references and inline scripts), no OSINT, no browser, no
validation or classification.

JavaScript discovery sources
* ``<script src>``, ``<link rel=modulepreload|preload as=script>``, import maps
  and inline scripts of the input page
* well-known bundler manifests (asset-manifest.json, .vite/manifest.json,
  ngsw.json, PWA manifests, service workers)
* JavaScript file references inside JavaScript (static/dynamic imports,
  importScripts, workers, string paths ending in .js/.mjs)
* webpack/rspack chunk maps evaluated by :mod:`webpack_chunk_reconstruction`
* source maps (``sourceMappingURL`` / ``SourceMap`` header / ``<file>.map``),
  whose original sources are analysed too
* verified AI-assisted extraction (opencode + configured model)

A candidate JavaScript URL is accepted only when the server actually returns
a non-HTML body for it (SPA catch-all HTML shells are rejected).
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..shared.http_client import FetchResult, HttpClient, utc_timestamp
from ..shared.module_runtime import Stopwatch, build_url_record, configure_logging, shorten
from ..shared.output import JsonlWriter, configured_model, module_output_directory, write_json
from ..shared.scope import TargetScope
from ..shared.url_normalization import normalize_url
from . import ai_assisted_extraction
from .javascript_lexer import TEMPLATE_PLACEHOLDER
from .reference_extraction import JAVASCRIPT_FILE, ExtractedReference, extract_references
from .webpack_chunk_reconstruction import reconstruct_chunks

MODULE_NAME = "javascript_recursive_crawler"
MAXIMUM_JAVASCRIPT_FILES = 3000
MAXIMUM_SOURCES_PER_URL = 25
MAXIMUM_SOURCE_MAP_BYTES = 60 * 1024 * 1024
MAXIMUM_AI_BATCHES = 48
AI_CONCURRENCY = 4
FETCH_WORKERS = 8
WELL_KNOWN_MANIFESTS = (
    "/asset-manifest.json", "/manifest.json", "/manifest.webmanifest", "/site.webmanifest", "/.vite/manifest.json",
    "/build-manifest.json", "/ngsw.json", "/service-worker.js", "/sw.js", "/serviceworker.js",
)
BASE_VARIABLE_ASSIGNMENT = re.compile(
    r"(?<![\w$.])(?P<variable>[A-Za-z_$][\w$]*|\"[A-Za-z_$][\w$]*\"|'[A-Za-z_$][\w$]*')\s*[:=]\s*"
    r"[\"'`](?P<value>https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\"'`\s]*)?)[\"'`]"
)
JAVASCRIPT_MIME_HINTS = ("javascript", "ecmascript", "jsx", "typescript")
NON_JAVASCRIPT_MIME_HINTS = ("text/html", "image/", "font/", "video/", "audio/", "text/css")


@dataclass
class JavascriptTask:
    url: str
    discovered_from: str | None
    discovery_method: str
    depth: int
    evidence: dict = field(default_factory=dict)
    alternative_urls: list[str] = field(default_factory=list)


@dataclass
class UrlEntry:
    sources: list[dict] = field(default_factory=list)
    source_count: int = 0
    reference_kinds: Counter = field(default_factory=Counter)
    extraction_methods: Counter = field(default_factory=Counter)
    http_methods: set = field(default_factory=set)
    route_definition: bool = False
    contains_template_expression: bool = False
    raw_values: set = field(default_factory=set)


class ScriptTagParser(HTMLParser):
    """Collects script references and inline script bodies from one page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_sources: list[tuple[str, str]] = []
        self.inline_scripts: list[str] = []
        self.import_maps: list[str] = []
        self._inline: list[str] | None = None
        self._inline_type = ""

    def handle_starttag(self, tag, attribute_list):
        attributes = {name.lower(): (value or "") for name, value in attribute_list}
        if tag == "script":
            if attributes.get("src"):
                self.script_sources.append((attributes["src"], "html_script_src"))
            else:
                self._inline = []
                self._inline_type = attributes.get("type", "").lower()
        elif tag == "link":
            rel = attributes.get("rel", "").lower()
            if "modulepreload" in rel or ("preload" in rel and attributes.get("as") == "script") or (
                    "prefetch" in rel and attributes.get("href", "").split("?")[0].endswith((".js", ".mjs"))):
                if attributes.get("href"):
                    self.script_sources.append((attributes["href"], f"html_link_{rel.replace(' ', '_')}"))

    def handle_data(self, data):
        if self._inline is not None:
            self._inline.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._inline is not None:
            body = "".join(self._inline)
            if self._inline_type == "importmap":
                self.import_maps.append(body)
            elif self._inline_type in ("", "text/javascript", "module", "application/javascript") and body.strip():
                self.inline_scripts.append(body)
            self._inline = None


class JavascriptRecursiveCrawler:
    def __init__(self, scope: TargetScope) -> None:
        self.scope = scope
        self.logger = configure_logging(MODULE_NAME)
        self.output_directory = module_output_directory(MODULE_NAME, scope.target_url)
        self.client = HttpClient(timeout_seconds=30, maximum_retries=2, maximum_body_bytes=MAXIMUM_SOURCE_MAP_BYTES,
                                 per_host_concurrency=6, per_host_delay_seconds=0.05)
        self.model = configured_model()
        self.document_base = scope.target_url
        self.queue: list[JavascriptTask] = []
        self.seen_javascript: set[str] = set()
        self.analyzed_texts: dict[str, str] = {}   # resource id -> text (for AI pass)
        self.ai_analyzed: set[str] = set()
        self.urls: dict[str, UrlEntry] = defaultdict(UrlEntry)
        self.parameters: dict[str, dict] = {}
        self.out_of_scope: Counter = Counter()
        self.statistics: Counter = Counter()
        self.files_writer = JsonlWriter(self.output_directory / "javascript_files.jsonl")
        self.ai_writer = JsonlWriter(self.output_directory / "ai_assistance.jsonl")
        self.unresolved_writer = JsonlWriter(self.output_directory / "unresolved_references.jsonl")
        self.ai_batches_used = 0

    # ---------------------------------------------------------------- recording
    def _record_url(self, normalized: str, source: dict, reference_kind: str, extraction_method: str,
                    raw_value: str, http_method: str | None = None, route_definition: bool = False,
                    template: bool = False) -> None:
        entry = self.urls[normalized]
        entry.source_count += 1
        entry.reference_kinds[reference_kind] += 1
        entry.extraction_methods[extraction_method] += 1
        entry.raw_values.add(raw_value[:300])
        if http_method:
            entry.http_methods.add(http_method)
        entry.route_definition |= route_definition
        entry.contains_template_expression |= template
        if len(entry.sources) < MAXIMUM_SOURCES_PER_URL:
            entry.sources.append(source)

    def _record_parameter(self, name: str, javascript_source: str, snippet: str) -> None:
        entry = self.parameters.setdefault(name, {"name": name, "occurrences": 0, "sources": []})
        entry["occurrences"] += 1
        if len(entry["sources"]) < 10:
            entry["sources"].append({"javascript_source": javascript_source, "snippet": snippet[:200]})

    def _resolve(self, raw_value: str, javascript_url: str | None) -> tuple[str | None, str]:
        """Resolve a reference: ES-module style ./ ../ against the JavaScript
        file, everything else against the document (the page executes it)."""
        value = raw_value.strip()
        if value.startswith(("./", "../")) and javascript_url and javascript_url.startswith("http"):
            return normalize_url(value, javascript_url), "javascript_file_url"
        return normalize_url(value, self.document_base), "document_url"

    def _enqueue_javascript(self, url: str, discovered_from: str | None, method: str, depth: int,
                            evidence: dict | None = None, alternatives: list[str] | None = None) -> None:
        if url in self.seen_javascript:
            return
        if not self.scope.url_in_scope(url):
            self.out_of_scope[urlsplit(url).hostname or "?"] += 1
            self.statistics["out_of_scope_javascript_skipped"] += 1
            return
        if len(self.seen_javascript) >= MAXIMUM_JAVASCRIPT_FILES:
            self.statistics["javascript_budget_exhausted"] += 1
            return
        self.seen_javascript.add(url)
        self.queue.append(JavascriptTask(url, discovered_from, method, depth, evidence or {}, alternatives or []))

    # ---------------------------------------------------------------- analysis
    def _process_references(self, references: list[ExtractedReference], javascript_source: str, javascript_url: str | None,
                            depth: int, extraction_method: str) -> int:
        recorded = 0
        for reference in references:
            if reference.reference_kind == "query_parameter_fragment":
                self._record_parameter(reference.raw_value, javascript_source, reference.context.get("snippet", ""))
                continue
            if reference.reference_kind == "source_map":
                continue  # handled by _process_source_map
            normalized, resolution = self._resolve(reference.raw_value, javascript_url)
            if normalized is None:
                self.statistics["unresolvable_references"] += 1
                continue
            if not self.scope.url_in_scope(normalized):
                self.out_of_scope[urlsplit(normalized).hostname or "?"] += 1
                continue
            context = {key: value for key, value in reference.context.items()}
            source = {
                "javascript_source": javascript_source,
                "extraction_method": extraction_method,
                "reference_kind": reference.reference_kind,
                "literal_kind": reference.literal_kind,
                "raw_value": reference.raw_value[:500],
                "offset": reference.offset,
                "resolved_against": resolution,
                "context": context,
            }
            self._record_url(normalized, source, reference.reference_kind, extraction_method, reference.raw_value,
                             context.get("http_method"), bool(context.get("route_definition")),
                             reference.contains_template_expression)
            recorded += 1
            path = urlsplit(normalized).path
            if JAVASCRIPT_FILE.search(path) and not reference.contains_template_expression:
                alternatives = []
                if resolution == "document_url" and javascript_url and not reference.raw_value.startswith(("/", "http", "//")):
                    alternative = normalize_url(reference.raw_value, javascript_url)
                    if alternative and alternative != normalized:
                        alternatives.append(alternative)
                self._enqueue_javascript(normalized, javascript_source, f"javascript_reference:{reference.reference_kind}",
                                         depth + 1, {"raw_value": reference.raw_value[:300],
                                                     "snippet": context.get("snippet", "")}, alternatives)
        return recorded

    def _analyze_text(self, text: str, javascript_source: str, javascript_url: str | None, depth: int,
                      extraction_method: str = "deterministic_literal_extraction") -> dict:
        references, literals = extract_references(text)
        recorded = self._process_references(references, javascript_source, javascript_url, depth, extraction_method)
        chunk_count = 0
        for reconstruction in reconstruct_chunks(text):
            if reconstruction.public_path and re.match(r"^(https?:)?//", reconstruction.public_path):
                base = normalize_url(reconstruction.public_path) or self.scope.target_origin + "/"
                prefix = ""
            else:
                base = self.scope.target_origin + "/"
                prefix = (reconstruction.public_path or "").lstrip("/") if reconstruction.public_path else ""
            for chunk_path in reconstruction.chunk_paths:
                chunk_url = normalize_url(prefix + chunk_path, base)
                if not chunk_url:
                    continue
                alternatives = []
                if javascript_url and reconstruction.public_path is None:
                    alternative = normalize_url(chunk_path, javascript_url)
                    if alternative and alternative != chunk_url:
                        alternatives.append(alternative)
                chunk_count += 1
                self._enqueue_javascript(chunk_url, javascript_source, "webpack_chunk_map_evaluation", depth + 1,
                                         {"expression": reconstruction.expression, "public_path": reconstruction.public_path,
                                          "chunk_path": chunk_path}, alternatives)
        return {"literals": len(literals), "references": len(references), "recorded_in_scope_urls": recorded,
                "reconstructed_chunks": chunk_count}

    @staticmethod
    def _is_javascript_response(result: FetchResult) -> tuple[bool, str]:
        if not result.ok:
            return False, f"fetch_error: {result.error}"
        if result.status_code != 200:
            return False, f"http_status_{result.status_code}"
        mime = result.mime_type
        head = result.body[:600].lstrip().lower()
        if head.startswith((b"<!doctype", b"<html", b"<head", b"<?xml")) or b"<html" in head[:200]:
            return False, f"html_or_xml_body ({mime or 'no content-type'})"
        if any(hint in mime for hint in JAVASCRIPT_MIME_HINTS):
            return True, f"content-type {mime}"
        if any(mime.startswith(hint) for hint in NON_JAVASCRIPT_MIME_HINTS):
            return False, f"non_javascript_content_type {mime}"
        if not result.body.strip():
            return False, "empty_body"
        return True, f"non-HTML body with content-type {mime or 'none'}"

    def _fetch_task(self, task: JavascriptTask) -> tuple[JavascriptTask, FetchResult, str]:
        result = self.client.fetch(task.url, redirect_allowed=self.scope.url_in_scope)
        accepted, reason = self._is_javascript_response(result)
        for alternative in task.alternative_urls:
            if accepted:
                break
            if alternative in self.seen_javascript:
                continue
            alternative_result = self.client.fetch(alternative, redirect_allowed=self.scope.url_in_scope)
            alternative_accepted, alternative_reason = self._is_javascript_response(alternative_result)
            if alternative_accepted:
                self.seen_javascript.add(alternative)
                task.evidence["primary_candidate_rejected"] = {"url": task.url, "reason": reason}
                task.url, result, accepted, reason = alternative, alternative_result, True, alternative_reason
        return task, result, reason

    def _handle_javascript(self, task: JavascriptTask, result: FetchResult, reason: str) -> None:
        accepted, _ = self._is_javascript_response(result)
        record = {
            "module": MODULE_NAME,
            "url": task.url,
            "discovered_from": task.discovered_from,
            "discovery_method": task.discovery_method,
            "discovery_evidence": task.evidence,
            "depth": task.depth,
            "http_evidence": result.evidence(),
            "accepted_as_javascript": accepted,
            "acceptance_reason": reason,
        }
        if not accepted:
            self.statistics["javascript_candidates_rejected"] += 1
            self.logger.info("rejected candidate %s (%s): %s", shorten(task.url), task.discovery_method, reason)
            self.files_writer.write(record)
            return
        self.statistics["javascript_files_analyzed"] += 1
        text = result.text()
        record["body_sha256"] = result.body_sha256
        if task.discovery_method in ("webpack_chunk_map_evaluation",):
            # A reconstructed chunk is a URL discovery once the server confirms it.
            self._record_url(task.url, {"javascript_source": task.discovered_from, "extraction_method": "webpack_chunk_map_evaluation",
                                        "reference_kind": "javascript_resource", "raw_value": task.evidence.get("chunk_path", ""),
                                        "context": {"expression": task.evidence.get("expression"),
                                                    "public_path": task.evidence.get("public_path")}},
                             "javascript_resource", "webpack_chunk_map_evaluation", task.evidence.get("chunk_path", ""))
        record["analysis"] = self._analyze_text(text, task.url, task.url, task.depth)
        self.analyzed_texts[task.url] = text
        record["source_map"] = self._process_source_map(task, result, text)
        self.files_writer.write(record)
        analysis, source_map = record["analysis"], record["source_map"]
        source_map_note = (f"source map found ({source_map['first_party_sources_analyzed']} first-party originals, "
                           f"{source_map['in_scope_urls_recorded']} URLs)" if source_map.get("status") == "found"
                           else "no source map")
        self.logger.info("analysed %s [%s, %.0f KB, depth %s]: %s literals, %s in-scope URLs, %s chunks reconstructed, %s",
                         shorten(task.url, 90), task.discovery_method, result.body_size / 1024, task.depth,
                         analysis["literals"], analysis["recorded_in_scope_urls"], analysis["reconstructed_chunks"],
                         source_map_note)

    # ---------------------------------------------------------------- source maps
    def _process_source_map(self, task: JavascriptTask, result: FetchResult, text: str) -> dict:
        candidates = []
        header = result.headers.get("sourcemap") or result.headers.get("x-sourcemap")
        if header:
            candidates.append((header, "sourcemap_header"))
        comment = re.findall(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)", text[-4000:])
        if comment:
            candidates.append((comment[-1], "sourcemappingurl_comment"))
        candidates.append((urlsplit(task.url).path.rsplit("/", 1)[-1] + ".map", "conventional_map_suffix"))
        tried = []
        for raw, method in candidates:
            if raw.startswith("data:"):
                return {"status": "inline_data_uri", "discovery_method": method}
            map_url = normalize_url(raw, task.url)
            if not map_url or map_url in tried:
                continue
            tried.append(map_url)
            if not self.scope.url_in_scope(map_url):
                self.out_of_scope[urlsplit(map_url).hostname or "?"] += 1
                continue
            map_result = self.client.fetch(map_url, redirect_allowed=self.scope.url_in_scope)
            if map_result.status_code != 200:
                continue
            try:
                source_map = json.loads(map_result.text())
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(source_map, dict) or "sources" not in source_map:
                continue
            self.statistics["source_maps_found"] += 1
            self._record_url(map_url, {"javascript_source": task.url, "extraction_method": method,
                                       "reference_kind": "source_map", "raw_value": raw[:300]},
                             "source_map", method, raw)
            sources = source_map.get("sources") or []
            contents = source_map.get("sourcesContent") or []
            first_party = 0
            analyzed_references = 0
            for index, source_name in enumerate(sources):
                content = contents[index] if index < len(contents) else None
                if not content or not isinstance(content, str):
                    continue
                if "node_modules/" in str(source_name) or str(source_name).startswith(("webpack/runtime", "webpack/bootstrap")):
                    continue
                first_party += 1
                identifier = f"{map_url}#{source_name}"
                analysis = self._analyze_text(content, identifier, task.url, task.depth, "source_map_original_source")
                analyzed_references += analysis["recorded_in_scope_urls"]
                self.analyzed_texts[identifier] = content
            self.statistics["source_map_original_sources_analyzed"] += first_party
            if first_party:
                # Unminified first-party originals replace the bundle for the AI
                # pass (less vendor noise, better context per token).
                self.ai_analyzed.add(task.url)
            return {"status": "found", "url": map_url, "discovery_method": method, "http_status": map_result.status_code,
                    "response_size": map_result.body_size, "sources_total": len(sources),
                    "first_party_sources_analyzed": first_party, "in_scope_urls_recorded": analyzed_references}
        return {"status": "not_available", "tried": tried}

    # ---------------------------------------------------------------- seeds
    def _seed_from_input_page(self) -> dict:
        result = self.client.fetch(self.scope.target_url, redirect_allowed=self.scope.url_in_scope)
        evidence = result.evidence()
        if result.ok and self.scope.url_in_scope(result.final_url):
            self.document_base = result.final_url
        if not result.ok or "html" not in (result.mime_type or "text/html"):
            self.logger.warning("input page %s did not return HTML (HTTP %s %s); no script references to seed from",
                                self.scope.target_url, result.status_code, result.mime_type or result.error or "")
            return {"input_page": evidence, "script_references": 0, "inline_scripts": 0}
        parser = ScriptTagParser()
        try:
            parser.feed(result.text())
            parser.close()
        except Exception:  # noqa: BLE001 - malformed markup
            pass
        for raw, method in parser.script_sources:
            normalized = normalize_url(raw, self.document_base)
            if normalized:
                if self.scope.url_in_scope(normalized):
                    self._record_url(normalized, {"javascript_source": self.document_base, "extraction_method": method,
                                                  "reference_kind": "javascript_resource", "raw_value": raw[:300]},
                                     "javascript_resource", method, raw)
                self._enqueue_javascript(normalized, self.document_base, method, 0, {"raw_value": raw[:300]})
        for index, body in enumerate(parser.inline_scripts):
            identifier = f"{self.document_base}#inline-script-{index + 1}"
            self._analyze_text(body, identifier, self.document_base, 0, "deterministic_literal_extraction")
            self.analyzed_texts[identifier] = body
            self.statistics["inline_scripts_analyzed"] += 1
        for body in parser.import_maps:
            try:
                import_map = json.loads(body)
            except json.JSONDecodeError:
                continue
            for value in self._walk_json_strings(import_map):
                normalized = normalize_url(value, self.document_base)
                if normalized and JAVASCRIPT_FILE.search(urlsplit(normalized).path):
                    self._enqueue_javascript(normalized, self.document_base, "html_import_map", 0, {"raw_value": value})
        self.logger.info("input page %s -> HTTP %s: %s script references, %s inline scripts, %s import maps",
                         self.document_base, result.status_code, len(parser.script_sources), len(parser.inline_scripts),
                         len(parser.import_maps))
        return {"input_page": evidence, "script_references": len(parser.script_sources),
                "inline_scripts": len(parser.inline_scripts), "import_maps": len(parser.import_maps)}

    @staticmethod
    def _walk_json_strings(data):
        if isinstance(data, str):
            yield data
        elif isinstance(data, dict):
            for key, value in data.items():
                yield from JavascriptRecursiveCrawler._walk_json_strings(value)
        elif isinstance(data, list):
            for value in data:
                yield from JavascriptRecursiveCrawler._walk_json_strings(value)

    def _seed_from_manifests(self) -> list[dict]:
        observations = self._probe_manifests()
        found = [item for item in observations if item.get("accepted")]
        for item in found:
            if "url_entries" in item:
                self.logger.info("well-known manifest %s: HTTP %s, %s URL entries", item["url"], item["status_code"],
                                 item["url_entries"])
            else:
                self.logger.info("well-known service worker %s: HTTP %s, queued for analysis", item["url"], item["status_code"])
        self.logger.info("probed %s well-known manifest locations, %s present", len(observations), len(found))
        return observations

    def _probe_manifests(self) -> list[dict]:
        origin = urlsplit(self.document_base)
        origin_url = f"{origin.scheme}://{origin.netloc}"
        observations = []
        for path in WELL_KNOWN_MANIFESTS:
            url = normalize_url(origin_url + path)
            result = self.client.fetch(url, redirect_allowed=self.scope.url_in_scope)
            observation = {"url": url, "status_code": result.status_code, "content_type": result.content_type,
                           "response_size": result.body_size}
            if path.endswith(".js"):
                accepted, reason = self._is_javascript_response(result)
                observation["accepted"] = accepted
                observation["reason"] = reason
                if accepted:
                    self._enqueue_javascript(url, None, "well_known_service_worker", 0)
                observations.append(observation)
                continue
            data = None
            if result.status_code == 200:
                try:
                    data = json.loads(result.text())
                except (json.JSONDecodeError, ValueError):
                    data = None
            observation["accepted"] = isinstance(data, (dict, list))
            if not observation["accepted"]:
                observation["reason"] = "not a JSON document (likely SPA fallback or absent)"
                observations.append(observation)
                continue
            self._record_url(url, {"javascript_source": None, "extraction_method": "well_known_manifest",
                                   "reference_kind": "manifest", "raw_value": path}, "manifest", "well_known_manifest", path)
            values = 0
            for value in self._walk_json_strings(data):
                if not re.match(r"^(https?:)?//|^/|^\.{0,2}/?[\w\-./]+\.\w{1,6}(\?|$)", value) or " " in value:
                    continue
                normalized = normalize_url(value, url)
                if not normalized or not self.scope.url_in_scope(normalized):
                    continue
                values += 1
                self._record_url(normalized, {"javascript_source": url, "extraction_method": "manifest_entry",
                                              "reference_kind": "manifest_entry", "raw_value": value[:300]},
                                 "manifest_entry", "manifest_entry", value)
                if JAVASCRIPT_FILE.search(urlsplit(normalized).path):
                    self._enqueue_javascript(normalized, url, "manifest_entry", 0, {"raw_value": value[:300]})
            observation["url_entries"] = values
            observations.append(observation)
        return observations

    # ---------------------------------------------------------------- AI pass
    def _ai_pass(self) -> int:
        """Run verified AI extraction over not-yet-analysed texts; returns new JS enqueued."""
        if not ai_assisted_extraction.opencode_available():
            self.statistics["ai_unavailable"] = 1
            self.logger.warning("opencode CLI not found: AI-assisted extraction skipped (deterministic analysis only)")
            return 0
        jobs = []
        pending_texts = [(identifier, text) for identifier, text in self.analyzed_texts.items() if identifier not in self.ai_analyzed]
        # Prioritise in-scope first-party code with the most request-building code.
        pending_texts.sort(key=lambda item: -len(ai_assisted_extraction.TRIGGER_PATTERN.findall(item[1][:2_000_000])))
        for identifier, text in pending_texts:
            self.ai_analyzed.add(identifier)
            for batch_index, excerpt in ai_assisted_extraction.select_excerpts(text):
                if self.ai_batches_used >= MAXIMUM_AI_BATCHES:
                    break
                self.ai_batches_used += 1
                jobs.append((identifier, batch_index, excerpt))
        if not jobs:
            return 0
        self.logger.info("AI-assisted extraction: %s excerpt batches from %s sources with %s (budget %s/%s used)",
                         len(jobs), len({job[0] for job in jobs}), self.model, self.ai_batches_used, MAXIMUM_AI_BATCHES)
        before = len(self.queue)
        with ThreadPoolExecutor(max_workers=AI_CONCURRENCY) as executor:
            futures = [executor.submit(ai_assisted_extraction.analyze_batch, identifier, batch_index, excerpt, self.model)
                       for identifier, batch_index, excerpt in jobs]
            dynamic_candidates = []
            for batch_number, future in enumerate(as_completed(futures), 1):
                call_record, candidates, dynamic = future.result()
                self.logger.info("AI batch %s/%s %s#%s: %s (%.0fs) accepted %s, rejected %s, dynamic-base %s%s",
                                 batch_number, len(futures), shorten(call_record.javascript_file, 80), call_record.batch_index,
                                 call_record.status, call_record.duration_seconds, len(call_record.accepted),
                                 len(call_record.rejected), len(call_record.dynamic_base),
                                 f" — {shorten(call_record.error, 120)}" if call_record.error else "")
                dynamic_candidates.extend((call_record.javascript_file, item) for item in dynamic)
                self.ai_writer.write(call_record.__dict__)
                self.statistics[f"ai_calls_{call_record.status}"] += 1
                self.statistics["ai_candidates_accepted"] += len(call_record.accepted)
                self.statistics["ai_candidates_rejected"] += len(call_record.rejected)
                javascript_url = call_record.javascript_file.split("#", 1)[0]
                for candidate in candidates:
                    raw = candidate.url
                    if raw.startswith(("ws://", "wss://")):
                        raw = "http" + raw[2:]
                    normalized, resolution = self._resolve(raw, javascript_url)
                    if not normalized:
                        continue
                    if not self.scope.url_in_scope(normalized):
                        self.out_of_scope[urlsplit(normalized).hostname or "?"] += 1
                        continue
                    has_placeholder = bool(re.search(r"\{[^}]*\}", candidate.url))
                    self._record_url(normalized, {
                        "javascript_source": call_record.javascript_file,
                        "extraction_method": "ai_assisted_static_analysis",
                        "reference_kind": f"ai_{candidate.kind}",
                        "raw_value": candidate.url[:500],
                        "resolved_against": resolution,
                        "context": {"evidence": candidate.evidence, "http_method": candidate.http_method,
                                    "parameters": candidate.parameters, "model": self.model,
                                    "verification": "evidence and every literal segment found verbatim in source excerpt"},
                    }, f"ai_{candidate.kind}", "ai_assisted_static_analysis", candidate.url,
                        candidate.http_method if candidate.http_method != "UNKNOWN" else None,
                        candidate.kind == "client_route", has_placeholder)
                    for name in candidate.parameters:
                        self._record_parameter(name, call_record.javascript_file, candidate.evidence)
                    if JAVASCRIPT_FILE.search(urlsplit(normalized).path) and not has_placeholder:
                        self._enqueue_javascript(normalized, call_record.javascript_file, "ai_assisted_static_analysis", 1,
                                                 {"evidence": candidate.evidence})
        self._resolve_dynamic_bases(dynamic_candidates)
        return len(self.queue) - before

    # ---------------------------------------------------------------- base variables
    def _base_variable_assignments(self) -> dict[str, list[dict]]:
        """Literal URL assignments ``name: "https://..."`` / ``name = "https://..."``
        across every analysed source, used to resolve ``{name}/path`` candidates."""
        assignments: dict[str, list[dict]] = defaultdict(list)
        for identifier, text in self.analyzed_texts.items():
            for match in BASE_VARIABLE_ASSIGNMENT.finditer(text):
                variable, value = match.group("variable").strip("\"'"), match.group("value")
                if len(assignments[variable]) >= 20 or any(item["value"] == value for item in assignments[variable]):
                    continue
                start = max(0, match.start() - 40)
                assignments[variable].append({"value": value, "javascript_source": identifier,
                                              "snippet": text[start:match.end() + 40].replace("\n", " ")[:240]})
        return assignments

    def _resolve_dynamic_bases(self, dynamic_candidates: list) -> None:
        if not dynamic_candidates:
            return
        assignments = self._base_variable_assignments()
        resolved_before = self.statistics["ai_dynamic_base_resolved"]
        unresolved_before = self.statistics["ai_dynamic_base_unresolved"]
        for javascript_file, item in dynamic_candidates:
            candidate = item.candidate
            resolved_any = False
            for assignment in assignments.get(item.base_variable, []):
                base = normalize_url(assignment["value"])
                if not base:
                    continue
                if not self.scope.url_in_scope(base):
                    self.out_of_scope[urlsplit(base).hostname or "?"] += 1
                    continue
                normalized = normalize_url(base.rstrip("/") + item.remainder)
                if not normalized:
                    continue
                resolved_any = True
                self.statistics["ai_dynamic_base_resolved"] += 1
                self._record_url(normalized, {
                    "javascript_source": javascript_file,
                    "extraction_method": "ai_assisted_static_analysis",
                    "reference_kind": f"ai_{candidate.kind}",
                    "raw_value": candidate.url[:500],
                    "resolved_against": "base_variable_literal_assignment",
                    "context": {"evidence": candidate.evidence, "http_method": candidate.http_method,
                                "parameters": candidate.parameters, "model": self.model,
                                "base_variable": item.base_variable,
                                "base_assignment": assignment,
                                "verification": "path verified verbatim in excerpt; base taken from a literal "
                                                "assignment of the same variable in analysed source"},
                }, f"ai_{candidate.kind}", "ai_assisted_static_analysis", candidate.url,
                    candidate.http_method if candidate.http_method != "UNKNOWN" else None,
                    candidate.kind == "client_route", bool(re.search(r"\{[^}]*\}", item.remainder)))
            if not resolved_any:
                self.statistics["ai_dynamic_base_unresolved"] += 1
                self.unresolved_writer.write({"module": MODULE_NAME, "javascript_source": javascript_file,
                                              "reference": candidate.url, "base_variable": item.base_variable,
                                              "path": item.remainder, "kind": candidate.kind,
                                              "http_method": candidate.http_method, "evidence": candidate.evidence,
                                              "reason": "no literal in-scope assignment of the base variable found"})
        self.logger.info("dynamic base variables: %s candidates -> %s URLs resolved from literal assignments, %s unresolved "
                         "(kept in unresolved_references.jsonl)", len(dynamic_candidates),
                         self.statistics["ai_dynamic_base_resolved"] - resolved_before,
                         self.statistics["ai_dynamic_base_unresolved"] - unresolved_before)

    # ---------------------------------------------------------------- main loop
    def _drain_queue(self) -> None:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
            while self.queue:
                wave, self.queue = self.queue, []
                self.logger.info("fetching %s JavaScript candidates (%s seen so far, %s analysed, %s in-scope URLs)",
                                 len(wave), len(self.seen_javascript), self.statistics["javascript_files_analyzed"], len(self.urls))
                for task, result, reason in executor.map(self._fetch_task, wave):
                    try:
                        self._handle_javascript(task, result, reason)
                    except Exception as error:  # noqa: BLE001 - keep crawling past one bad file
                        self.logger.exception("failed to analyse %s", task.url)
                        self.statistics["analysis_errors"] += 1
                        self.files_writer.write({"module": MODULE_NAME, "url": task.url, "analysis_error": str(error)})

    def run(self) -> dict:
        stopwatch = Stopwatch()
        self.logger.info("starting recursive JavaScript analysis of %s (scope: %s and *.%s, AI model: %s)",
                         self.scope.target_url, self.scope.domain, self.scope.domain, self.model)
        seed_page = self._seed_from_input_page()
        manifests = self._seed_from_manifests()
        rounds = 0
        while True:
            rounds += 1
            self._drain_queue()
            new_from_ai = self._ai_pass()
            self.logger.info("round %s complete: %s JavaScript files seen, %s URLs, AI enqueued %s new files",
                             rounds, len(self.seen_javascript), len(self.urls), new_from_ai)
            if not self.queue:
                self.logger.info("no new JavaScript discovered: recursion finished after %s round(s)", rounds)
                break
        return self._finish(stopwatch, seed_page, manifests, rounds)

    def _finish(self, stopwatch: Stopwatch, seed_page: dict, manifests: list[dict], rounds: int) -> dict:
        self.files_writer.close()
        self.ai_writer.close()
        self.unresolved_writer.close()
        with JsonlWriter(self.output_directory / "urls.jsonl") as writer:
            for url in sorted(self.urls):
                entry = self.urls[url]
                writer.write(build_url_record(
                    MODULE_NAME, url,
                    discovery_methods=dict(entry.extraction_methods),
                    reference_kinds=dict(entry.reference_kinds),
                    raw_values=sorted(entry.raw_values)[:20],
                    http_methods_in_code=sorted(entry.http_methods),
                    route_definition=entry.route_definition,
                    contains_template_expression=entry.contains_template_expression,
                    source_count=entry.source_count,
                    sources=entry.sources,
                ))
        with JsonlWriter(self.output_directory / "parameters.jsonl") as writer:
            for name in sorted(self.parameters):
                writer.write({"module": MODULE_NAME, **self.parameters[name]})
        method_totals: Counter = Counter()
        kind_totals: Counter = Counter()
        for entry in self.urls.values():
            method_totals.update(entry.extraction_methods.keys())
            kind_totals.update(entry.reference_kinds.keys())
        summary = {
            "module": MODULE_NAME,
            "scope": self.scope.describe(),
            "model": self.model,
            "started_at": stopwatch.started_at,
            "finished_at": utc_timestamp(),
            "duration_seconds": stopwatch.seconds(),
            "recursion_rounds": rounds,
            "http_requests_sent": self.client.request_count,
            "input_page": seed_page,
            "well_known_manifests": manifests,
            "javascript_candidates_seen": len(self.seen_javascript),
            "javascript_files_analyzed": self.statistics["javascript_files_analyzed"],
            "unique_in_scope_urls": len(self.urls),
            "route_definitions": sum(1 for entry in self.urls.values() if entry.route_definition),
            "urls_with_template_expressions": sum(1 for entry in self.urls.values() if entry.contains_template_expression),
            "urls_with_query_parameters": sum(1 for url in self.urls if "?" in url),
            "unique_parameter_names": len(self.parameters),
            "urls_by_extraction_method": dict(method_totals.most_common()),
            "urls_by_reference_kind": dict(kind_totals.most_common()),
            "urls_by_host": dict(Counter(urlsplit(url).hostname for url in self.urls).most_common(40)),
            "ai_batches_used": self.ai_batches_used,
            "ai_batch_budget": MAXIMUM_AI_BATCHES,
            "out_of_scope_references_by_host": dict(self.out_of_scope.most_common(40)),
            "statistics": dict(self.statistics),
            "outputs": {"urls": "urls.jsonl", "javascript_files": "javascript_files.jsonl",
                        "parameters": "parameters.jsonl", "ai_assistance": "ai_assistance.jsonl",
                        "unresolved_references": "unresolved_references.jsonl"},
        }
        write_json(self.output_directory / "summary.json", summary)
        self.logger.info("URLs by extraction method: %s", ", ".join(f"{key}={value}" for key, value in method_totals.most_common()))
        self.logger.info("done in %ss: %s JavaScript files analysed (%s rejected), %s source maps, %s unique in-scope URLs, "
                         "%s route definitions, %s parameter names -> %s", summary["duration_seconds"],
                         summary["javascript_files_analyzed"], self.statistics["javascript_candidates_rejected"],
                         self.statistics["source_maps_found"], len(self.urls), summary["route_definitions"],
                         len(self.parameters), self.output_directory / "urls.jsonl")
        return summary
