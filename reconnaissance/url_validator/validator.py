"""Validation and classification of discovered URLs.

Responsibility: take the URLs produced by the discovery modules, send real
HTTP GET requests, and classify each URL from the observed evidence.  It
performs no discovery: it never parses responses for new links.

Inputs (read from the shared output directory, all optional):
  static_page_crawler/urls.jsonl, url_osint_gatherer/urls.jsonl,
  javascript_recursive_crawler/urls.jsonl
plus the ``--url`` itself.

Per host it first records baselines (randomized nonexistent paths and the
root document); per first path directory it lazily records a directory
baseline.  Every URL's response is compared with them, so catch-all servers,
SPA shells and soft-404 pages are recognised from evidence.

Outputs (``<output>/url_validator/``):
  validated_urls.jsonl   one evidence-backed record per validated URL
  not_validated.jsonl    URLs skipped and why (out of scope, sampling limit)
  host_baselines.jsonl   the baseline probes themselves (request + response)
  summary.json
"""

from __future__ import annotations

import secrets
import string
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..shared.http_client import FetchResult, HttpClient, utc_timestamp
from ..shared.module_runtime import ProgressThrottle, Stopwatch, configure_logging
from ..shared.output import JsonlWriter, module_output_directory, output_root, read_jsonl, write_json
from ..shared.scope import TargetScope
from ..shared.url_normalization import deduplication_key, normalize_url, path_template, query_parameter_names
from .classification import classify, looks_like_application_shell
from .response_fingerprint import Fingerprint, fingerprint

MODULE_NAME = "url_validator"
DISCOVERY_MODULES = ("static_page_crawler", "url_osint_gatherer", "javascript_recursive_crawler")
MAXIMUM_URLS_PER_TEMPLATE = 5
MAXIMUM_DIRECTORY_BASELINES_PER_HOST = 400
MAXIMUM_URLS = 12000
WORKER_COUNT = 16
BODY_SNIPPET_CHARACTERS = 600
VALIDATION_BODY_LIMIT = 2 * 1024 * 1024
RANDOM_ALPHABET = string.ascii_lowercase + string.digits


def _random_token(length: int = 14) -> str:
    return "".join(secrets.choice(RANDOM_ALPHABET) for _ in range(length))


@dataclass
class Candidate:
    url: str
    modules: set = field(default_factory=set)
    discovery_methods: dict = field(default_factory=lambda: defaultdict(set))
    source_count: int = 0
    defined_as_client_route: bool = False
    contains_template_expression: bool = False
    http_methods_seen: set = field(default_factory=set)

    @property
    def priority(self) -> tuple:
        return (-len(self.modules), -self.source_count, self.contains_template_expression, self.url)


@dataclass
class Baseline:
    probe_url: str
    result: FetchResult
    fingerprint: Fingerprint | None


class UrlValidator:
    def __init__(self, scope: TargetScope) -> None:
        self.scope = scope
        self.logger = configure_logging(MODULE_NAME)
        self.output_directory = module_output_directory(MODULE_NAME, scope.target_url)
        self.input_root = output_root(scope.target_url)
        self.client = HttpClient(timeout_seconds=20, maximum_retries=2, maximum_body_bytes=VALIDATION_BODY_LIMIT,
                                 per_host_concurrency=4, per_host_delay_seconds=0.05)
        self.host_baselines: dict[str, Baseline | None] = {}
        self.root_documents: dict[str, Fingerprint | None] = {}
        self.directory_baselines: dict[tuple[str, str], Baseline | None] = {}
        self.unreachable_hosts: dict[str, str] = {}
        self.root_is_application_shell: dict[str, bool] = {}
        self.locks: dict[object, threading.Lock] = defaultdict(threading.Lock)
        self.global_lock = threading.Lock()
        self.baseline_writer = JsonlWriter(self.output_directory / "host_baselines.jsonl")

    # ---------------------------------------------------------------- inputs
    def collect_candidates(self) -> tuple[dict[str, Candidate], Counter, list[dict]]:
        candidates: dict[str, Candidate] = {}
        input_statistics: Counter = Counter()
        rejected: list[dict] = []

        def add(raw_url: str, module: str, record: dict) -> None:
            normalized = normalize_url(raw_url)
            if not normalized:
                input_statistics[f"{module}:unparseable"] += 1
                return
            if not self.scope.url_in_scope(normalized):
                input_statistics[f"{module}:out_of_scope"] += 1
                rejected.append({"url": normalized, "module": module, "reason": "out_of_scope"})
                return
            key = deduplication_key(normalized)
            candidate = candidates.get(key)
            if candidate is None:
                candidate = candidates[key] = Candidate(url=normalized)
            candidate.modules.add(module)
            for method in (record.get("discovery_methods") or {}):
                candidate.discovery_methods[module].add(method)
            candidate.source_count += int(record.get("source_count") or len(record.get("sources") or []) or 1)
            candidate.defined_as_client_route |= bool(record.get("route_definition"))
            candidate.contains_template_expression |= bool(record.get("contains_template_expression"))
            for method in record.get("http_methods_in_code") or record.get("http_methods") or []:
                candidate.http_methods_seen.add(method)
            input_statistics[f"{module}:accepted"] += 1

        add(self.scope.target_url, "input_url", {"discovery_methods": {"input_url": 1}})
        for module in DISCOVERY_MODULES:
            path = self.input_root / module / "urls.jsonl"
            if not path.exists():
                input_statistics[f"{module}:missing_input_file"] += 1
                continue
            for record in read_jsonl(path):
                if record.get("url"):
                    add(record["url"], module, record)
        return candidates, input_statistics, rejected

    def select(self, candidates: dict[str, Candidate]) -> tuple[list[Candidate], list[dict]]:
        """Sample at most MAXIMUM_URLS_PER_TEMPLATE URLs per structural template
        (``/item/{number}?page=*``) so parameter-value variants cannot swamp
        the run; the skipped ones are written with their representative."""
        by_template: dict[str, list[Candidate]] = defaultdict(list)
        for candidate in candidates.values():
            by_template[path_template(candidate.url)].append(candidate)
        selected: list[Candidate] = []
        skipped: list[dict] = []
        for template, members in by_template.items():
            members.sort(key=lambda candidate: candidate.priority)
            selected.extend(members[:MAXIMUM_URLS_PER_TEMPLATE])
            for member in members[MAXIMUM_URLS_PER_TEMPLATE:]:
                skipped.append({"url": member.url, "reason": "path_template_sample_limit", "path_template": template,
                                "modules": sorted(member.modules)})
        selected.sort(key=lambda candidate: candidate.priority)
        if len(selected) > MAXIMUM_URLS:
            for member in selected[MAXIMUM_URLS:]:
                skipped.append({"url": member.url, "reason": "global_url_budget", "modules": sorted(member.modules)})
            selected = selected[:MAXIMUM_URLS]
        return selected, skipped

    # ---------------------------------------------------------------- baselines
    def _probe(self, url: str, kind: str, host: str, directory: str | None, token: str) -> Baseline:
        result = self.client.fetch(url, redirect_allowed=self.scope.url_in_scope)
        print_fingerprint = fingerprint(result, [token]) if result.ok else None
        self.baseline_writer.write({
            "module": MODULE_NAME, "host": host, "baseline_kind": kind, "directory": directory, "probe_url": url,
            "evidence": result.evidence(include_snippet=300, include_headers=True),
            "fingerprint": print_fingerprint.as_dict() if print_fingerprint else None,
        })
        return Baseline(url, result, print_fingerprint)

    def host_context(self, scheme: str, host: str) -> tuple[Baseline | None, Fingerprint | None]:
        key = f"{scheme}://{host}"
        with self.locks[key]:
            if key not in self.host_baselines:
                token = _random_token()
                baseline = self._probe(f"{key}/{token}", "random_nonexistent_path", host, None, token)
                if not baseline.result.ok:
                    self.unreachable_hosts[key] = baseline.result.error or "no response"
                    self.host_baselines[key] = None
                    self.root_documents[key] = None
                    self.logger.warning("host %s unreachable (%s): its URLs are recorded as unreachable", key,
                                        (baseline.result.error or "no response")[:160])
                else:
                    second_token = _random_token(10)
                    second = self._probe(f"{key}/{second_token}/{_random_token(8)}", "random_nested_nonexistent_path",
                                         host, None, second_token)
                    self.host_baselines[key] = baseline
                    if second.fingerprint and baseline.fingerprint and (
                            second.fingerprint.status_code != baseline.fingerprint.status_code):
                        self.logger.info("%s answers nested random paths differently (%s vs %s)", key,
                                         second.fingerprint.status_code, baseline.fingerprint.status_code)
                    root = self._probe(f"{key}/", "root_document", host, None, "")
                    self.root_documents[key] = root.fingerprint
                    self.root_is_application_shell[key] = looks_like_application_shell(root.result)
                    behaviour = baseline.fingerprint
                    self.logger.info("host baseline %s: random path -> HTTP %s %s; root -> HTTP %s; root is %s",
                                     key, behaviour.status_code if behaviour else "?", behaviour.mime_type if behaviour else "",
                                     root.result.status_code,
                                     "an SPA application shell" if self.root_is_application_shell[key] else "a server-rendered page")
            return self.host_baselines[key], self.root_documents.get(key)

    @staticmethod
    def path_shape(path: str) -> tuple[str, str]:
        """(parent directory, shape) where shape mimics the last segment:
        ``slash`` for ``/dir/name/``, ``extension:.svg`` for ``/dir/a.svg``,
        ``plain`` otherwise.  Servers often route these shapes differently
        (static file handler, trailing-slash rewrites), so the nonexistent-path
        baseline must have the same shape as the URL it is compared with."""
        if path.endswith("/") and path != "/":
            trimmed = path.rstrip("/")
            return trimmed.rsplit("/", 1)[0] + "/", "slash"
        parent, _separator, last = path.rpartition("/")
        extension = ""
        if "." in last.strip("."):
            extension = "." + last.rsplit(".", 1)[-1][:10]
        return (parent or "") + "/", f"extension:{extension}" if extension else "plain"

    def directory_baseline(self, scheme: str, host: str, path: str) -> Baseline | None:
        parent, shape = self.path_shape(path)
        if parent == "/" and shape == "plain":
            return None  # identical to the host baseline
        origin = f"{scheme}://{host}"
        with self.global_lock:
            directories_for_host = sum(1 for key in self.directory_baselines if key[0] == origin)
        if directories_for_host >= MAXIMUM_DIRECTORY_BASELINES_PER_HOST:
            # Bound probe volume on hosts with very many directories: fall back
            # to the first path segment with the same shape.
            first_segment = [segment for segment in parent.split("/") if segment][:1]
            parent = "/" + first_segment[0] + "/" if first_segment else "/"
        key = (origin, parent, shape)
        with self.locks[key]:
            if key not in self.directory_baselines:
                token = _random_token()
                suffix = "/" if shape == "slash" else (shape.split(":", 1)[1] if shape.startswith("extension:") else "")
                self.directory_baselines[key] = self._probe(f"{origin}{parent}{token}{suffix}",
                                                            f"random_nonexistent_path_same_shape:{shape}", host, parent, token)
            return self.directory_baselines[key]

    # ---------------------------------------------------------------- validation
    def validate(self, candidate: Candidate) -> dict:
        parts = urlsplit(candidate.url)
        host_key = f"{parts.scheme}://{parts.netloc}"
        host_baseline, root_document = self.host_context(parts.scheme, parts.netloc)
        record = {
            "module": MODULE_NAME,
            "url": candidate.url,
            "deduplication_key": deduplication_key(candidate.url),
            "host": parts.hostname,
            "query_parameters": query_parameter_names(candidate.url),
            "discovered_by": {
                "modules": sorted(candidate.modules),
                "discovery_methods": {module: sorted(methods) for module, methods in candidate.discovery_methods.items()},
                "source_count": candidate.source_count,
                "defined_as_client_route": candidate.defined_as_client_route,
                "contains_template_expression": candidate.contains_template_expression,
                "http_methods_seen_in_sources": sorted(candidate.http_methods_seen),
            },
        }
        if host_baseline is None:
            record.update({
                "accessibility": "unreachable", "resource_type": "unknown",
                "classification_evidence": [f"host unreachable during baseline probe: {self.unreachable_hosts.get(host_key)}"],
                "request": None, "response": None, "validated_at": utc_timestamp(),
            })
            return record
        result = self.client.fetch(candidate.url, redirect_allowed=self.scope.url_in_scope)
        final_parts = urlsplit(result.final_url)
        if result.redirect_chain and final_parts.netloc != parts.netloc and self.scope.url_in_scope(result.final_url):
            host_baseline, root_document = self.host_context(final_parts.scheme, final_parts.netloc)
        final_origin = f"{final_parts.scheme}://{final_parts.netloc}"
        directory = self.directory_baseline(final_parts.scheme, final_parts.netloc, final_parts.path) if result.ok else None
        url_fingerprint = fingerprint(result, [final_parts.path.rsplit("/", 1)[-1]]) if result.ok else None
        classification = classify(
            result, final_parts.path, url_fingerprint,
            directory.fingerprint if directory and directory.fingerprint else None,
            host_baseline.fingerprint if host_baseline else None,
            root_document, candidate.defined_as_client_route,
            root_is_application_shell=self.root_is_application_shell.get(final_origin, False),
        )
        evidence = result.evidence(include_snippet=BODY_SNIPPET_CHARACTERS, include_headers=True)
        record.update({
            "accessibility": classification.accessibility,
            "resource_type": classification.resource_type,
            "classification_evidence": classification.evidence,
            "request": {"method": evidence["request_method"], "url": evidence["request_url"],
                        "headers": evidence["request_headers"]},
            "response": {
                "status_code": evidence["status_code"],
                "final_url": evidence["final_url"],
                "content_type": evidence["content_type"],
                "response_size": evidence["response_size"],
                "response_size_truncated": evidence["response_size_truncated"],
                "content_length_header": result.headers.get("content-length"),
                "headers": evidence["response_headers"],
                "body_sha256": evidence["body_sha256"],
                "body_snippet": evidence["body_snippet"],
                "title": url_fingerprint.title if url_fingerprint else "",
                "elapsed_milliseconds": evidence["elapsed_milliseconds"],
                "attempts": evidence["attempts"],
                "error": evidence.get("error"),
            },
            "redirect_chain": evidence["redirect_chain"],
            "redirect_blocked_out_of_scope": evidence.get("redirect_blocked_out_of_scope"),
            "baseline_comparison": {
                "host_baseline_probe": host_baseline.probe_url if host_baseline else None,
                "same_shape_baseline_probe": directory.probe_url if directory else None,
            },
            "validated_at": utc_timestamp(),
        })
        return record

    def run(self) -> dict:
        stopwatch = Stopwatch()
        candidates, input_statistics, out_of_scope = self.collect_candidates()
        selected, skipped = self.select(candidates)
        for module in ("input_url",) + DISCOVERY_MODULES:
            if input_statistics.get(f"{module}:missing_input_file"):
                self.logger.warning("input from %s missing (%s not found)", module, self.input_root / module / "urls.jsonl")
            else:
                self.logger.info("input from %s: %s in-scope URLs, %s out of scope", module,
                                 input_statistics.get(f"{module}:accepted", 0), input_statistics.get(f"{module}:out_of_scope", 0))
        self.logger.info("validating %s URLs across %s hosts (%s unique candidates after cross-module deduplication, "
                         "%s skipped by the %s-per-path-template sampling limit)", len(selected),
                         len({urlsplit(candidate.url).netloc for candidate in selected}), len(candidates), len(skipped),
                         MAXIMUM_URLS_PER_TEMPLATE)
        progress = ProgressThrottle(5.0)
        accessibility_counts: Counter = Counter()
        type_counts: Counter = Counter()
        by_module: dict[str, Counter] = defaultdict(Counter)
        errors = 0
        with JsonlWriter(self.output_directory / "validated_urls.jsonl") as writer, \
                ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
            futures = {executor.submit(self.validate, candidate): candidate for candidate in selected}
            for index, future in enumerate(as_completed(futures), 1):
                candidate = futures[future]
                try:
                    record = future.result()
                except Exception as error:  # noqa: BLE001 - record and continue
                    self.logger.exception("validation crashed for %s", candidate.url)
                    errors += 1
                    record = {"module": MODULE_NAME, "url": candidate.url, "accessibility": "validator_error",
                              "resource_type": "unknown", "classification_evidence": [f"{error.__class__.__name__}: {error}"],
                              "validated_at": utc_timestamp()}
                writer.write(record)
                accessibility_counts[record["accessibility"]] += 1
                type_counts[record["resource_type"]] += 1
                for module in candidate.modules:
                    by_module[module][record["accessibility"]] += 1
                if progress.due() or index == len(selected):
                    elapsed = stopwatch.seconds()
                    remaining = (elapsed / index) * (len(selected) - index) if index else 0
                    self.logger.info("progress: %s/%s validated (%.0f%%), ~%.0fs remaining — %s", index, len(selected),
                                     100 * index / max(len(selected), 1), remaining,
                                     ", ".join(f"{key}={value}" for key, value in accessibility_counts.most_common()))
        self.baseline_writer.close()
        with JsonlWriter(self.output_directory / "not_validated.jsonl") as writer:
            writer.write_many(skipped)
            writer.write_many(out_of_scope)
        catch_all_hosts = {}
        for key, baseline in self.host_baselines.items():
            if baseline and baseline.fingerprint:
                catch_all_hosts[key] = {"random_path_status": baseline.fingerprint.status_code,
                                        "random_path_mime_type": baseline.fingerprint.mime_type,
                                        "root_is_application_shell": self.root_is_application_shell.get(key, False)}
        summary = {
            "module": MODULE_NAME,
            "scope": self.scope.describe(),
            "started_at": stopwatch.started_at,
            "finished_at": utc_timestamp(),
            "duration_seconds": stopwatch.seconds(),
            "http_requests_sent": self.client.request_count,
            "input_statistics": dict(input_statistics),
            "unique_candidates": len(candidates),
            "validated": len(selected),
            "skipped_by_sampling_or_budget": len(skipped),
            "rejected_out_of_scope": len(out_of_scope),
            "validator_errors": errors,
            "by_accessibility": dict(accessibility_counts.most_common()),
            "by_resource_type": dict(type_counts.most_common()),
            "accessibility_by_discovering_module": {module: dict(counts) for module, counts in by_module.items()},
            "hosts_validated": len(self.host_baselines),
            "unreachable_hosts": self.unreachable_hosts,
            "host_random_path_behaviour": catch_all_hosts,
            "limits": {"maximum_urls_per_template": MAXIMUM_URLS_PER_TEMPLATE, "maximum_urls": MAXIMUM_URLS},
            "outputs": {"validated_urls": "validated_urls.jsonl", "not_validated": "not_validated.jsonl",
                        "host_baselines": "host_baselines.jsonl"},
        }
        write_json(self.output_directory / "summary.json", summary)
        self.logger.info("resource types: %s", ", ".join(f"{key}={value}" for key, value in type_counts.most_common()))
        self.logger.info("done in %ss: %s URLs validated with %s HTTP requests (%s hosts, %s unreachable) -> %s",
                         summary["duration_seconds"], len(selected), self.client.request_count, len(self.host_baselines),
                         len(self.unreachable_hosts), self.output_directory / "validated_urls.jsonl")
        return summary
