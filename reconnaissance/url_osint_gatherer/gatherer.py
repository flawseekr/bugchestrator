"""External URL intelligence gathering.

Responsibility: collect URLs (and subdomains) associated with the target from
third-party OSINT sources.  It never requests the target itself, never crawls,
never validates or classifies URLs.

Outputs (in ``<output>/url_osint_gatherer/``)
* ``urls.jsonl``        one record per unique in-scope URL with every source
                        that reported it and the source metadata
* ``subdomains.jsonl``  one record per in-scope hostname with its sources
* ``sources.jsonl``     one record per source: status, detail and every
                        request made (URL, status, size) as collection evidence
* ``summary.json``
"""

from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..shared.http_client import HttpClient, utc_timestamp
from ..shared.module_runtime import Stopwatch, build_url_record, configure_logging
from ..shared.output import JsonlWriter, module_output_directory, write_json
from ..shared.scope import TargetScope
from ..shared.url_normalization import host_of, normalize_url, query_parameters
from .sources import ALL_SOURCES, SourceContext, SourceResult

MODULE_NAME = "url_osint_gatherer"
MAXIMUM_SOURCE_ENTRIES_PER_URL = 10


def query_hosts_for(scope: TargetScope) -> list[str]:
    """Hosts whose URL history is collected.  ``www.example.com`` and the bare
    ``example.com`` are the same site in practice, so both are queried."""
    hosts = [scope.target_host]
    if scope.target_host == f"www.{scope.domain}":
        hosts.append(scope.domain)
    elif scope.target_host == scope.domain:
        hosts.append(f"www.{scope.domain}")
    return hosts


class UrlOsintGatherer:
    def __init__(self, scope: TargetScope) -> None:
        self.scope = scope
        self.logger = configure_logging(MODULE_NAME)
        self.output_directory = module_output_directory(MODULE_NAME, scope.target_url)
        # Third-party APIs, not the target: modest per-host concurrency.
        self.client = HttpClient(timeout_seconds=60, maximum_retries=3, maximum_body_bytes=200 * 1024 * 1024,
                                 per_host_concurrency=2, per_host_delay_seconds=1.0)

    def run(self) -> dict:
        stopwatch = Stopwatch()
        context = SourceContext(self.scope, self.client, query_hosts_for(self.scope))
        self.logger.info("collecting external URL intelligence for %s; subdomains of %s (the target itself is never contacted)",
                         ", ".join(context.query_hosts), self.scope.domain)
        self.logger.info("querying %s sources in parallel: %s", len(ALL_SOURCES),
                         ", ".join(source.__name__ for source in ALL_SOURCES))
        source_results: list[SourceResult] = []
        with ThreadPoolExecutor(max_workers=len(ALL_SOURCES)) as executor:
            futures = {executor.submit(source, context): source.__name__ for source in ALL_SOURCES}
            completed = 0
            for future in as_completed(futures):
                name = futures[future]
                try:
                    source_result = future.result()
                except Exception as error:  # noqa: BLE001 - a broken source must not kill the run
                    self.logger.exception("source %s crashed", name)
                    source_result = SourceResult(name, status="failed", detail=f"{error.__class__.__name__}: {error}")
                completed += 1
                level = self.logger.info if source_result.status in ("ok", "partial", "empty", "skipped") else self.logger.warning
                level("source %s/%s finished: %s -> %s, %s URLs, %s subdomains, %s requests%s", completed, len(futures),
                      source_result.source, source_result.status, len(source_result.urls), len(source_result.subdomains),
                      len(source_result.requests), f" ({source_result.detail[:160]})" if source_result.detail else "")
                source_results.append(source_result)
        return self._merge_and_write(source_results, stopwatch)

    def _merge_and_write(self, source_results: list[SourceResult], stopwatch: Stopwatch) -> dict:
        collected_at = utc_timestamp()
        urls: dict[str, dict] = {}
        subdomains: dict[str, dict] = {}
        source_statistics = []
        out_of_scope = Counter()
        unparseable = Counter()
        for source_result in sorted(source_results, key=lambda item: item.source):
            in_scope_urls = set()
            for raw_url, metadata in source_result.urls:
                normalized = normalize_url(raw_url)
                if normalized is None:
                    unparseable[source_result.source] += 1
                    continue
                if not self.scope.url_in_scope(normalized):
                    out_of_scope[source_result.source] += 1
                    continue
                in_scope_urls.add(normalized)
                entry = urls.setdefault(normalized, {"sources": defaultdict(list), "parameter_values": defaultdict(set)})
                entries = entry["sources"][source_result.source]
                if len(entries) < MAXIMUM_SOURCE_ENTRIES_PER_URL:
                    entries.append({"raw_url": raw_url[:2000], **{k: v for k, v in metadata.items() if v not in (None, "")}})
                for name, values in query_parameters(normalized).items():
                    for value in values[:5]:
                        if len(entry["parameter_values"][name]) < 10:
                            entry["parameter_values"][name].add(value[:200])
            in_scope_hosts = set()
            for raw_host, metadata in source_result.subdomains:
                host = raw_host.strip().lower().rstrip(".").lstrip("*.")
                if not host or not self.scope.host_in_scope(host) or " " in host:
                    continue
                in_scope_hosts.add(host)
                entry = subdomains.setdefault(host, defaultdict(list))
                if len(entry[source_result.source]) < 3:
                    entry[source_result.source].append({k: v for k, v in metadata.items() if v not in (None, "")})
            source_statistics.append({
                "source": source_result.source,
                "status": source_result.status,
                "detail": source_result.detail,
                "started_at": source_result.started_at,
                "raw_url_count": len(source_result.urls),
                "unique_in_scope_url_count": len(in_scope_urls),
                "raw_subdomain_count": len(source_result.subdomains),
                "unique_in_scope_subdomain_count": len(in_scope_hosts),
                "request_count": len(source_result.requests),
                "requests": source_result.requests,
            })
        # URL hosts are subdomain evidence as well.
        for url in urls:
            host = host_of(url)
            entry = subdomains.setdefault(host, defaultdict(list))
            if not entry.get("url_host_of_collected_urls"):
                entry["url_host_of_collected_urls"].append({"example_url": url})

        with JsonlWriter(self.output_directory / "sources.jsonl") as writer:
            writer.write_many(source_statistics)
        with JsonlWriter(self.output_directory / "urls.jsonl") as writer:
            for url in sorted(urls):
                entry = urls[url]
                writer.write(build_url_record(
                    MODULE_NAME, url,
                    discovery_methods={name: len(items) for name, items in entry["sources"].items()},
                    source_names=sorted(entry["sources"]),
                    sources=[{"source": name, "observations": items} for name, items in sorted(entry["sources"].items())],
                    observed_parameter_values={name: sorted(values) for name, values in entry["parameter_values"].items()},
                    discovered_at=collected_at,
                ))
        with JsonlWriter(self.output_directory / "subdomains.jsonl") as writer:
            for host in sorted(subdomains):
                writer.write({"module": MODULE_NAME, "host": host, "source_names": sorted(subdomains[host]),
                              "sources": {name: items for name, items in sorted(subdomains[host].items())},
                              "discovered_at": collected_at})

        by_source = Counter()
        for entry in urls.values():
            by_source.update(entry["sources"].keys())
        summary = {
            "module": MODULE_NAME,
            "scope": self.scope.describe(),
            "query_hosts": query_hosts_for(self.scope),
            "started_at": stopwatch.started_at,
            "finished_at": utc_timestamp(),
            "duration_seconds": stopwatch.seconds(),
            "third_party_requests_sent": self.client.request_count,
            "target_requests_sent": 0,
            "unique_in_scope_urls": len(urls),
            "urls_with_query_parameters": sum(1 for url in urls if "?" in url),
            "unique_in_scope_subdomains": len(subdomains),
            "urls_by_host": dict(Counter(host_of(url) for url in urls).most_common(30)),
            "unique_urls_by_source": dict(by_source.most_common()),
            "source_status": {item["source"]: item["status"] for item in source_statistics},
            "source_detail": {item["source"]: item["detail"] for item in source_statistics if item["detail"]},
            "dropped_out_of_scope_by_source": dict(out_of_scope),
            "dropped_unparseable_by_source": dict(unparseable),
            "outputs": {"urls": "urls.jsonl", "subdomains": "subdomains.jsonl", "sources": "sources.jsonl"},
        }
        write_json(self.output_directory / "summary.json", summary)
        dropped = sum(out_of_scope.values())
        self.logger.info("merged and deduplicated: %s unique in-scope URLs (%s with query parameters), %s subdomains; "
                         "%s out-of-scope and %s unparseable results dropped", len(urls), summary["urls_with_query_parameters"],
                         len(subdomains), dropped, sum(unparseable.values()))
        self.logger.info("unique URLs by source: %s", ", ".join(f"{key}={value}" for key, value in by_source.most_common()) or "none")
        self.logger.info("done in %ss -> %s", summary["duration_seconds"], self.output_directory / "urls.jsonl")
        return summary
