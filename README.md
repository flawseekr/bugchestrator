# Bugchestrator — reconnaissance harness

```bash
python3 run.py --config target.config.json --output output/target.com
```

Write results under `output/`: that directory is git-ignored, and results contain target data
that does not belong in the repository.

`run.py` reads `url` and `model` from the configuration (`scope`, `credentials` and
`full_crud` are reserved and ignored for now), runs the three discovery modules in
parallel, then runs the validator over their combined output.

```
                    TARGET
          +------------+------------+
     static_page   url_osint     javascript_recursive     (parallel processes)
       _crawler    _gatherer          _crawler
          +------------+------------+
                  url_validator
                       |
     <output>/url_validator/validated_urls.jsonl          (validated URL dataset)
```

Progress is shown live on screen, and each line is also written to `<output>/logs/<module>.log`:

```
[2026-11-09 20:37:04][bugchestrator][reconnaissance][url_validator] progress: 56/319 validated (18%), ~24s remaining — accessible=55, not_found=1
```

Lines from `run.py` itself use `[bugchestrator][run]`. Warnings (blocked sources, unreachable hosts, fetch failures) start with `WARNING:`.

Every module also runs on its own with exactly one argument:

```bash
cd /home/xcho   # the directory that contains bugchestrator/
python3 -m bugchestrator.reconnaissance.static_page_crawler          --url https://www.ovo.id/
python3 -m bugchestrator.reconnaissance.url_osint_gatherer           --url https://www.ovo.id/
python3 -m bugchestrator.reconnaissance.javascript_recursive_crawler --url https://www.ovo.id/
python3 -m bugchestrator.reconnaissance.url_validator                --url https://www.ovo.id/
```

On its own a module writes to `./output/<host>/<module>/`. Under `run.py` it writes to
`<--output>/<module>/` (passed as `BUGCHESTRATOR_OUTPUT_DIRECTORY`). The model comes from
`BUGCHESTRATOR_MODEL`, default `deepseek/deepseek-flash`. The validator reads the
discovery modules' `urls.jsonl` from that same directory.

Requirements: Python 3.11+ and `requests` (`pip install -r requirements.txt`). The JavaScript crawler's AI step uses the
`opencode` CLI. If `opencode` is missing, the step is skipped and the summary says so.
Optional: `GITHUB_TOKEN` enables GitHub code search, and `URLSCAN_API_KEY` raises urlscan.io limits.

## Scope (shared by all modules)

The scope is derived from `--url`: the registrable domain plus all of its subdomains.
For example, `https://pax-poi-webapp.grab.com/` scopes to `grab.com` and `*.grab.com`.
Nothing outside it is ever requested. Redirects are followed manually, and a hop that
leaves scope is recorded but not followed. Out-of-scope references are counted per host
in each summary but never stored as URLs.
(`reconnaissance/shared/scope.py`; multi-label suffixes such as `co.id` and `com.sg` are built in.)

## Layout

```
run.py                              orchestrator
target.config.json                  sample configuration
configurations/                     configurations for the three development targets
reconnaissance/shared/              url_normalization, scope, http_client, output, module_runtime
reconnaissance/static_page_crawler/ html_link_extraction.py, crawler.py
reconnaissance/url_osint_gatherer/  sources.py, gatherer.py
reconnaissance/javascript_recursive_crawler/
                                    javascript_lexer.py, reference_extraction.py,
                                    webpack_chunk_reconstruction.py, ai_assisted_extraction.py, crawler.py
reconnaissance/url_validator/       response_fingerprint.py, classification.py, validator.py
tests/                              offline unit tests (python3 -m unittest discover -s bugchestrator/tests -t .)
                                    and evidence_verification.py (live re-verification of a finished run)
```

Shared HTTP behaviour (`http_client.py`):
- thread-local pooled sessions
- per-host concurrency limits and request spacing
- retries with backoff for connection errors, timeouts and 429/502/503/504 (honours `Retry-After`)
- manual, scope-checked redirect following
- streamed body caps
- a `FetchResult` that serializes as HTTP evidence

## Common URL record

Every discovery module writes `urls.jsonl` with one record per unique in-scope URL:

| field | meaning |
|---|---|
| `module` | producing module |
| `url` | normalized URL: lowercase scheme and host, default port and fragment removed, dot segments resolved, query order preserved |
| `deduplication_key` | URL with sorted query, used for cross-module deduplication |
| `path_template` | structural template (`/item/{number}?page=*`), used for sampling |
| `host`, `query_parameters` | host and parameter names |
| `discovery_methods` | `{method: count}` |
| `sources` | attribution list (capped at 25): where and how the URL was found |
| `discovered_at` | UTC timestamp |

## Modules

### static_page_crawler (no AI)
- **Crawl:** BFS over HTML pages on the target host, plus any in-scope host the input URL
  redirects to (e.g. `ovo.id` → `www.ovo.id`). It also reads `robots.txt` and XML
  sitemaps, including sitemap indexes and gzip.
- **Extracts:** anchors, plus labels for navigation, header, footer and pagination links.
  Also `<link rel>`, forms (action, method, field names), the URL a GET form
  submission produces, iframes and frames, media, `srcset`, `meta refresh`/`og:*`,
  `data-href`-style attributes and `<base href>`.
- **Never fetched:** static assets and non-HTML extensions. They are still recorded.
- **Trap limits:** depth 12, 2500 pages, 60 pages per path template. Sitemap entries are
  exempt from the template budget.
- **Outputs:**
  - `urls.jsonl`: sources carry `source_url`, element, attribute and raw reference
  - `pages.jsonl`: HTTP evidence per fetched document (method, URL, status, content type, size, redirect chain, source URL)
  - `errors.jsonl`
  - `summary.json`

### url_osint_gatherer (no AI, never contacts the target)

| source | provides |
|---|---|
| Wayback Machine CDX (paginated, `collapse=urlkey`) | URLs plus archived timestamp, status and MIME type |
| Common Crawl index (latest 3 crawls) | URLs |
| AlienVault OTX (URL list + passive DNS) | URLs, subdomains |
| urlscan.io search | URLs, subdomains |
| Bing, Yahoo, Google, DuckDuckGo `site:` searches | URLs |
| GitHub code search (needs `GITHUB_TOKEN`) | URLs |
| grep.app code search | URLs |
| crt.sh certificate transparency | subdomains |
| HackerTarget host search | subdomains |
| Anubis | subdomains |

`www.example.com` and `example.com` are both queried for URL history.

Every source reports one status: `ok`, `partial`, `empty`, `blocked` (bot wall),
`rate_limited`, `unreachable` (no HTTP response from this network), `skipped` (no
credential) or `failed`. It also logs every request it made (URL, status, size) in
`sources.jsonl`. A URL record lists every source that reported it, with that source's
metadata (archive timestamp, status, query, repository…).

Outputs: `urls.jsonl`, `subdomains.jsonl`, `sources.jsonl`, `summary.json`.

### javascript_recursive_crawler (AI-assisted: opencode + configured model)

**Where JavaScript comes from:**
- the input page's `<script src>`, modulepreload/preload links, import maps and inline
  scripts (the page is read once and no links are followed)
- well-known manifests: `asset-manifest.json`, `.vite/manifest.json`, `ngsw.json`, PWA
  manifests, service workers
- JavaScript file references inside JavaScript
- webpack/rspack chunk maps, evaluated by a small expression evaluator (lazy chunks are
  never written as literals)
- source maps from the `sourceMappingURL` comment, the `SourceMap` header or the `<file>.map` convention

**Analysis:**
- A lexer that understands comments, strings, template literals and regex literals
  extracts string literals, and each is labelled by syntax and context:
  - syntax: absolute, protocol-relative, root-relative or relative URL
  - context: `fetch`/`axios`/`.post(` call with HTTP method, property name,
    client-route property, concatenation
- Noise is filtered: MIME types, date formats and bundler module ids such as `./pages/x`.
- Query-parameter names are collected into `parameters.jsonl`.
- When a source map is available, its first-party `sourcesContent` (no `node_modules`) is
  analysed too.

**Recursion:**
- runs until no new in-scope JavaScript appears (budget: 3000 files)
- a candidate counts as JavaScript only if the server returns a non-HTML body, so an SPA
  catch-all HTML shell is rejected and logged

**AI step** (`ai_assisted_extraction.py`):
- Excerpts around request-building code go to `opencode run --model <model>`.
- The model returns URLs built by concatenation, template literals or `baseURL`+path joins.
- A candidate is accepted only if:
  1. its quoted `evidence` occurs verbatim in the excerpt, and
  2. its host and every literal path segment occur in the excerpt, and
  3. its host is not unresolved and dynamic.
- Rejected candidates are kept with their reason in `ai_assistance.jsonl`.
- **Base-variable resolution:** a candidate such as
  `{window.Grab.config.uriForApiGateway}/portal/groups` has its path verified against the
  excerpt as above. Its base is resolved only from a literal assignment of the same variable
  found in the analysed sources (e.g. `uriForApiGateway:"https://portal.grab.com"`), and only
  if the result is in scope. The assignment snippet is stored as evidence.
- When no such assignment exists, the reference goes to `unresolved_references.jsonl`
  and never becomes a URL.
- Budget: 48 batches per run. A bundle whose source map supplied first-party originals is
  analysed through the originals instead.

**Outputs:**
- `urls.jsonl`: sources carry the JavaScript file, extraction method, reference kind,
  raw value, offset and context snippet
- `javascript_files.jsonl`: per candidate file, its discovery path, HTTP evidence,
  accept/reject reason and source-map result
- `parameters.jsonl`
- `ai_assistance.jsonl`
- `unresolved_references.jsonl`
- `summary.json`

### url_validator (no AI)

**Inputs:** the three `urls.jsonl` files plus `--url`. They are deduplicated across
modules by `deduplication_key`, and at most 5 URLs per path template are validated
(the rest go to `not_validated.jsonl`).

**Baselines:** per host, two randomized nonexistent paths, the root document, and whether
that root is an application shell (it loads scripts and carries under 1,500 characters of
visible text).

Per URL shape, one randomized nonexistent path in the same parent directory with the same
shape:
- trailing slash: `/dir/<random>/`
- extension: `/dir/<random>.svg`
- plain: `/dir/<random>`

Servers route these shapes differently (static file handlers, trailing-slash rewrites), so
the baseline must match the shape. Probes are recorded lazily, capped at 400 per host before
falling back to the first path segment. All probes are written to `host_baselines.jsonl`
with full request and response evidence.

**Per URL:** one GET (2 MB body cap) with in-scope redirect following. Classification uses
response evidence only, never the URL text:

- `accessibility`: accessible, restricted, not_found, method_not_allowed, server_error,
  client_error, redirect_out_of_scope or unreachable
- `resource_type`:

| resource_type | assigned when |
|---|---|
| `html_page` | the body is an HTML document |
| `api_endpoint` | the body is JSON or XML without static-file delivery headers |
| `file:<subtype>` | identified by magic bytes or content sniffing; JSON or XML served with `Last-Modified`, `Accept-Ranges` or object-storage headers becomes `file:json_document` |
| `spa_catch_all` | the response equals both the random-path baseline and the root shell |
| `spa_route` | as above, and a JavaScript source references the path in a route context, or the server returns the shell for this path while random paths behave differently |
| `soft_404` | 2xx and identical to the random-path baseline (not an SPA shell), or the homepage of a server-rendered site served for this path |
| `redirect`, `empty_response`, `error_response`, `unknown` | — |

Each record carries:
- `classification_evidence`: the reasoning, one line per check
- the request (method, URL, headers)
- the response (status, all headers, content type, size, `Content-Length`, body SHA-256,
  600-character body snippet, title, elapsed time)
- the redirect chain, the baseline probes it was compared with, and the discovering modules

Outputs: `validated_urls.jsonl`, `not_validated.jsonl`, `host_baselines.jsonl`, `summary.json`.

## Verifying a run

`tests/evidence_verification.py <output directory> [sample size]` re-fetches the cited
sources for a random sample of each module's records and checks every claim. It writes
`evidence_verification.json` in the output directory and exits non-zero on any mismatch.

| module | check |
|---|---|
| static crawler | the raw reference is present in the cited page |
| JavaScript crawler | the raw value or the AI evidence (plus any base assignment) is present in the cited file or source-map original |
| OSINT gatherer | the Wayback record exists in the CDX API |
| validator | a fresh GET returns the recorded status |

## Run outputs

```
<output>/
  run_summary.json                 per-module status, exit code, duration, log path
  logs/<module>.log
  static_page_crawler/  url_osint_gatherer/  javascript_recursive_crawler/  url_validator/
```
