#!/usr/bin/env python3
"""Bugchestrator orchestrator.

    python3 run.py --config target.config.json --output target.com

Flow:
                    TARGET
          +------------+------------+
     static_page   url_osint     javascript_recursive     (in parallel)
       _crawler    _gatherer          _crawler
          +------------+------------+
                  url_validator
                       |
              validated URL dataset

Each module runs as its own process (``python3 -m
bugchestrator.reconnaissance.<module> --url <url>``) and receives the shared
output directory and model through environment variables, so modules keep a
single ``--url`` argument and can also be run on their own.

Only ``url`` and ``model`` are read from the configuration; ``scope``,
``credentials`` and ``full_crud`` are reserved for future use.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PACKAGE_DIRECTORY = Path(__file__).resolve().parent
PACKAGE_PARENT = PACKAGE_DIRECTORY.parent
sys.path.insert(0, str(PACKAGE_PARENT))

from bugchestrator.reconnaissance.shared.output import (  # noqa: E402
    MODEL_ENVIRONMENT_VARIABLE,
    OUTPUT_DIRECTORY_ENVIRONMENT_VARIABLE,
    DEFAULT_MODEL,
    write_json,
)
from bugchestrator.reconnaissance.shared.module_runtime import log_prefix  # noqa: E402
from bugchestrator.reconnaissance.shared.scope import TargetScope  # noqa: E402

DISCOVERY_MODULES = ["static_page_crawler", "url_osint_gatherer", "javascript_recursive_crawler"]
VALIDATION_MODULE = "url_validator"
RESERVED_CONFIGURATION_FIELDS = ("scope", "credentials", "full_crud")
MODULE_TIMEOUT_SECONDS = 3 * 60 * 60


def load_configuration(path: Path) -> dict:
    try:
        configuration = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"configuration file not found: {path}")
    except json.JSONDecodeError as error:
        sys.exit(f"configuration file is not valid JSON: {error}")
    if not isinstance(configuration, dict) or not configuration.get("url"):
        sys.exit("configuration must be a JSON object with a 'url' field")
    try:
        TargetScope.from_url(configuration["url"])
    except ValueError as error:
        sys.exit(f"invalid 'url' in configuration: {error}")
    return configuration


SCREEN_LOCK = threading.Lock()


def log(message: str, component: str = "run") -> None:
    with SCREEN_LOCK:
        print(f"{log_prefix('bugchestrator', component)} {message}", flush=True)


def _stream_output(process: subprocess.Popen, module: str, log_handle) -> None:
    """Show every line of the module live on screen and keep it in its log
    file.  Lines that are not already in the log format (e.g. tracebacks) get
    the module prefix so interleaved parallel output stays attributable."""
    for line in process.stdout:
        line = line.rstrip("\n")
        if not line.startswith("["):
            line = f"{log_prefix('bugchestrator', 'reconnaissance', module)} {line}"
        log_handle.write(line + "\n")
        log_handle.flush()
        with SCREEN_LOCK:
            print(line, flush=True)


def run_module(module: str, url: str, environment: dict, logs_directory: Path) -> dict:
    log_path = logs_directory / f"{module}.log"
    command = [sys.executable, "-m", f"bugchestrator.reconnaissance.{module}", "--url", url]
    log(f"starting {module} (log: {log_path})")
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, text=True, bufsize=1, errors="replace")
        reader = threading.Thread(target=_stream_output, args=(process, module, log_handle), daemon=True)
        reader.start()
        try:
            exit_code = process.wait(timeout=MODULE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            exit_code = None
        reader.join(timeout=10)
    duration = round(time.monotonic() - started, 1)
    summary_path = Path(environment[OUTPUT_DIRECTORY_ENVIRONMENT_VARIABLE]) / module / "summary.json"
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
    status = "completed" if exit_code == 0 and summary else ("timeout" if exit_code is None else "failed")
    headline = ""
    if summary:
        headline = ", ".join(f"{key}={summary[key]}" for key in (
            "unique_in_scope_urls", "unique_in_scope_subdomains", "javascript_files_analyzed", "validated", "by_accessibility")
            if key in summary)
    log(f"{module} {status} in {duration}s (exit {exit_code}) {headline}")
    return {"module": module, "status": status, "exit_code": exit_code, "duration_seconds": duration,
            "log": str(log_path), "summary": str(summary_path) if summary else None}


def main() -> int:
    parser = argparse.ArgumentParser(description="Bugchestrator reconnaissance orchestrator")
    parser.add_argument("--config", required=True, help="path to target.config.json")
    parser.add_argument("--output", required=True, help="output directory for generated results")
    arguments = parser.parse_args()

    configuration = load_configuration(Path(arguments.config))
    url = configuration["url"]
    model = configuration.get("model") or DEFAULT_MODEL
    output_directory = Path(arguments.output).resolve()
    logs_directory = output_directory / "logs"
    logs_directory.mkdir(parents=True, exist_ok=True)

    environment = dict(os.environ)
    environment[OUTPUT_DIRECTORY_ENVIRONMENT_VARIABLE] = str(output_directory)
    environment[MODEL_ENVIRONMENT_VARIABLE] = model
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, [str(PACKAGE_PARENT), environment.get("PYTHONPATH")]))
    environment["PYTHONUNBUFFERED"] = "1"

    scope = TargetScope.from_url(url)
    log(f"target {scope.target_url} (scope {scope.domain} and *.{scope.domain}), model {model}")
    log(f"output {output_directory}")
    ignored = [field for field in RESERVED_CONFIGURATION_FIELDS if field in configuration]
    if ignored:
        log(f"reserved configuration fields not used yet: {', '.join(ignored)}")

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log(f"phase 1/2: discovery — running {', '.join(DISCOVERY_MODULES)} in parallel")
    with ThreadPoolExecutor(max_workers=len(DISCOVERY_MODULES)) as executor:
        discovery_results = list(executor.map(lambda module: run_module(module, url, environment, logs_directory),
                                              DISCOVERY_MODULES))
    log(f"phase 2/2: validation — running {VALIDATION_MODULE} over the discovered URLs")
    validation_result = run_module(VALIDATION_MODULE, url, environment, logs_directory)

    results = discovery_results + [validation_result]
    run_summary = {
        "target_url": scope.target_url,
        "scope": scope.describe(),
        "model": model,
        "configuration_file": str(Path(arguments.config).resolve()),
        "reserved_fields_ignored": ignored,
        "started_at": started,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modules": results,
        "validated_url_dataset": str(output_directory / VALIDATION_MODULE / "validated_urls.jsonl"),
    }
    write_json(output_directory / "run_summary.json", run_summary)
    log("summary:")
    for result in results:
        log(f"  {result['module']:<30} {result['status']:<10} {result['duration_seconds']:>7}s  log: {result['log']}")
    validator_summary_path = output_directory / VALIDATION_MODULE / "summary.json"
    if validator_summary_path.exists():
        validator_summary = json.loads(validator_summary_path.read_text())
        log(f"  validated {validator_summary['validated']} URLs: "
            + ", ".join(f"{key}={value}" for key, value in validator_summary["by_accessibility"].items()))
    log(f"validated URL dataset: {run_summary['validated_url_dataset']}")
    failed = [result["module"] for result in results if result["status"] != "completed"]
    if failed:
        log(f"modules that did not complete: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
