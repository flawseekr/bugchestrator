"""Output location resolution and JSONL persistence.

Modules accept only ``--url``; where they write is resolved here:

* ``BUGCHESTRATOR_OUTPUT_DIRECTORY`` (set by ``run.py`` from ``--output``), or
* ``./output/<target host>`` when a module is run on its own.

Each module writes into ``<output directory>/<module name>/``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable, Iterator

from .url_normalization import host_of

OUTPUT_DIRECTORY_ENVIRONMENT_VARIABLE = "BUGCHESTRATOR_OUTPUT_DIRECTORY"
MODEL_ENVIRONMENT_VARIABLE = "BUGCHESTRATOR_MODEL"
DEFAULT_MODEL = "deepseek/deepseek-flash"


def output_root(target_url: str) -> Path:
    configured = os.environ.get(OUTPUT_DIRECTORY_ENVIRONMENT_VARIABLE)
    root = Path(configured) if configured else Path.cwd() / "output" / (host_of(target_url) or "target")
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def module_output_directory(module_name: str, target_url: str) -> Path:
    directory = output_root(target_url) / module_name
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def configured_model() -> str:
    return os.environ.get(MODEL_ENVIRONMENT_VARIABLE) or DEFAULT_MODEL


class JsonlWriter:
    """Thread-safe, line-buffered JSONL writer (truncates on open)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8")
        self._lock = threading.Lock()
        self.count = 0

    def write(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=False)
        with self._lock:
            self._handle.write(line + "\n")
            self._handle.flush()
            self.count += 1

    def write_many(self, records: Iterable[dict]) -> None:
        for record in records:
            self.write(record)

    def close(self) -> None:
        with self._lock:
            if not self._handle.closed:
                self._handle.close()

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *exception) -> None:
        self.close()


def read_jsonl(path: Path) -> Iterator[dict]:
    path = Path(path)
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def write_json(path: Path, data) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)
