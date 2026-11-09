"""Common command line, logging and URL-record construction for modules.

Every module exposes exactly one argument, ``--url``.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from .http_client import utc_timestamp
from .scope import TargetScope
from .url_normalization import deduplication_key, host_of, normalize_url, path_template, query_parameter_names


def parse_module_arguments(description: str) -> TargetScope:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--url", required=True, help="Target URL (absolute http/https)")
    arguments = parser.parse_args()
    try:
        return TargetScope.from_url(arguments.url)
    except ValueError as error:
        parser.error(str(error))
        raise  # unreachable, parser.error exits


LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def log_prefix(*components: str) -> str:
    """``[2026-11-09 19:58:09][bugchestrator][reconnaissance][static_page_crawler]``"""
    return f"[{time.strftime(LOG_TIME_FORMAT)}]" + "".join(f"[{component}]" for component in components)


class ModuleLogFormatter(logging.Formatter):
    """``[%Y-%m-%d %H:%M:%S][bugchestrator][reconnaissance][<module>] message``;
    warnings and errors carry their level in front of the message."""

    def __init__(self, module_name: str) -> None:
        super().__init__(f"[%(asctime)s][bugchestrator][reconnaissance][{module_name}] %(message)s", LOG_TIME_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno >= logging.WARNING and not getattr(record, "_level_prefixed", False):
            record.msg = f"{record.levelname}: {record.msg}"
            record._level_prefixed = True
        return super().format(record)


def configure_logging(module_name: str) -> logging.Logger:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ModuleLogFormatter(module_name))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger(f"bugchestrator.{module_name}")


class ProgressThrottle:
    """True at most once every ``interval_seconds``: periodic progress lines
    without flooding the screen."""

    def __init__(self, interval_seconds: float = 5.0) -> None:
        self.interval_seconds = interval_seconds
        self._last = time.monotonic()

    def due(self) -> bool:
        now = time.monotonic()
        if now - self._last >= self.interval_seconds:
            self._last = now
            return True
        return False


def shorten(text: str, length: int = 110) -> str:
    text = str(text)
    return text if len(text) <= length else text[: length - 3] + "..."


def build_url_record(module_name: str, normalized_url: str, **fields) -> dict:
    """Uniform URL record shared by every discovery module."""
    record = {
        "module": module_name,
        "url": normalized_url,
        "deduplication_key": deduplication_key(normalized_url),
        "path_template": path_template(normalized_url),
        "host": host_of(normalized_url),
        "query_parameters": query_parameter_names(normalized_url),
    }
    record.update(fields)
    record.setdefault("discovered_at", utc_timestamp())
    return record


class Stopwatch:
    def __init__(self) -> None:
        self.started_at = utc_timestamp()
        self._start = time.monotonic()

    def seconds(self) -> float:
        return round(time.monotonic() - self._start, 2)


__all__ = [
    "parse_module_arguments", "configure_logging", "build_url_record", "Stopwatch", "ProgressThrottle", "shorten", "log_prefix",
    "normalize_url", "utc_timestamp",
]
