"""python3 -m bugchestrator.reconnaissance.url_validator --url <target URL>

Validates the URLs that the discovery modules wrote into the same output
directory (BUGCHESTRATOR_OUTPUT_DIRECTORY, or ./output/<host>)."""

import sys

from ..shared.module_runtime import parse_module_arguments
from .validator import UrlValidator


def main() -> int:
    scope = parse_module_arguments("Validate and classify discovered URLs with real HTTP evidence.")
    UrlValidator(scope).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
