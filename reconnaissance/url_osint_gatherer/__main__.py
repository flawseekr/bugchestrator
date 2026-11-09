"""python3 -m bugchestrator.reconnaissance.url_osint_gatherer --url <target URL>"""

import sys

from ..shared.module_runtime import parse_module_arguments
from .gatherer import UrlOsintGatherer


def main() -> int:
    scope = parse_module_arguments("Collect URLs and subdomains of the target from external OSINT sources.")
    UrlOsintGatherer(scope).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
