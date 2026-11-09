"""python3 -m bugchestrator.reconnaissance.static_page_crawler --url <target URL>"""

import sys

from ..shared.module_runtime import parse_module_arguments
from .crawler import StaticPageCrawler


def main() -> int:
    scope = parse_module_arguments("Recursively crawl static HTML pages and record every in-scope URL reference.")
    StaticPageCrawler(scope).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
