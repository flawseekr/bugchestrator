"""python3 -m bugchestrator.reconnaissance.javascript_recursive_crawler --url <target URL>"""

import sys

from ..shared.module_runtime import parse_module_arguments
from .crawler import JavascriptRecursiveCrawler


def main() -> int:
    scope = parse_module_arguments("Recursively discover JavaScript resources and extract every in-scope URL reference.")
    JavascriptRecursiveCrawler(scope).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
