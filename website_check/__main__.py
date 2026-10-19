"""Command line: website-check <url> [--json] [--min-score N] [--allow-private]"""
import argparse
import json
import sys

from . import _common
from ._common import CheckError, format_report
from .check import check_website


def main(argv=None):
    parser = argparse.ArgumentParser(prog="website-check", description="Score a web page on what matters for being found by local customers (Dutch report).")
    parser.add_argument("url", help="address of the page, e.g. www.example.nl")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--min-score", type=int, metavar="N",
                        help="exit with status 1 when the score is below N (handy in CI)")
    parser.add_argument("--allow-private", action="store_true",
                        help="allow localhost, intranet addresses and other ports (local use only)")
    parser.add_argument("--no-extras", action="store_true",
                        help="skip robots.txt, sitemap and http->https checks")
    args = parser.parse_args(argv)
    _common.ALLOW_PRIVATE = args.allow_private
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    try:
        result = check_website(args.url, extras=not args.no_extras)
    except CheckError as error:
        print(error, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else format_report(result))
    return 1 if args.min_score is not None and result["score"] < args.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
