"""Command-line entry point for local, read-only file identification."""

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .domain.contracts import AnalysisRequest
from .local_analysis import LocalAnalysisError, analyze_local_file


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be blank")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="babylon")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser(
        "analyze",
        help="identify and hash one explicitly authorized local file",
    )
    analyze.add_argument("target", type=Path, help="path to a local regular file")
    analyze.add_argument(
        "--authorization-basis",
        required=True,
        type=_require_non_blank,
        help="briefly state why you are authorized to analyze this file",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    request = AnalysisRequest(args.target, args.authorization_basis)
    try:
        result = analyze_local_file(request)
    except LocalAnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0
