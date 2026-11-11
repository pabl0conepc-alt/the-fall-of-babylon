"""Command-line entry point for bounded, local static analysis."""

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .domain.contracts import AnalysisRequest, DirectoryRequest, EngineStatus
from .directory_analysis import DirectoryAnalysisError, analyze_local_directory
from .local_analysis import LocalAnalysisError
from .orchestrator import create_default_analyzer
from .report_store import (
    MAX_JOB_LIMIT,
    ReportStoreError,
    export_report,
    list_jobs,
    save_report,
)


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be blank")
    return value


def _positive_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= limit <= MAX_JOB_LIMIT:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_JOB_LIMIT}")
    return limit


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="babylon")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser(
        "analyze",
        help="statically inspect one explicitly authorized local file",
    )
    analyze.add_argument("target", type=Path, help="path to a local regular file")
    analyze.add_argument(
        "--authorization-basis",
        required=True,
        type=_require_non_blank,
        help="briefly state why you are authorized to analyze this file",
    )
    analyze.add_argument(
        "--database",
        type=Path,
        help="opt in to saving the report in this private local SQLite database",
    )

    analyze_directory = commands.add_parser(
        "analyze-directory",
        help="inventory and statically analyze a bounded local directory",
    )
    analyze_directory.add_argument(
        "target",
        type=Path,
        help="path to a local directory whose contents you are authorized to analyze",
    )
    analyze_directory.add_argument(
        "--authorization-basis",
        required=True,
        type=_require_non_blank,
        help="briefly state why you are authorized to analyze this directory",
    )
    analyze_directory.add_argument(
        "--database",
        type=Path,
        help="opt in to saving the directory report in this private local SQLite database",
    )

    jobs = commands.add_parser("jobs", help="list saved local analysis jobs")
    jobs.add_argument("--database", required=True, type=Path, help="existing local SQLite database")
    jobs.add_argument(
        "--limit",
        type=_positive_limit,
        default=20,
        help=f"maximum number of recent jobs to list (1-{MAX_JOB_LIMIT}; default: 20)",
    )

    export = commands.add_parser("export", help="print one saved report as JSON")
    export.add_argument("job_id", type=_require_non_blank, help="saved job ID")
    export.add_argument("--database", required=True, type=Path, help="existing local SQLite database")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            request = AnalysisRequest(args.target, args.authorization_basis)
            result = create_default_analyzer().analyze(request)
            if args.database is not None:
                save_report(args.database, result)
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return int(any(engine.status is EngineStatus.FAILED for engine in result.engine_results))
        if args.command == "analyze-directory":
            request = DirectoryRequest(args.target, args.authorization_basis)
            result = analyze_local_directory(request)
            if args.database is not None:
                save_report(args.database, result)
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return 0
        if args.command == "jobs":
            print(json.dumps({"jobs": list_jobs(args.database, args.limit)}, indent=2, sort_keys=True))
            return 0
        if args.command == "export":
            print(json.dumps(export_report(args.database, args.job_id), indent=2, sort_keys=True))
            return 0
    except LocalAnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except DirectoryAnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ReportStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    raise RuntimeError(f"unsupported command: {args.command}")
