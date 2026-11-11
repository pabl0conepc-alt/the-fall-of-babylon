"""Human-readable terminal views of the versioned report payloads."""

from typing import Any


_LIMITATION = (
    "Observational static analysis only; no verdict, execution, extraction, "
    "or structural file parsing is performed."
)


def render_report(report: dict[str, Any]) -> str:
    job = report["job"]
    lines = [
        f"Babylon analysis · {job['type']} job {job['id']}",
        f"Created: {job['created_at']}",
    ]
    if "evidence" in report:
        evidence = report["evidence"]
        lines.extend(
            [
                f"File: {evidence['path']}",
                f"Size: {evidence['size_bytes']} bytes",
                f"SHA-256: {evidence['sha256']}",
                f"Recovery: {evidence['recovery_status']}",
            ]
        )
        _render_engines_and_findings(lines, report.get("engines", []), report.get("findings", []))
    else:
        source = report["source"]
        summary = report["summary"]
        lines.extend(
            [
                f"Directory: {source['path']}",
                (
                    f"Files analyzed: {summary['files_analyzed']} · "
                    f"entries recorded: {summary['entries_recorded']} · "
                    f"bytes read: {summary['total_bytes_read']}"
                ),
                f"Traversal truncated: {'yes' if summary['truncated'] else 'no'}",
                (
                    "Limits: "
                    f"depth {report['limits']['max_depth']} · "
                    f"{report['limits']['max_files']} files · "
                    f"{report['limits']['max_entries']} entries · "
                    f"{report['limits']['max_total_bytes']} bytes total"
                ),
                "Inventory:",
            ]
        )
        if summary["truncated"]:
            lines.append("Warning: traversal stopped at a configured safety limit.")
        for item in report["items"]:
            size = f" · {item['size_bytes']} bytes" if item["size_bytes"] is not None else ""
            lines.append(f"  {item['status']:<28} {item['path']}{size}")
            analysis = item["analysis"]
            if analysis is not None:
                for engine in analysis["engines"]:
                    lines.append(
                        f"    {engine['status']:<9} {engine['id']}: {engine['summary']}"
                    )
                    if engine["error"]:
                        lines.append(f"      Error: {engine['error']}")
                for finding in analysis["findings"]:
                    lines.append(f"    • {finding['title']}: {finding['description']}")
                    if finding["evidence"]:
                        lines.append(f"      Observation: {finding['evidence']}")
    lines.extend(["", _LIMITATION])
    return "\n".join(lines)


def _render_engines_and_findings(
    lines: list[str],
    engines: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    lines.append("Engines:")
    for engine in engines:
        lines.append(f"  {engine['status']:<9} {engine['id']}: {engine['summary']}")
        if engine["error"]:
            lines.append(f"    Error: {engine['error']}")
    lines.append("Findings:")
    if not findings:
        lines.append("  No findings.")
    for finding in findings:
        lines.append(
            f"  [{finding['severity'].upper()}] {finding['title']}: "
            f"{finding['description']}"
        )
        if finding["evidence"]:
            lines.append(f"    Observation: {finding['evidence']}")
        provenance = finding["provenance"]
        if provenance is not None:
            lines.append(
                f"    Provenance: bytes {provenance['byte_start']}-"
                f"{provenance['byte_end_exclusive']} · SHA-256 "
                f"{provenance['artifact_sha256']}"
            )


def render_jobs(jobs: list[dict[str, Any]]) -> str:
    if not jobs:
        return "No saved analysis jobs."
    lines = ["Saved local analysis jobs:"]
    for job in jobs:
        digest = job["sha256"] or "not applicable"
        lines.extend(
            [
                f"  {job['job_id']} · {job['job_type']} · {job['created_at']}",
                f"    Source: {job['source_path']}",
                f"    SHA-256: {digest}",
            ]
        )
    return "\n".join(lines)
