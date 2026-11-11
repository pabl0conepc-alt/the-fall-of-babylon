"""Opt-in local SQLite persistence for analysis reports."""

import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any, Protocol

from .domain.contracts import AnalysisJobReport, DirectoryAnalysisReport

SCHEMA_VERSION = 2
MAX_REPORT_BYTES = 1_048_576
MAX_JOB_LIMIT = 1_000
_APPLICATION_ID = 0x42414259
_TABLE_NAME = "babylon_jobs"
_EXPECTED_COLUMNS = (
    "job_id",
    "job_type",
    "created_at",
    "source_path",
    "sha256",
    "report_json",
)


class PersistableReport(Protocol):
    """Common metadata exposed by file and directory analysis reports."""

    job_id: str
    created_at: str
    report_kind: str
    source_path: Path
    sha256: str | None

    def to_dict(self) -> dict[str, object]:
        """Return the versioned report payload."""
        ...


class ReportStoreError(Exception):
    """Expected failure while creating, reading, or writing the local report store."""


class JobNotFoundError(ReportStoreError):
    """The requested analysis job is not present in the report store."""


def save_report(database: Path, report: PersistableReport) -> None:
    """Persist one report in a caller-selected local database transaction."""
    report_json = json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":"))
    if len(report_json.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ReportStoreError(f"Reports larger than {MAX_REPORT_BYTES} bytes are not accepted.")
    if report.report_kind not in ("file", "directory"):
        raise ReportStoreError("Unsupported report kind.")
    database_path = _prepare_database_path(database, report)

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(database_path, timeout=5.0)
        _set_sqlite_limits(connection)
        _ensure_schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO babylon_jobs
                (job_id, job_type, created_at, source_path, sha256, report_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report.job_id,
                report.report_kind,
                report.created_at,
                str(report.source_path),
                report.sha256,
                report_json,
            ),
        )
        connection.commit()
    except sqlite3.Error as exc:
        if connection is not None:
            connection.rollback()
        raise ReportStoreError(f"Could not save the analysis report: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()


def list_jobs(database: Path, limit: int = 20) -> list[dict[str, str | None]]:
    """Return recent job metadata from an existing database without writing to it."""
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError("limit must be an integer")
    if not 1 <= limit <= MAX_JOB_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_JOB_LIMIT}")

    connection = _open_read_only(database)
    try:
        _set_sqlite_limits(connection)
        version = _validate_schema(connection)
        if version == 1:
            rows = connection.execute(
                """
                SELECT 'file', substr(job_id, 1, 64), substr(created_at, 1, 64),
                       substr(source_path, 1, 4096), substr(sha256, 1, 64)
                FROM babylon_jobs
                ORDER BY created_at DESC, job_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT substr(job_type, 1, 16), substr(job_id, 1, 64),
                       substr(created_at, 1, 64), substr(source_path, 1, 4096),
                       substr(sha256, 1, 64)
                FROM babylon_jobs
                ORDER BY created_at DESC, job_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "job_type": row[0],
                "job_id": row[1],
                "created_at": row[2],
                "source_path": row[3],
                "sha256": row[4],
            }
            for row in rows
        ]
    except sqlite3.Error as exc:
        raise ReportStoreError(f"Could not query the analysis database: {exc}") from exc
    finally:
        connection.close()


def export_report(database: Path, job_id: str) -> dict[str, Any]:
    """Load a saved JSON report by ID without modifying the database."""
    if not isinstance(job_id, str) or not job_id.strip():
        raise ValueError("job_id must not be empty")

    connection = _open_read_only(database)
    try:
        _set_sqlite_limits(connection)
        version = _validate_schema(connection)
        row = connection.execute(
            (
                "SELECT 'file', report_json FROM babylon_jobs WHERE job_id = ?"
                if version == 1
                else "SELECT job_type, report_json FROM babylon_jobs WHERE job_id = ?"
            ),
            (job_id,),
        ).fetchone()
        if row is None:
            raise JobNotFoundError(f"No analysis job named {job_id!r} exists in this database.")
        report_type, report_json = row
        report = json.loads(report_json)
        if (
            not isinstance(report, dict)
            or report.get("schema_version") not in (2, 3)
            or not isinstance(report.get("job"), dict)
            or report["job"].get("id") != job_id
            or report["job"].get("type", "file") != report_type
        ):
            raise ReportStoreError("The saved report does not match the supported report schema.")
        return report
    except sqlite3.Error as exc:
        raise ReportStoreError(f"Could not export the analysis report: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReportStoreError("The saved report is not valid JSON.") from exc
    finally:
        connection.close()


def _prepare_database_path(database: Path, report: PersistableReport) -> Path:
    if not isinstance(database, Path):
        raise TypeError("database must be a pathlib.Path")
    if str(database) == ":memory:":
        raise ReportStoreError("A filesystem path is required for the local report database.")
    try:
        database_path = Path(os.path.abspath(os.fspath(database)))
        _check_database_not_in_sources(database_path, report)
        try:
            metadata = database_path.lstat()
        except FileNotFoundError:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(database_path, flags, 0o600)
            os.close(descriptor)
            metadata = database_path.lstat()
    except OSError as exc:
        raise ReportStoreError(f"Could not safely create the analysis database: {exc}") from exc

    if not stat.S_ISREG(metadata.st_mode):
        raise ReportStoreError("The analysis database must be a regular file, not a symlink or device.")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReportStoreError("The analysis database must not be accessible by group or other users.")
    _check_database_not_in_sources(database_path, report, check_inode=True)
    return database_path


def _check_database_not_in_sources(
    database_path: Path,
    report: PersistableReport,
    *,
    check_inode: bool = False,
) -> None:
    protected_paths = [report.source_path]
    root_path: Path | None = None
    if isinstance(report, DirectoryAnalysisReport):
        root_path = report.root_path
        protected_paths.extend(
            item.analysis.evidence.source_path
            for item in report.items
            if item.analysis is not None
        )

    resolved_database = database_path.resolve(strict=False)
    if root_path is not None:
        resolved_root = root_path.resolve(strict=True)
        if resolved_database == resolved_root or resolved_root in resolved_database.parents:
            raise ReportStoreError("The report database must be outside the analyzed directory.")
    for source_path in protected_paths:
        try:
            if source_path.resolve(strict=True) == resolved_database:
                raise ReportStoreError("The report database must not be an analyzed source file.")
            if check_inode and os.path.samefile(database_path, source_path):
                raise ReportStoreError("The report database must not be an analyzed source file.")
        except OSError as exc:
            raise ReportStoreError("Could not verify that the database differs from the source.") from exc


def _open_read_only(database: Path) -> sqlite3.Connection:
    if not isinstance(database, Path):
        raise TypeError("database must be a pathlib.Path")
    try:
        database_path = Path(os.path.abspath(os.fspath(database)))
        metadata = database_path.lstat()
    except OSError as exc:
        raise ReportStoreError(f"Could not open the analysis database: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReportStoreError("The analysis database must be a regular file, not a symlink or device.")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReportStoreError("The analysis database must not be accessible by group or other users.")
    try:
        return sqlite3.connect(
            f"{database_path.as_uri()}?mode=ro",
            uri=True,
            timeout=5.0,
        )
    except sqlite3.Error as exc:
        raise ReportStoreError(f"Could not open the analysis database: {exc}") from exc


def _set_sqlite_limits(connection: sqlite3.Connection) -> None:
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_REPORT_BYTES)
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 10_000)
    connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 16)
    connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 16)


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        if version == 0 and application_id == 0:
            existing_objects = connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN "
                "('table', 'view', 'trigger', 'index') AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if existing_objects:
                raise ReportStoreError(
                    "Refusing to initialize a non-empty, unversioned SQLite database."
                )
            connection.execute(
                """
                CREATE TABLE babylon_jobs (
                    job_id TEXT PRIMARY KEY CHECK (length(job_id) <= 64),
                    job_type TEXT NOT NULL CHECK (job_type IN ('file', 'directory')),
                    created_at TEXT NOT NULL CHECK (length(created_at) <= 64),
                    source_path TEXT NOT NULL CHECK (length(source_path) <= 4096),
                    sha256 TEXT CHECK (sha256 IS NULL OR length(sha256) = 64),
                    report_json TEXT NOT NULL
                        CHECK (length(report_json) <= 1048576)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX babylon_jobs_created_at_idx
                ON babylon_jobs (created_at DESC, job_id ASC)
                """
            )
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        elif application_id == _APPLICATION_ID and version == 1:
            _migrate_schema_1_to_2(connection)
        elif application_id != _APPLICATION_ID or version != SCHEMA_VERSION:
            raise ReportStoreError(
                f"Unsupported or unrecognized database schema "
                f"(application_id={application_id}, version={version})."
            )
        _validate_schema(connection)
        connection.commit()
    except (sqlite3.Error, ReportStoreError):
        connection.rollback()
        raise


def _migrate_schema_1_to_2(connection: sqlite3.Connection) -> None:
    connection.execute("ALTER TABLE babylon_jobs RENAME TO babylon_jobs_v1")
    connection.execute(
        """
        CREATE TABLE babylon_jobs (
            job_id TEXT PRIMARY KEY CHECK (length(job_id) <= 64),
            job_type TEXT NOT NULL CHECK (job_type IN ('file', 'directory')),
            created_at TEXT NOT NULL CHECK (length(created_at) <= 64),
            source_path TEXT NOT NULL CHECK (length(source_path) <= 4096),
            sha256 TEXT CHECK (sha256 IS NULL OR length(sha256) = 64),
            report_json TEXT NOT NULL CHECK (length(report_json) <= 1048576)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO babylon_jobs (job_id, job_type, created_at, source_path, sha256, report_json)
        SELECT job_id, 'file', created_at, source_path, sha256, report_json
        FROM babylon_jobs_v1
        """
    )
    connection.execute("DROP TABLE babylon_jobs_v1")
    connection.execute(
        """
        CREATE INDEX babylon_jobs_created_at_idx
        ON babylon_jobs (created_at DESC, job_id ASC)
        """
    )
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _validate_schema(connection: sqlite3.Connection) -> int:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    application_id = connection.execute("PRAGMA application_id").fetchone()[0]
    if application_id != _APPLICATION_ID or version not in (1, SCHEMA_VERSION):
        raise ReportStoreError(
            f"Unsupported or unrecognized database schema "
            f"(application_id={application_id}, version={version})."
        )
    rows = connection.execute(f"PRAGMA table_info({_TABLE_NAME})").fetchall()
    expected_columns = _EXPECTED_COLUMNS if version == SCHEMA_VERSION else (
        "job_id",
        "created_at",
        "source_path",
        "sha256",
        "report_json",
    )
    if tuple(row[1] for row in rows) != expected_columns:
        raise ReportStoreError("The analysis database schema is incomplete or incompatible.")
    return version
