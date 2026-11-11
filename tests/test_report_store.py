import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fall_of_babylon import AnalysisRequest
from fall_of_babylon.orchestrator import create_default_analyzer
from fall_of_babylon.report_store import (
    JobNotFoundError,
    ReportStoreError,
    export_report,
    list_jobs,
    save_report,
)


class ReportStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.source = self.root / "sample.bin"
        self.source.write_bytes(b"local test evidence")
        self.report = create_default_analyzer().analyze(
            AnalysisRequest(self.source, "authorized test fixture")
        )
        self.database = self.root / "reports.sqlite3"

    def test_round_trips_report_and_records_versioned_schema(self) -> None:
        save_report(self.database, self.report)

        self.assertEqual(
            list_jobs(self.database),
            [
                {
                    "job_type": "file",
                    "job_id": self.report.job_id,
                    "created_at": self.report.created_at,
                    "source_path": str(self.source),
                    "sha256": self.report.evidence.sha256,
                }
            ],
        )
        self.assertEqual(export_report(self.database, self.report.job_id), self.report.to_dict())
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], 0x42414259)

    def test_database_is_created_private_on_posix(self) -> None:
        save_report(self.database, self.report)

        if os.name == "posix":
            self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)

    def test_failed_duplicate_insert_keeps_original_job(self) -> None:
        save_report(self.database, self.report)

        with self.assertRaises(ReportStoreError):
            save_report(self.database, self.report)

        self.assertEqual(len(list_jobs(self.database)), 1)

    def test_queries_use_job_id_as_data_not_sql(self) -> None:
        save_report(self.database, self.report)

        with self.assertRaises(JobNotFoundError):
            export_report(self.database, "' OR 1=1 --")

    def test_refuses_to_use_source_as_database_without_modifying_it(self) -> None:
        original = self.source.read_bytes()
        if os.name == "posix":
            self.source.chmod(0o600)

        with self.assertRaises(ReportStoreError):
            save_report(self.source, self.report)

        self.assertEqual(self.source.read_bytes(), original)

    def test_refuses_symlinked_database_path(self) -> None:
        linked_database = self.root / "linked.sqlite3"
        linked_database.symlink_to(self.source)
        original = self.source.read_bytes()

        with self.assertRaises(ReportStoreError):
            save_report(linked_database, self.report)

        self.assertEqual(self.source.read_bytes(), original)

    def test_read_only_query_does_not_create_missing_database(self) -> None:
        missing = self.root / "not-created.sqlite3"

        with self.assertRaises(ReportStoreError):
            list_jobs(missing)

        self.assertFalse(missing.exists())

    def test_refuses_non_empty_unversioned_database(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE unrelated (value TEXT)")
        if os.name == "posix":
            self.database.chmod(0o600)

        with self.assertRaises(ReportStoreError):
            save_report(self.database, self.report)

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='unrelated'"
                ).fetchone()[0],
                "unrelated",
            )

    def test_migrates_existing_v1_database_transactionally(self) -> None:
        old_report = self.report.to_dict()
        old_report["job"]["id"] = "previous-job"
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """
                CREATE TABLE babylon_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX babylon_jobs_created_at_idx "
                "ON babylon_jobs (created_at DESC, job_id ASC)"
            )
            connection.execute("PRAGMA application_id = 0x42414259")
            connection.execute("PRAGMA user_version = 1")
            connection.execute(
                """
                INSERT INTO babylon_jobs
                    (job_id, created_at, source_path, sha256, report_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "previous-job",
                    self.report.created_at,
                    str(self.source),
                    self.report.evidence.sha256,
                    json.dumps(old_report),
                ),
            )
        if os.name == "posix":
            self.database.chmod(0o600)

        save_report(self.database, self.report)

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
        jobs = list_jobs(self.database)
        self.assertEqual({job["job_type"] for job in jobs}, {"file"})
        self.assertEqual(len(jobs), 2)
        self.assertEqual(export_report(self.database, "previous-job"), old_report)

    def test_list_limit_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            list_jobs(self.database, 0)


if __name__ == "__main__":
    unittest.main()
