import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.env = os.environ.copy()
        source_path = str(Path(__file__).resolve().parents[1] / "src")
        existing_pythonpath = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = os.pathsep.join(
            part for part in (source_path, existing_pythonpath) if part
        )

    def run_cli(
        self, *args: str, output_format: str | None = "json"
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "fall_of_babylon", *args]
        if output_format is not None:
            command.extend(("--format", output_format))
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=self.env,
            timeout=10,
            check=False,
        )

    def test_analysis_defaults_to_human_readable_report(self) -> None:
        target = self.root / "sample.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\nfixture")

        result = self.run_cli(
            "analyze",
            str(target),
            "--authorization-basis",
            "owned test fixture",
            output_format=None,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Babylon analysis · file job", result.stdout)
        self.assertIn(f"SHA-256: {hashlib.sha256(target.read_bytes()).hexdigest()}", result.stdout)
        self.assertIn("[INFO] File signature identified", result.stdout)
        self.assertIn("Observational static analysis only", result.stdout)
        self.assertNotEqual(result.stdout[:1], "{")

    def test_emits_json_for_an_authorized_local_file(self) -> None:
        target = self.root / "sample.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\nfixture")

        result = self.run_cli(
            "analyze",
            str(target),
            "--authorization-basis",
            "owned test fixture",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["evidence"]["path"], str(target))
        self.assertEqual(report["evidence"]["size_bytes"], len(target.read_bytes()))
        self.assertEqual(report["evidence"]["recovery_status"], "not_attempted")
        self.assertEqual(
            [engine["id"] for engine in report["engines"]],
            [
                "signature-identification",
                "byte-profile",
                "text-encoding-profile",
                "native-structural-format",
            ],
        )
        self.assertIn(
            "PNG",
            [finding["evidence"] for finding in report["findings"]],
        )
        self.assertEqual([path.name for path in self.root.iterdir()], ["sample.png"])

    def test_opt_in_database_persists_and_supports_list_and_export(self) -> None:
        target = self.root / "sample.png"
        target_bytes = b"\x89PNG\r\n\x1a\nfixture"
        target.write_bytes(target_bytes)
        database = self.root / "reports.sqlite3"

        analyzed = self.run_cli(
            "analyze",
            str(target),
            "--authorization-basis",
            "owned test fixture",
            "--database",
            str(database),
        )

        self.assertEqual(analyzed.returncode, 0, analyzed.stderr)
        report = json.loads(analyzed.stdout)
        self.assertEqual(target.read_bytes(), target_bytes)
        self.assertTrue(database.exists())

        listed = self.run_cli("jobs", "--database", str(database))
        self.assertEqual(listed.returncode, 0, listed.stderr)
        jobs = json.loads(listed.stdout)["jobs"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["job_id"], report["job"]["id"])

        readable = self.run_cli("jobs", "--database", str(database), output_format="text")
        self.assertEqual(readable.returncode, 0, readable.stderr)
        self.assertIn(report["job"]["id"], readable.stdout)
        self.assertIn("Saved local analysis jobs", readable.stdout)

        exported = self.run_cli(
            "export",
            report["job"]["id"],
            "--database",
            str(database),
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual(json.loads(exported.stdout), report)

        readable_export = self.run_cli(
            "export",
            report["job"]["id"],
            "--database",
            str(database),
            output_format="text",
        )
        self.assertEqual(readable_export.returncode, 0, readable_export.stderr)
        self.assertIn(f"Babylon analysis · file job {report['job']['id']}", readable_export.stdout)

    def test_rejects_using_the_source_as_the_database(self) -> None:
        target = self.root / "sample.bin"
        target.write_bytes(b"do not replace")
        original = target.read_bytes()

        result = self.run_cli(
            "analyze",
            str(target),
            "--authorization-basis",
            "owned test fixture",
            "--database",
            str(target),
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr)

    @unittest.skipIf(os.name == "nt", "directory traversal is not supported on Windows")
    def test_directory_command_is_read_only_without_database_and_persists_opt_in(self) -> None:
        directory = self.root / "authorized"
        directory.mkdir()
        source = directory / "sample.txt"
        source.write_bytes(b"fixture")
        original = source.read_bytes()

        analyzed = self.run_cli(
            "analyze-directory",
            str(directory),
            "--authorization-basis",
            "authorized test fixture",
        )

        self.assertEqual(analyzed.returncode, 0, analyzed.stderr)
        report = json.loads(analyzed.stdout)
        self.assertEqual(report["source"]["path"], str(directory))
        self.assertEqual(report["summary"]["files_analyzed"], 1)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual([path.name for path in directory.iterdir()], ["sample.txt"])

        readable = self.run_cli(
            "analyze-directory",
            str(directory),
            "--authorization-basis",
            "authorized test fixture",
            output_format="text",
        )
        self.assertEqual(readable.returncode, 0, readable.stderr)
        self.assertIn("Files analyzed: 1", readable.stdout)
        self.assertIn("sample.txt", readable.stdout)
        self.assertIn("Observational static analysis only", readable.stdout)

        database = self.root / "reports.sqlite3"
        stored = self.run_cli(
            "analyze-directory",
            str(directory),
            "--authorization-basis",
            "authorized test fixture",
            "--database",
            str(database),
        )
        self.assertEqual(stored.returncode, 0, stored.stderr)
        stored_report = json.loads(stored.stdout)
        jobs = self.run_cli("jobs", "--database", str(database))
        self.assertEqual(jobs.returncode, 0, jobs.stderr)
        self.assertEqual(json.loads(jobs.stdout)["jobs"][0]["job_type"], "directory")
        exported = self.run_cli(
            "export",
            stored_report["job"]["id"],
            "--database",
            str(database),
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual(json.loads(exported.stdout), stored_report)

    @unittest.skipIf(os.name == "nt", "directory traversal is not supported on Windows")
    def test_directory_report_database_cannot_be_created_inside_scanned_tree(self) -> None:
        directory = self.root / "authorized"
        directory.mkdir()
        source = directory / "sample.txt"
        source.write_bytes(b"fixture")
        database = directory / "reports.sqlite3"

        result = self.run_cli(
            "analyze-directory",
            str(directory),
            "--authorization-basis",
            "authorized test fixture",
            "--database",
            str(database),
        )

        self.assertEqual(result.returncode, 2)
        self.assertFalse(database.exists())
        self.assertEqual(source.read_bytes(), b"fixture")

    def test_requires_authorization_basis(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("fixture", encoding="utf-8")

        result = self.run_cli("analyze", str(target))

        self.assertEqual(result.returncode, 2)
        self.assertIn("--authorization-basis", result.stderr)

    def test_rejects_whitespace_authorization_basis_without_traceback(self) -> None:
        result = self.run_cli(
            "analyze",
            str(self.root / "sample.txt"),
            "--authorization-basis",
            "   ",
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--authorization-basis: must not be blank", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_reports_symlink_refusal_without_json_output(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("fixture", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic-link creation is unavailable")

        result = self.run_cli(
            "analyze",
            str(link),
            "--authorization-basis",
            "owned test fixture",
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
