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

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "fall_of_babylon", *args],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=10,
            check=False,
        )

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
        self.assertEqual(report["identification"]["format"], "PNG")
        self.assertEqual(report["source"]["path"], str(target))
        self.assertEqual(report["source"]["size_bytes"], len(target.read_bytes()))
        self.assertEqual([path.name for path in self.root.iterdir()], ["sample.png"])

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
        link.symlink_to(target)

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
