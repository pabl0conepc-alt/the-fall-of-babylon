import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from fall_of_babylon import AnalysisRequest
from fall_of_babylon.local_analysis import (
    MAX_FILE_BYTES,
    LocalAnalysisError,
    analyze_local_file,
)


class LocalAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def analyze(self, path: Path):
        return analyze_local_file(AnalysisRequest(path, "test-owned fixture"))

    def test_hashes_and_identifies_signature_without_parsing(self) -> None:
        content = b"\x89PNG\r\n\x1a\nfixture-data"
        target = self.root / "image.bin"
        target.write_bytes(content)

        result = self.analyze(target)

        self.assertEqual(result.format_name, "PNG")
        self.assertEqual(result.identification_method, "signature")
        self.assertEqual(result.size_bytes, len(content))
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(result.extension_hint, ".bin")

    def test_extension_is_reported_as_hint_only(self) -> None:
        target = self.root / "unknown.pdf"
        target.write_bytes(b"not a PDF")

        result = self.analyze(target)

        self.assertIsNone(result.format_name)
        self.assertEqual(result.identification_method, "filename_extension_only")
        self.assertEqual(result.extension_hint, ".pdf")

    def test_recognizes_only_the_documented_signature_families(self) -> None:
        signatures = {
            "PDF": b"%PDF-1.7",
            "PNG": b"\x89PNG\r\n\x1a\n",
            "JPEG": b"\xff\xd8\xff",
            "GIF": b"GIF89a",
            "ZIP": b"PK\x03\x04",
            "GZIP": b"\x1f\x8b",
            "SQLite": b"SQLite format 3\x00",
            "WAVE": b"RIFF\x00\x00\x00\x00WAVE",
            "WebP": b"RIFF\x00\x00\x00\x00WEBP",
        }

        for expected_format, signature in signatures.items():
            with self.subTest(format=expected_format):
                target = self.root / f"{expected_format}.data"
                target.write_bytes(signature)
                self.assertEqual(self.analyze(target).format_name, expected_format)

    def test_rejects_missing_paths_directories_and_parent_components(self) -> None:
        with self.assertRaises(LocalAnalysisError):
            self.analyze(self.root / "missing")
        with self.assertRaises(LocalAnalysisError):
            self.analyze(self.root)
        with self.assertRaises(LocalAnalysisError):
            self.analyze(Path("folder") / ".." / "sample.txt")

    def test_rejects_symlinked_file_and_directory(self) -> None:
        target = self.root / "real.txt"
        target.write_text("fixture", encoding="utf-8")
        file_link = self.root / "file-link"
        file_link.symlink_to(target)
        directory_link = self.root / "directory-link"
        directory_link.symlink_to(self.root, target_is_directory=True)

        with self.assertRaises(LocalAnalysisError):
            self.analyze(file_link)
        with self.assertRaises(LocalAnalysisError):
            self.analyze(directory_link / "real.txt")

    def test_rejects_non_regular_file(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        fifo = self.root / "pipe"
        os.mkfifo(fifo)

        with self.assertRaises(LocalAnalysisError):
            self.analyze(fifo)

    def test_rejects_files_over_the_size_limit(self) -> None:
        target = self.root / "oversized.bin"
        with target.open("wb") as file:
            file.truncate(MAX_FILE_BYTES + 1)

        with self.assertRaises(LocalAnalysisError):
            self.analyze(target)

    def test_report_contains_origin_method_and_limitations(self) -> None:
        target = self.root / "sample.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\n")

        report = self.analyze(target).to_dict()

        self.assertEqual(report["source"]["kind"], "local_file")
        self.assertTrue(report["source"]["authorization_declared"])
        self.assertEqual(report["identification"]["method"], "signature")
        self.assertTrue(report["limitations"])
        self.assertNotIn("authorization_basis", report["source"])


if __name__ == "__main__":
    unittest.main()
