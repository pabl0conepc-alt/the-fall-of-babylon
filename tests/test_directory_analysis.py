import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fall_of_babylon import (
    DirectoryEntryKind,
    DirectoryItemStatus,
    DirectoryRequest,
)
from fall_of_babylon.directory_analysis import (
    MAX_DIRECTORY_DEPTH,
    MAX_DIRECTORY_ENTRIES,
    MAX_DIRECTORY_FILES,
    DirectoryAnalysisError,
    analyze_local_directory,
)


class DirectoryAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name) / "authorized"
        self.root.mkdir()

    def analyze(self, root: Path | None = None):
        return analyze_local_directory(
            DirectoryRequest(root or self.root, "authorized test fixture")
        )

    def test_analyzes_regular_files_and_records_symlinks_and_special_files(self) -> None:
        (self.root / "sample.txt").write_bytes(b"safe fixture")
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "inner.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        outside = self.root.parent / "outside.txt"
        outside.write_text("must not be read", encoding="utf-8")
        (self.root / "file-link").symlink_to(outside)
        (self.root / "directory-link").symlink_to(nested, target_is_directory=True)
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo")

        report = self.analyze()

        items = {item.relative_path: item for item in report.items}
        self.assertEqual(items["file-link"].kind, DirectoryEntryKind.SYMLINK)
        self.assertEqual(items["file-link"].status, DirectoryItemStatus.REJECTED_SYMLINK)
        self.assertEqual(
            items["directory-link"].status,
            DirectoryItemStatus.REJECTED_SYMLINK,
        )
        self.assertEqual(items["nested"].status, DirectoryItemStatus.DIRECTORY_TRAVERSED)
        self.assertEqual(items["sample.txt"].status, DirectoryItemStatus.ANALYZED)
        self.assertEqual(items["nested/inner.png"].status, DirectoryItemStatus.ANALYZED)
        self.assertNotIn("outside.txt", items)
        if hasattr(os, "mkfifo"):
            self.assertEqual(items["fifo"].status, DirectoryItemStatus.REJECTED_SPECIAL)
        self.assertEqual(report.files_analyzed, 2)

    def test_rejects_symlinked_root_without_following_it(self) -> None:
        link = self.root.parent / "root-link"
        link.symlink_to(self.root, target_is_directory=True)

        with self.assertRaises(DirectoryAnalysisError):
            self.analyze(link)

    def test_depth_limit_records_directory_without_traversing_below_it(self) -> None:
        path = self.root
        for component in ("a", "b", "c", "d"):
            path = path / component
            path.mkdir()
        (path / "hidden.txt").write_text("fixture", encoding="utf-8")

        report = self.analyze()
        items = {item.relative_path: item for item in report.items}

        self.assertEqual(
            items["a/b/c/d"].status,
            DirectoryItemStatus.SKIPPED_DEPTH_LIMIT,
        )
        self.assertNotIn("a/b/c/d/hidden.txt", items)
        self.assertTrue(report.truncated)
        self.assertEqual(report.max_depth, MAX_DIRECTORY_DEPTH)

    def test_file_count_and_entry_limits_are_reported(self) -> None:
        for index in range(MAX_DIRECTORY_FILES + 3):
            (self.root / f"{index:03}.txt").write_bytes(b"x")

        report = self.analyze()

        self.assertEqual(report.files_analyzed, MAX_DIRECTORY_FILES)
        self.assertTrue(report.truncated)
        self.assertTrue(
            any(item.status is DirectoryItemStatus.SKIPPED_FILE_LIMIT for item in report.items)
        )

        other_root = self.root.parent / "entries"
        other_root.mkdir()
        for index in range(MAX_DIRECTORY_ENTRIES + 5):
            (other_root / f"{index:03}.txt").write_bytes(b"x")
        limited = self.analyze(other_root)
        self.assertEqual(len(limited.items), MAX_DIRECTORY_ENTRIES)
        self.assertTrue(limited.truncated)

    def test_total_byte_limit_skips_files_without_reading_them(self) -> None:
        (self.root / "first").write_bytes(b"123456789012")
        (self.root / "second").write_bytes(b"abcdefghijkl")

        with patch("fall_of_babylon.directory_analysis.MAX_DIRECTORY_BYTES", 20):
            report = self.analyze()

        self.assertEqual(report.total_bytes_read, 12)
        skipped = [
            item
            for item in report.items
            if item.status is DirectoryItemStatus.SKIPPED_TOTAL_BYTES_LIMIT
        ]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(report.max_total_bytes, 20)
        self.assertTrue(report.truncated)


if __name__ == "__main__":
    unittest.main()
