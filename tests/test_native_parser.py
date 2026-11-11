import hashlib
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from fall_of_babylon.domain.contracts import (
    EngineStatus,
    EvidenceRecord,
)
from fall_of_babylon.local_analysis import MAX_FILE_BYTES, LocalFileContent
from fall_of_babylon.native_parser import NativeFormatEngine, _helper_path
from fall_of_babylon.orchestrator import AnalysisOrchestrator, EngineRegistry


def _put16(data: bytearray, offset: int, value: int, endian: str = "little") -> None:
    data[offset : offset + 2] = value.to_bytes(2, endian)


def _put32(data: bytearray, offset: int, value: int, endian: str = "little") -> None:
    data[offset : offset + 4] = value.to_bytes(4, endian)


def _put64(data: bytearray, offset: int, value: int, endian: str = "little") -> None:
    data[offset : offset + 8] = value.to_bytes(8, endian)


def pe_fixture() -> bytes:
    data = bytearray(368)
    data[:2] = b"MZ"
    _put32(data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    _put16(data, 68, 0x8664)
    _put16(data, 70, 1)
    _put16(data, 84, 240)
    _put16(data, 86, 2)
    _put16(data, 88, 0x20B)
    _put32(data, 104, 0x1000)
    return bytes(data)


def elf64_fixture() -> bytes:
    data = bytearray(185)
    data[:7] = b"\x7fELF\x02\x01\x01"
    _put16(data, 16, 2)
    _put16(data, 18, 62)
    _put32(data, 20, 1)
    _put64(data, 24, 0x400000)
    _put64(data, 32, 64)
    _put64(data, 40, 120)
    _put16(data, 52, 64)
    _put16(data, 54, 56)
    _put16(data, 56, 1)
    _put16(data, 58, 64)
    _put16(data, 60, 1)
    _put32(data, 64, 1)
    _put64(data, 72, 184)
    _put64(data, 96, 1)
    _put32(data, 124, 1)
    _put64(data, 144, 184)
    _put64(data, 152, 1)
    data[184] = 0x90
    return bytes(data)


def macho64_fixture() -> bytes:
    data = bytearray(40)
    data[:4] = b"\xcf\xfa\xed\xfe"
    _put32(data, 4, 0x01000007)
    _put32(data, 12, 2)
    _put32(data, 16, 1)
    _put32(data, 20, 8)
    _put32(data, 32, 0x1B)
    _put32(data, 36, 8)
    return bytes(data)


class NativeFormatEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not _helper_path().is_file():
            raise unittest.SkipTest("native parser helper has not been built")

    def analyze(self, content: bytes):
        source = Path("synthetic-fixture")
        loaded = LocalFileContent(
            source,
            content,
            hashlib.sha256(content).hexdigest(),
        )
        analyzer = AnalysisOrchestrator(EngineRegistry((NativeFormatEngine(),)))
        return analyzer.analyze_loaded(loaded)

    def test_extracts_metadata_from_valid_pe_elf_and_macho(self) -> None:
        cases = (
            (pe_fixture(), "PE", "bits=64", "object_type=0x2"),
            (elf64_fixture(), "ELF", "endianness=little", "object_type=0x2"),
            (macho64_fixture(), "Mach-O", "parse_status=valid", "object_type=0x2"),
        )
        for content, format_name, expected_a, expected_b in cases:
            with self.subTest(format=format_name):
                report = self.analyze(content)
                result = report.engine_results[0]
                self.assertEqual(result.status, EngineStatus.COMPLETED)
                finding = result.findings[0]
                self.assertEqual(finding.title, f"{format_name} structural metadata")
                self.assertIn(expected_a, finding.evidence)
                self.assertIn(expected_b, finding.evidence)
                self.assertEqual(
                    finding.provenance.artifact_sha256,
                    hashlib.sha256(content).hexdigest(),
                )
                self.assertEqual(finding.provenance.byte_end_exclusive, len(content))
                self.assertNotIn(content.hex(), finding.evidence)

    def test_reports_truncated_and_malformed_structures_without_verdicts(self) -> None:
        truncated_pe = pe_fixture()[:-1]
        malformed_elf = bytearray(elf64_fixture())
        _put64(malformed_elf, 72, len(malformed_elf) + 10)
        malformed_macho = bytearray(macho64_fixture())
        _put32(malformed_macho, 36, 0)
        cases = (
            (truncated_pe, "PE", "parse_status=truncated"),
            (bytes(malformed_elf), "ELF", "parse_status=malformed"),
            (bytes(malformed_macho), "Mach-O", "parse_status=malformed"),
        )
        for content, format_name, expected in cases:
            with self.subTest(format=format_name):
                report = self.analyze(content)
                finding = report.engine_results[0].findings[0]
                self.assertIn(expected, finding.evidence)
                self.assertNotIn("malicious", finding.description.lower())

    def test_unsupported_content_completes_without_findings(self) -> None:
        result = self.analyze(b"ordinary local text").engine_results[0]

        self.assertEqual(result.status, EngineStatus.COMPLETED)
        self.assertEqual(result.findings, ())

    def test_helper_failure_and_invalid_protocol_are_explicit(self) -> None:
        engine = NativeFormatEngine()
        evidence = EvidenceRecord(
            Path("fixture"),
            1,
            hashlib.sha256(b"x").hexdigest(),
            "2026-01-01T00:00:00+00:00",
        )
        with patch("fall_of_babylon.native_parser._helper_path", return_value=Path(__file__)):
            with patch(
                "fall_of_babylon.native_parser.subprocess.run",
                side_effect=subprocess.TimeoutExpired("parser", 3),
            ):
                timed_out = engine.analyze(evidence, b"x")
            self.assertEqual(timed_out.status, EngineStatus.FAILED)
            self.assertIn("time limit", timed_out.error)

            with patch(
                "fall_of_babylon.native_parser.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["parser"], 0, stdout=b'{"status":"valid"}', stderr=b""
                ),
            ):
                invalid = engine.analyze(evidence, b"x")
            self.assertEqual(invalid.status, EngineStatus.FAILED)
            self.assertIn("invalid response", invalid.error)

            with patch(
                "fall_of_babylon.native_parser.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["parser"], 7, stdout=b"", stderr=b"parser_error"
                ),
            ):
                failed = engine.analyze(evidence, b"x")
            self.assertEqual(failed.status, EngineStatus.FAILED)
            self.assertIn("status 7", failed.error)

            with patch(
                "fall_of_babylon.native_parser.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["parser"], 0, stdout=b"x" * 4097, stderr=b""
                ),
            ):
                oversized = engine.analyze(evidence, b"x")
            self.assertEqual(oversized.status, EngineStatus.FAILED)
            self.assertIn("oversized response", oversized.error)

    def test_rejects_input_over_the_existing_file_limit(self) -> None:
        content = b"x" * (MAX_FILE_BYTES + 1)
        evidence = EvidenceRecord(
            Path("fixture"),
            len(content),
            hashlib.sha256(content).hexdigest(),
            "2026-01-01T00:00:00+00:00",
        )

        result = NativeFormatEngine().analyze(evidence, content)

        self.assertEqual(result.status, EngineStatus.FAILED)
        self.assertIn("1 MiB", result.error)


if __name__ == "__main__":
    unittest.main()
