import hashlib
import tempfile
import unittest
from pathlib import Path

from fall_of_babylon import AnalysisRequest, EngineStatus, RecoveryStatus
from fall_of_babylon.engines import StaticProfileEngine, TextEncodingEngine
from fall_of_babylon.orchestrator import (
    AnalysisOrchestrator,
    EngineRegistry,
    create_default_analyzer,
)


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_default_pipeline_hashes_source_and_provenance_covers_same_artifact(self) -> None:
        content = b"\x89PNG\r\n\x1a\nhello\x00"
        target = self.root / "sample.png"
        target.write_bytes(content)

        report = create_default_analyzer().analyze(
            AnalysisRequest(target, "authorized test fixture")
        )
        data = report.to_dict()

        self.assertEqual(report.evidence.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(report.evidence.size_bytes, len(content))
        self.assertEqual(report.evidence.recovery_status, RecoveryStatus.NOT_ATTEMPTED)
        self.assertEqual(
            [result.status for result in report.engine_results],
            [
                EngineStatus.COMPLETED,
                EngineStatus.COMPLETED,
                EngineStatus.COMPLETED,
            ],
        )
        self.assertTrue(
            all(
                finding.provenance.artifact_sha256 == report.evidence.sha256
                for result in report.engine_results
                for finding in result.findings
            )
        )
        self.assertEqual(data["schema_version"], 2)
        self.assertNotIn("authorization_basis", data["evidence"])
        self.assertEqual([path.name for path in self.root.iterdir()], ["sample.png"])

    def test_registry_rejects_duplicate_engine_identifiers(self) -> None:
        with self.assertRaises(ValueError):
            EngineRegistry((StaticProfileEngine(), StaticProfileEngine()))

    def test_registry_rejects_no_engines(self) -> None:
        with self.assertRaises(ValueError):
            EngineRegistry(())

    def test_empty_file_has_defined_zero_entropy_profile(self) -> None:
        target = self.root / "empty"
        target.write_bytes(b"")

        report = AnalysisOrchestrator(
            EngineRegistry((StaticProfileEngine(),))
        ).analyze(AnalysisRequest(target, "authorized test fixture"))

        profile = report.engine_results[0].findings[0]
        self.assertIn("shannon_entropy_bits_per_byte=0.0000", profile.evidence)
        self.assertEqual(profile.provenance.byte_start, profile.provenance.byte_end_exclusive)

    def test_text_encoding_engine_reports_validation_without_content(self) -> None:
        for content, expected in (
            ("local café".encode("utf-8"), "strict_decode=valid"),
            (b"\xff\xfe", "strict_decode=valid"),
            (b"\xff\xfe\xff", "strict_decode=invalid"),
        ):
            with self.subTest(content=content):
                target = self.root / "encoding-fixture"
                target.write_bytes(content)
                report = AnalysisOrchestrator(
                    EngineRegistry((TextEncodingEngine(),))
                ).analyze(AnalysisRequest(target, "authorized test fixture"))

                finding = report.engine_results[0].findings[0]
                self.assertIn(expected, finding.evidence)
                self.assertNotIn("café", finding.evidence)
                self.assertEqual(
                    finding.provenance.byte_end_exclusive,
                    len(content),
                )


if __name__ == "__main__":
    unittest.main()
