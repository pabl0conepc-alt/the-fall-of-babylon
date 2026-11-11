import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from fall_of_babylon import (
    AnalysisJobReport,
    AnalysisReport,
    AnalysisRequest,
    EngineResult,
    EngineStatus,
    EvidenceRecord,
    EvidenceReference,
    Finding,
    RecoveryStatus,
    Severity,
)


class AnalysisRequestTests(unittest.TestCase):
    def test_requires_an_authorization_basis(self) -> None:
        with self.assertRaises(ValueError):
            AnalysisRequest(Path("sample.txt"), "  ")

    def test_authorization_basis_must_be_text(self) -> None:
        with self.assertRaises(TypeError):
            AnalysisRequest(Path("sample.txt"), None)  # type: ignore[arg-type]

    def test_target_must_be_a_path(self) -> None:
        with self.assertRaises(TypeError):
            AnalysisRequest("sample.txt", "owned test fixture")  # type: ignore[arg-type]

    def test_request_is_immutable(self) -> None:
        request = AnalysisRequest(Path("sample.txt"), "owned test fixture")
        with self.assertRaises(FrozenInstanceError):
            request.target = Path("other.txt")  # type: ignore[misc]


class FindingTests(unittest.TestCase):
    def test_requires_descriptive_text(self) -> None:
        with self.assertRaises(ValueError):
            Finding("", Severity.LOW, "Description")
        with self.assertRaises(ValueError):
            Finding("Title", Severity.LOW, " ")

    def test_text_fields_must_be_strings(self) -> None:
        with self.assertRaises(TypeError):
            Finding(None, Severity.LOW, "Description")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            Finding("Title", Severity.LOW, None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            Finding("Title", Severity.LOW, "Description", evidence=1)  # type: ignore[arg-type]

    def test_finding_is_immutable(self) -> None:
        finding = Finding("Title", Severity.LOW, "Description")
        with self.assertRaises(FrozenInstanceError):
            finding.title = "Updated title"  # type: ignore[misc]

    def test_report_defaults_to_no_findings(self) -> None:
        report = AnalysisReport(Path("sample.txt"))
        self.assertEqual(report.findings, ())

    def test_report_validates_target_and_findings(self) -> None:
        with self.assertRaises(TypeError):
            AnalysisReport("sample.txt")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            AnalysisReport(Path("sample.txt"), [])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            AnalysisReport(Path("sample.txt"), ("not a finding",))  # type: ignore[arg-type]

    def test_report_is_immutable(self) -> None:
        report = AnalysisReport(Path("sample.txt"))
        with self.assertRaises(FrozenInstanceError):
            report.findings = (Finding("Title", Severity.LOW, "Description"),)  # type: ignore[misc]


class EvidenceContractTests(unittest.TestCase):
    def test_validates_evidence_digest_and_byte_range(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceReference("bad", 0, 1, "signature", "match")
        with self.assertRaises(ValueError):
            EvidenceReference("a" * 64, 2, 1, "signature", "match")

    def test_evidence_records_explicitly_default_to_no_recovery(self) -> None:
        evidence = EvidenceRecord(
            Path("sample.bin"),
            4,
            "a" * 64,
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(evidence.recovery_status, RecoveryStatus.NOT_ATTEMPTED)

    def test_failed_engine_result_requires_an_error(self) -> None:
        with self.assertRaises(ValueError):
            EngineResult("engine", EngineStatus.FAILED, "Failed")

    def test_job_report_serializes_verifiable_finding_provenance(self) -> None:
        evidence = EvidenceRecord(
            Path("sample.bin"),
            4,
            "a" * 64,
            "2026-01-01T00:00:00+00:00",
        )
        finding = Finding(
            "Signature",
            Severity.INFO,
            "Recognized bytes.",
            provenance=EvidenceReference("a" * 64, 0, 4, "signature", "match"),
        )
        report = AnalysisJobReport(
            "job-1",
            "2026-01-01T00:00:00+00:00",
            evidence,
            (EngineResult("signature", EngineStatus.COMPLETED, "Done", (finding,)),),
        )

        data = report.to_dict()

        self.assertEqual(data["evidence"]["recovery_status"], "not_attempted")
        self.assertEqual(
            data["findings"][0]["provenance"]["artifact_sha256"],
            evidence.sha256,
        )
        self.assertEqual(data["findings"][0]["provenance"]["byte_end_exclusive"], 4)

    def test_job_report_rejects_provenance_for_other_or_out_of_range_evidence(self) -> None:
        evidence = EvidenceRecord(
            Path("sample.bin"),
            4,
            "a" * 64,
            "2026-01-01T00:00:00+00:00",
        )
        for reference in (
            EvidenceReference("b" * 64, 0, 1, "signature", "match"),
            EvidenceReference("a" * 64, 0, 5, "signature", "match"),
        ):
            finding = Finding(
                "Signature",
                Severity.INFO,
                "Recognized bytes.",
                provenance=reference,
            )
            with self.subTest(reference=reference):
                with self.assertRaises(ValueError):
                    AnalysisJobReport(
                        "job-1",
                        "2026-01-01T00:00:00+00:00",
                        evidence,
                        (
                            EngineResult(
                                "signature",
                                EngineStatus.COMPLETED,
                                "Done",
                                (finding,),
                            ),
                        ),
                    )

    def test_evidence_timestamps_must_be_utc(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceRecord(
                Path("sample.bin"),
                0,
                "a" * 64,
                "2026-01-01T01:00:00+01:00",
            )


if __name__ == "__main__":
    unittest.main()
