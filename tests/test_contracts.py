import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from fall_of_babylon import AnalysisReport, AnalysisRequest, Finding, Severity


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


if __name__ == "__main__":
    unittest.main()
