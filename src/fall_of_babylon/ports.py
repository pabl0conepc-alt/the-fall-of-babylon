"""Interfaces between the domain and analysis implementations."""

from typing import Protocol

from .domain.contracts import AnalysisJobReport, AnalysisRequest, EngineResult, EvidenceRecord


class Analyzer(Protocol):
    """Typed boundary for a complete analysis job."""

    name: str

    def analyze(self, request: AnalysisRequest) -> AnalysisJobReport:
        """Return a report for the supplied, authorized request."""
        ...


class AnalysisEngine(Protocol):
    """A deterministic static analyzer operating only on acquired bytes."""

    engine_id: str

    def analyze(
        self, evidence: EvidenceRecord, content: bytes
    ) -> EngineResult:
        """Return observations without modifying or executing the artifact."""
        ...
