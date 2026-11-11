"""Interfaces between the domain and future analysis implementations."""

from typing import Protocol

from .domain.contracts import AnalysisReport, AnalysisRequest


class Analyzer(Protocol):
    """Typed boundary for an analysis implementation."""

    name: str

    def analyze(self, request: AnalysisRequest) -> AnalysisReport:
        """Return a report for the supplied, authorized request."""
        ...
