"""Foundational contracts for authorized, local analysis."""

from .domain.contracts import AnalysisReport, AnalysisRequest, Finding, Severity
from .ports import Analyzer

__all__ = [
    "AnalysisReport",
    "AnalysisRequest",
    "Analyzer",
    "Finding",
    "Severity",
]
