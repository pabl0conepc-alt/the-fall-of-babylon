"""Immutable data contracts shared by future analysis components."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Relative severity assigned to a reported finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AnalysisRequest:
    """A request to analyze a caller-selected local path."""

    target: Path
    authorization_basis: str

    def __post_init__(self) -> None:
        if not isinstance(self.target, Path):
            raise TypeError("target must be a pathlib.Path")
        if not isinstance(self.authorization_basis, str):
            raise TypeError("authorization_basis must be a string")
        if not self.authorization_basis.strip():
            raise ValueError("authorization_basis must not be empty")


@dataclass(frozen=True)
class Finding:
    """A single descriptive result from an analysis component."""

    title: str
    severity: Severity
    description: str
    evidence: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.title, str):
            raise TypeError("title must be a string")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")
        if self.evidence is not None and not isinstance(self.evidence, str):
            raise TypeError("evidence must be a string or None")
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.description.strip():
            raise ValueError("description must not be empty")


@dataclass(frozen=True)
class AnalysisReport:
    """Findings associated with one analysis request target."""

    target: Path
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.target, Path):
            raise TypeError("target must be a pathlib.Path")
        if not isinstance(self.findings, tuple):
            raise TypeError("findings must be a tuple")
        if any(not isinstance(finding, Finding) for finding in self.findings):
            raise TypeError("findings must contain only Finding instances")
