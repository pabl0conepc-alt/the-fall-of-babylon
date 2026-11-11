"""Immutable data contracts shared by local analysis components."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Relative severity assigned to a reported finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStatus(str, Enum):
    """Whether evidence recovery was attempted for an artifact."""

    NOT_ATTEMPTED = "not_attempted"
    RECOVERED = "recovered"
    PARTIALLY_RECOVERED = "partially_recovered"
    UNAVAILABLE = "unavailable"


class EngineStatus(str, Enum):
    """Outcome of one registered analysis engine."""

    COMPLETED = "completed"
    FAILED = "failed"


class DirectoryEntryKind(str, Enum):
    """Filesystem entry type recorded during directory inventory."""

    REGULAR_FILE = "regular_file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    SPECIAL = "special"
    UNKNOWN = "unknown"


class DirectoryItemStatus(str, Enum):
    """Outcome for a single inventoried directory entry."""

    ANALYZED = "analyzed"
    DIRECTORY_TRAVERSED = "directory_traversed"
    REJECTED_SYMLINK = "rejected_symlink"
    REJECTED_SPECIAL = "rejected_special"
    REJECTED_FILE_TOO_LARGE = "rejected_file_too_large"
    REJECTED_UNREADABLE = "rejected_unreadable"
    SKIPPED_DEPTH_LIMIT = "skipped_depth_limit"
    SKIPPED_FILE_LIMIT = "skipped_file_limit"
    SKIPPED_TOTAL_BYTES_LIMIT = "skipped_total_bytes_limit"


@dataclass(frozen=True)
class EvidenceReference:
    """A verifiable observation tied to bytes in a hashed artifact."""

    artifact_sha256: str
    byte_start: int
    byte_end_exclusive: int
    method: str
    observation: str

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_sha256, str) or not _is_sha256(self.artifact_sha256):
            raise ValueError("artifact_sha256 must be a 64-character hexadecimal digest")
        if (
            not isinstance(self.byte_start, int)
            or isinstance(self.byte_start, bool)
            or self.byte_start < 0
        ):
            raise ValueError("byte_start must be a non-negative integer")
        if (
            not isinstance(self.byte_end_exclusive, int)
            or isinstance(self.byte_end_exclusive, bool)
            or self.byte_end_exclusive < self.byte_start
        ):
            raise ValueError("byte_end_exclusive must not be less than byte_start")
        if not isinstance(self.method, str) or not self.method.strip():
            raise ValueError("method must not be empty")
        if not isinstance(self.observation, str) or not self.observation.strip():
            raise ValueError("observation must not be empty")


@dataclass(frozen=True)
class EvidenceRecord:
    """Provenance and acquisition boundary for one local source file."""

    source_path: Path
    size_bytes: int
    sha256: str
    acquired_at: str
    acquisition_method: str = "bounded_local_read"
    recovery_status: RecoveryStatus = RecoveryStatus.NOT_ATTEMPTED

    def __post_init__(self) -> None:
        if not isinstance(self.source_path, Path):
            raise TypeError("source_path must be a pathlib.Path")
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise TypeError("size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")
        if not isinstance(self.sha256, str) or not _is_sha256(self.sha256):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        _validate_utc_timestamp(self.acquired_at, "acquired_at")
        if not isinstance(self.acquisition_method, str) or not self.acquisition_method.strip():
            raise ValueError("acquisition_method must not be empty")
        if not isinstance(self.recovery_status, RecoveryStatus):
            raise TypeError("recovery_status must be a RecoveryStatus")


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
class DirectoryRequest:
    """A request to inventory a caller-selected local directory."""

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
    provenance: EvidenceReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.title, str):
            raise TypeError("title must be a string")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")
        if self.evidence is not None and not isinstance(self.evidence, str):
            raise TypeError("evidence must be a string or None")
        if self.provenance is not None and not isinstance(self.provenance, EvidenceReference):
            raise TypeError("provenance must be an EvidenceReference or None")
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.description.strip():
            raise ValueError("description must not be empty")


@dataclass(frozen=True)
class EngineResult:
    """Status and findings produced by one analysis engine."""

    engine_id: str
    status: EngineStatus
    summary: str
    findings: tuple[Finding, ...] = ()
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.engine_id, str) or not self.engine_id.strip():
            raise ValueError("engine_id must not be empty")
        if not isinstance(self.status, EngineStatus):
            raise TypeError("status must be an EngineStatus")
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("summary must not be empty")
        if not isinstance(self.findings, tuple):
            raise TypeError("findings must be a tuple")
        if any(not isinstance(finding, Finding) for finding in self.findings):
            raise TypeError("findings must contain only Finding instances")
        if self.status is EngineStatus.FAILED:
            if not isinstance(self.error, str) or not self.error.strip():
                raise ValueError("failed engine results require an error")
        elif self.error is not None:
            raise ValueError("completed engine results must not contain an error")


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


@dataclass(frozen=True)
class AnalysisJobReport:
    """Serializable result of one bounded, local analysis job."""

    job_id: str
    created_at: str
    evidence: EvidenceRecord
    engine_results: tuple[EngineResult, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.job_id, str) or not self.job_id.strip():
            raise ValueError("job_id must not be empty")
        _validate_utc_timestamp(self.created_at, "created_at")
        if not isinstance(self.evidence, EvidenceRecord):
            raise TypeError("evidence must be an EvidenceRecord")
        if not isinstance(self.engine_results, tuple):
            raise TypeError("engine_results must be a tuple")
        if any(not isinstance(result, EngineResult) for result in self.engine_results):
            raise TypeError("engine_results must contain only EngineResult instances")
        for result in self.engine_results:
            for finding in result.findings:
                reference = finding.provenance
                if reference is not None and (
                    reference.artifact_sha256 != self.evidence.sha256
                    or reference.byte_end_exclusive > self.evidence.size_bytes
                ):
                    raise ValueError("finding provenance must reference this evidence record")

    def to_dict(self) -> dict[str, object]:
        findings = [
            _finding_to_dict(finding)
            for result in self.engine_results
            for finding in result.findings
        ]
        return {
            "schema_version": 2,
            "job": {"id": self.job_id, "created_at": self.created_at, "type": self.report_kind},
            "evidence": {
                "kind": "local_file",
                "path": str(self.evidence.source_path),
                "size_bytes": self.evidence.size_bytes,
                "sha256": self.evidence.sha256,
                "acquired_at": self.evidence.acquired_at,
                "acquisition_method": self.evidence.acquisition_method,
                "authorization_declared": True,
                "recovery_status": self.evidence.recovery_status.value,
            },
            "engines": [
                {
                    "id": result.engine_id,
                    "status": result.status.value,
                    "summary": result.summary,
                    "error": result.error,
                }
                for result in self.engine_results
            ],
            "findings": findings,
        }

    @property
    def report_kind(self) -> str:
        return "file"

    @property
    def source_path(self) -> Path:
        return self.evidence.source_path

    @property
    def sha256(self) -> str:
        return self.evidence.sha256


@dataclass(frozen=True)
class DirectoryAnalysisItem:
    """One bounded inventory result; symlinks are recorded but never followed."""

    relative_path: str
    kind: DirectoryEntryKind
    status: DirectoryItemStatus
    size_bytes: int | None = None
    analysis: AnalysisJobReport | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.relative_path, str) or not self.relative_path.strip():
            raise ValueError("relative_path must not be empty")
        if Path(self.relative_path).is_absolute() or ".." in Path(self.relative_path).parts:
            raise ValueError("relative_path must remain beneath the analyzed root")
        if not isinstance(self.kind, DirectoryEntryKind):
            raise TypeError("kind must be a DirectoryEntryKind")
        if not isinstance(self.status, DirectoryItemStatus):
            raise TypeError("status must be a DirectoryItemStatus")
        if self.size_bytes is not None:
            if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
                raise TypeError("size_bytes must be an integer or None")
            if self.size_bytes < 0:
                raise ValueError("size_bytes must not be negative")
        if self.analysis is not None and not isinstance(self.analysis, AnalysisJobReport):
            raise TypeError("analysis must be an AnalysisJobReport or None")
        if self.detail is not None and not isinstance(self.detail, str):
            raise TypeError("detail must be a string or None")
        if self.status is DirectoryItemStatus.ANALYZED:
            if self.kind is not DirectoryEntryKind.REGULAR_FILE or self.analysis is None:
                raise ValueError("analyzed entries require a regular file report")
            if self.size_bytes != self.analysis.evidence.size_bytes:
                raise ValueError("analyzed entry size must match its evidence record")
        elif self.analysis is not None:
            raise ValueError("only analyzed entries may contain a file report")

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.relative_path,
            "kind": self.kind.value,
            "status": self.status.value,
            "size_bytes": self.size_bytes,
            "detail": self.detail,
            "analysis": self.analysis.to_dict() if self.analysis is not None else None,
        }


@dataclass(frozen=True)
class DirectoryAnalysisReport:
    """Bounded inventory and static analysis result for a local directory."""

    job_id: str
    created_at: str
    root_path: Path
    max_depth: int
    max_files: int
    max_entries: int
    max_total_bytes: int
    items: tuple[DirectoryAnalysisItem, ...]
    truncated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.job_id, str) or not self.job_id.strip():
            raise ValueError("job_id must not be empty")
        _validate_utc_timestamp(self.created_at, "created_at")
        if not isinstance(self.root_path, Path):
            raise TypeError("root_path must be a pathlib.Path")
        for field_name in ("max_depth", "max_files", "max_entries", "max_total_bytes"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{field_name} must be an integer")
            if value < 0:
                raise ValueError(f"{field_name} must not be negative")
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a tuple")
        if any(not isinstance(item, DirectoryAnalysisItem) for item in self.items):
            raise TypeError("items must contain only DirectoryAnalysisItem instances")
        if len(self.items) > self.max_entries:
            raise ValueError("items cannot exceed max_entries")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be a boolean")
        analyzed_items = [
            item for item in self.items if item.status is DirectoryItemStatus.ANALYZED
        ]
        if len(analyzed_items) > self.max_files:
            raise ValueError("analyzed items cannot exceed max_files")
        total_bytes = sum(item.size_bytes or 0 for item in analyzed_items)
        if total_bytes > self.max_total_bytes:
            raise ValueError("analyzed items cannot exceed max_total_bytes")

    @property
    def report_kind(self) -> str:
        return "directory"

    @property
    def source_path(self) -> Path:
        return self.root_path

    @property
    def sha256(self) -> None:
        return None

    @property
    def files_analyzed(self) -> int:
        return sum(item.status is DirectoryItemStatus.ANALYZED for item in self.items)

    @property
    def total_bytes_read(self) -> int:
        return sum(
            item.size_bytes or 0
            for item in self.items
            if item.status is DirectoryItemStatus.ANALYZED
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 3,
            "job": {
                "id": self.job_id,
                "created_at": self.created_at,
                "type": self.report_kind,
            },
            "source": {
                "kind": "local_directory",
                "path": str(self.root_path),
                "authorization_declared": True,
            },
            "limits": {
                "max_depth": self.max_depth,
                "max_files": self.max_files,
                "max_entries": self.max_entries,
                "max_total_bytes": self.max_total_bytes,
            },
            "summary": {
                "entries_recorded": len(self.items),
                "files_analyzed": self.files_analyzed,
                "total_bytes_read": self.total_bytes_read,
                "truncated": self.truncated,
            },
            "items": [item.to_dict() for item in self.items],
        }


def _finding_to_dict(finding: Finding) -> dict[str, object]:
    provenance: dict[str, object] | None = None
    if finding.provenance is not None:
        provenance = {
            "artifact_sha256": finding.provenance.artifact_sha256,
            "byte_start": finding.provenance.byte_start,
            "byte_end_exclusive": finding.provenance.byte_end_exclusive,
            "method": finding.provenance.method,
            "observation": finding.provenance.observation,
        }
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "evidence": finding.evidence,
        "provenance": provenance,
    }


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _validate_utc_timestamp(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp") from exc
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError(f"{field_name} must be in UTC")
