"""Local analysis orchestration and explicit engine registration."""

from datetime import datetime, timezone
from uuid import uuid4

from .domain.contracts import AnalysisJobReport, AnalysisRequest, EvidenceRecord
from .engines import SignatureEngine, StaticProfileEngine, TextEncodingEngine
from .local_analysis import (
    MAX_FILE_BYTES,
    LocalAnalysisError,
    LocalFileContent,
    read_local_file,
)
from .ports import AnalysisEngine, Analyzer


class EngineRegistry:
    """An immutable ordered set of engines selected by the application."""

    def __init__(self, engines: tuple[AnalysisEngine, ...]) -> None:
        if not isinstance(engines, tuple):
            raise TypeError("engines must be a tuple")
        if not engines:
            raise ValueError("at least one analysis engine must be registered")
        identifiers = [engine.engine_id for engine in engines]
        if any(not isinstance(identifier, str) or not identifier.strip() for identifier in identifiers):
            raise ValueError("engine identifiers must not be empty")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("engine identifiers must be unique")
        self._engines = engines

    @property
    def engines(self) -> tuple[AnalysisEngine, ...]:
        return self._engines


class AnalysisOrchestrator:
    """Acquire one bounded artifact and run the explicitly registered engines."""

    name = "local-static-analysis"

    def __init__(self, registry: EngineRegistry) -> None:
        self._registry = registry

    def analyze(self, request: AnalysisRequest) -> AnalysisJobReport:
        return self.analyze_loaded(read_local_file(request))

    def analyze_loaded(self, loaded: LocalFileContent) -> AnalysisJobReport:
        """Analyze bytes acquired by the safe local reader."""
        if not isinstance(loaded, LocalFileContent):
            raise TypeError("loaded must be a LocalFileContent")
        if loaded.size_bytes > MAX_FILE_BYTES:
            raise LocalAnalysisError("The acquired file exceeded the configured size limit.")
        created_at = datetime.now(timezone.utc).isoformat()
        evidence = EvidenceRecord(
            source_path=loaded.source_path,
            size_bytes=loaded.size_bytes,
            sha256=loaded.sha256,
            acquired_at=created_at,
        )
        engine_results = tuple(
            engine.analyze(evidence, loaded.content) for engine in self._registry.engines
        )
        return AnalysisJobReport(
            job_id=str(uuid4()),
            created_at=created_at,
            evidence=evidence,
            engine_results=engine_results,
        )


def create_default_analyzer() -> Analyzer:
    """Build the offline analyzer with the supported built-in engines."""
    return AnalysisOrchestrator(
        EngineRegistry(
            (SignatureEngine(), StaticProfileEngine(), TextEncodingEngine())
        )
    )
