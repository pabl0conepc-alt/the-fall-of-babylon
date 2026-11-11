"""Built-in deterministic engines for bounded static inspection."""

import codecs
from collections import Counter
from math import log2

from .domain.contracts import (
    EngineResult,
    EngineStatus,
    EvidenceRecord,
    EvidenceReference,
    Finding,
    Severity,
)
from .local_analysis import identify_format_with_range
from .ports import AnalysisEngine

_TEXT_BOMS = (
    (b"\x00\x00\xfe\xff", "UTF-32 BE BOM", "utf-32"),
    (b"\xff\xfe\x00\x00", "UTF-32 LE BOM", "utf-32"),
    (b"\xef\xbb\xbf", "UTF-8 BOM", "utf-8-sig"),
    (b"\xfe\xff", "UTF-16 BE BOM", "utf-16"),
    (b"\xff\xfe", "UTF-16 LE BOM", "utf-16"),
)


class SignatureEngine:
    """Identify a limited set of file families from their leading bytes."""

    engine_id = "signature-identification"

    def analyze(self, evidence: EvidenceRecord, content: bytes) -> EngineResult:
        format_name, evidence_end = identify_format_with_range(content)
        extension = evidence.source_path.suffix.lower() or None
        if format_name is None:
            summary = "No supported signature was found."
            if extension:
                summary += f" Filename extension {extension!r} is only a hint."
            return EngineResult(self.engine_id, EngineStatus.COMPLETED, summary)

        extension_note = (
            f" Filename extension {extension!r} is only a hint."
            if extension
            else " No filename extension was provided."
        )
        reference = EvidenceReference(
            evidence.sha256,
            0,
            evidence_end,
            "bounded-header-signature",
            f"Matched the built-in {format_name} signature family.",
        )
        finding = Finding(
            title="File signature identified",
            severity=Severity.INFO,
            description=f"Bounded header bytes match the {format_name} signature family.",
            evidence=format_name,
            provenance=reference,
        )
        return EngineResult(
            self.engine_id,
            EngineStatus.COMPLETED,
            f"Identified the {format_name} signature family.{extension_note}",
            (finding,),
        )


class TextEncodingEngine:
    """Validate a likely text encoding incrementally without emitting file contents."""

    engine_id = "text-encoding-profile"

    def analyze(self, evidence: EvidenceRecord, content: bytes) -> EngineResult:
        bom = "none"
        codec = "utf-8"
        for marker, label, codec_name in _TEXT_BOMS:
            if content.startswith(marker):
                bom = label
                codec = codec_name
                break

        valid = True
        decoder = codecs.getincrementaldecoder(codec)(errors="strict")
        try:
            chunk_size = 64 * 1024
            for start in range(0, max(1, len(content)), chunk_size):
                end = min(start + chunk_size, len(content))
                decoder.decode(content[start:end], final=end == len(content))
        except UnicodeDecodeError:
            valid = False

        observation = (
            f"encoding_hint={codec}; bom={bom}; strict_decode="
            f"{'valid' if valid else 'invalid'}"
        )
        finding = Finding(
            title="Text encoding profile",
            severity=Severity.INFO,
            description=(
                "A strict streaming decoder checked the byte sequence. "
                "A valid encoding does not establish that the artifact is a text file."
            ),
            evidence=observation,
            provenance=EvidenceReference(
                evidence.sha256,
                0,
                len(content),
                "streaming-text-encoding-validation",
                observation,
            ),
        )
        return EngineResult(
            self.engine_id,
            EngineStatus.COMPLETED,
            observation,
            (finding,),
        )


class StaticProfileEngine:
    """Calculate bounded descriptive byte statistics without parsing content."""

    engine_id = "byte-profile"

    def analyze(self, evidence: EvidenceRecord, content: bytes) -> EngineResult:
        size = len(content)
        counts = Counter(content)
        entropy = 0.0
        if size:
            entropy = -sum(
                (count / size) * log2(count / size)
                for count in counts.values()
            )
        printable = sum(32 <= value <= 126 for value in content)
        null_bytes = counts.get(0, 0)
        observation = (
            f"size_bytes={size}; shannon_entropy_bits_per_byte={entropy:.4f}; "
            f"printable_ascii_bytes={printable}; null_bytes={null_bytes}"
        )
        finding = Finding(
            title="Bounded byte profile",
            severity=Severity.INFO,
            description=(
                "Descriptive statistics over the complete acquired byte sequence; "
                "these values are not a malware verdict."
            ),
            evidence=observation,
            provenance=EvidenceReference(
                evidence.sha256,
                0,
                size,
                "byte-frequency-profile",
                observation,
            ),
        )
        return EngineResult(
            self.engine_id,
            EngineStatus.COMPLETED,
            "Calculated byte-frequency, printable-byte, and null-byte statistics.",
            (finding,),
        )
