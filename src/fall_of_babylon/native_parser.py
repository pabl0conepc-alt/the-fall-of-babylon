"""Bounded subprocess adapter for the native structural format parser."""

import json
import re
import subprocess
import sys
from pathlib import Path

from .domain.contracts import (
    EngineResult,
    EngineStatus,
    EvidenceRecord,
    EvidenceReference,
    Finding,
    Severity,
)
from .local_analysis import MAX_FILE_BYTES

_ENGINE_ID = "native-structural-format"
_MAX_RESPONSE_BYTES = 4096
_TIMEOUT_SECONDS = 3
_FORMATS = {"PE", "ELF", "Mach-O", "unknown"}
_STATUSES = {"valid", "truncated", "malformed", "unsupported"}
_ERROR_CODE = re.compile(r"[a-z0-9_]{1,64}\Z")
_FIELDS = {
    "status",
    "format",
    "error",
    "endian",
    "bits",
    "machine",
    "object_type",
    "header_size",
    "entry_point",
    "table_count",
    "table_bytes",
    "aux_count",
    "aux_bytes",
    "slices",
}


class NativeFormatEngine:
    """Parse bounded PE/ELF/Mach-O structure in a bundled helper process."""

    engine_id = _ENGINE_ID

    def analyze(self, evidence: EvidenceRecord, content: bytes) -> EngineResult:
        if len(content) > MAX_FILE_BYTES:
            return self._failed("The input exceeded the configured 1 MiB limit.")
        executable = _helper_path()
        if not executable.is_file():
            return self._failed("The native parser helper is not installed.")
        try:
            completed = subprocess.run(
                [str(executable)],
                input=content,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._failed("The native parser helper exceeded its time limit.")
        except OSError:
            return self._failed("The native parser helper could not be started.")

        if completed.returncode != 0:
            return self._failed(
                f"The native parser helper exited with status {completed.returncode}."
            )
        if len(completed.stdout) > _MAX_RESPONSE_BYTES:
            return self._failed("The native parser helper returned an oversized response.")
        if completed.stderr:
            return self._failed("The native parser helper returned unexpected diagnostics.")
        try:
            parsed = _validate_response(json.loads(completed.stdout))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return self._failed("The native parser helper returned an invalid response.")

        if parsed["format"] == "unknown":
            return EngineResult(
                self.engine_id,
                EngineStatus.COMPLETED,
                "No supported executable structure was detected.",
            )

        observation = _format_observation(parsed)
        finding = Finding(
            title=f"{parsed['format']} structural metadata",
            severity=Severity.INFO,
            description=(
                "Bounded structural metadata and parse status only; this is not "
                "a safety verdict."
            ),
            evidence=observation,
            provenance=EvidenceReference(
                evidence.sha256,
                0,
                len(content),
                "bounded-native-structural-parse",
                observation,
            ),
        )
        return EngineResult(
            self.engine_id,
            EngineStatus.COMPLETED,
            f"{parsed['format']} structural parse: {parsed['status']}.",
            (finding,),
        )

    def _failed(self, message: str) -> EngineResult:
        return EngineResult(
            self.engine_id,
            EngineStatus.FAILED,
            "The native structural parser did not complete.",
            error=message,
        )


def _helper_path() -> Path:
    executable_name = (
        "babylon-format-parser.exe" if sys.platform == "win32" else "babylon-format-parser"
    )
    bundle_root = getattr(sys, "_MEIPASS", None)
    if isinstance(bundle_root, str):
        return Path(bundle_root) / "native" / executable_name
    repository_root = Path(__file__).resolve().parents[2]
    return repository_root / "build" / "native" / executable_name


def _validate_response(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _FIELDS:
        raise ValueError("unexpected response fields")
    if payload["status"] not in _STATUSES or payload["format"] not in _FORMATS:
        raise ValueError("unsupported parse state")
    if payload["endian"] not in ("", "little", "big"):
        raise ValueError("invalid endianness")
    error = payload["error"]
    if error is not None and (
        not isinstance(error, str) or _ERROR_CODE.fullmatch(error) is None
    ):
        raise ValueError("invalid parse error code")
    if payload["status"] == "valid" and error is not None:
        raise ValueError("valid results must not contain errors")
    if payload["status"] != "valid" and error is None:
        raise ValueError("non-valid results require an error code")

    limits = {
        "bits": 64,
        "machine": (1 << 64) - 1,
        "object_type": (1 << 32) - 1,
        "header_size": MAX_FILE_BYTES,
        "entry_point": (1 << 64) - 1,
        "table_count": 8192,
        "table_bytes": MAX_FILE_BYTES,
        "aux_count": 8192,
        "aux_bytes": MAX_FILE_BYTES,
        "slices": 64,
    }
    for field, maximum in limits.items():
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
            raise ValueError(f"invalid {field}")
    if payload["bits"] not in (0, 32, 64):
        raise ValueError("invalid bitness")
    if payload["format"] == "unknown" and payload["status"] != "unsupported":
        raise ValueError("unknown formats must be unsupported")
    return payload


def _format_observation(parsed: dict[str, object]) -> str:
    fields = [
        f"format={parsed['format']}",
        f"parse_status={parsed['status']}",
    ]
    if parsed["error"] is not None:
        fields.append(f"parse_error={parsed['error']}")
    if parsed["bits"]:
        fields.append(f"bits={parsed['bits']}")
    if parsed["endian"]:
        fields.append(f"endianness={parsed['endian']}")
    fields.extend(
        [
            f"machine=0x{parsed['machine']:x}",
            f"object_type=0x{parsed['object_type']:x}",
            f"header_bytes={parsed['header_size']}",
            f"entry_point=0x{parsed['entry_point']:x}",
            f"table_count={parsed['table_count']}",
            f"table_bytes={parsed['table_bytes']}",
            f"aux_count={parsed['aux_count']}",
            f"aux_bytes={parsed['aux_bytes']}",
            f"slice_count={parsed['slices']}",
        ]
    )
    return "; ".join(fields)
