"""Bounded, read-only identification of caller-authorized local files."""

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .domain.contracts import AnalysisRequest

MAX_FILE_BYTES = 1_048_576
_READ_CHUNK_BYTES = 64 * 1024
_SIGNATURES = (
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x01\x02", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"PK\x07\x08", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"SQLite format 3\x00", "SQLite"),
)
_LIMITATIONS = (
    "Identification is limited to a small built-in set of signatures; an extension is only a hint.",
    "File contents are not parsed; archives are not listed, extracted, or decompressed.",
    "No binary analysis is performed.",
    "The source and report are not written by this tool; JSON is emitted to stdout and may be redirected by the caller.",
)


class LocalAnalysisError(Exception):
    """An expected refusal or failure while safely reading a local file."""


@dataclass(frozen=True)
class LocalFileAnalysis:
    """Metadata produced by bounded local-file identification."""

    source_path: Path
    size_bytes: int
    sha256: str
    format_name: str | None
    identification_method: Literal["signature", "filename_extension_only", "none"]
    extension_hint: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "source": {
                "kind": "local_file",
                "path": str(self.source_path),
                "size_bytes": self.size_bytes,
                "sha256": self.sha256,
                "authorization_declared": True,
            },
            "identification": {
                "format": self.format_name,
                "method": self.identification_method,
                "extension_hint": self.extension_hint,
            },
            "limitations": list(_LIMITATIONS),
        }


def analyze_local_file(request: AnalysisRequest) -> LocalFileAnalysis:
    """Read at most the configured limit, hash bytes, and inspect known signatures."""
    target = request.target
    if any(part == ".." for part in target.parts):
        raise LocalAnalysisError("Parent-directory components are not allowed in the target path.")

    try:
        source_path = Path(os.path.abspath(os.fspath(target)))
    except (OSError, TypeError, ValueError) as exc:
        raise LocalAnalysisError("The target path is invalid.") from exc

    prefix, size_bytes, digest = _read_file_safely(source_path)
    format_name = _identify_format(prefix)
    extension = source_path.suffix.lower() or None

    if format_name is not None:
        method: Literal["signature", "filename_extension_only", "none"] = "signature"
    elif extension is not None:
        method = "filename_extension_only"
    else:
        method = "none"

    return LocalFileAnalysis(
        source_path=source_path,
        size_bytes=size_bytes,
        sha256=digest,
        format_name=format_name,
        identification_method=method,
        extension_hint=extension,
    )


def _read_file_safely(path: Path) -> tuple[bytes, int, str]:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise LocalAnalysisError(
            "This platform does not support secure no-follow path traversal."
        )

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)

    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        if not path.name:
            raise LocalAnalysisError("The target must be a regular file.")
        file_fd = os.open(path.name, file_flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LocalAnalysisError("Symbolic links are not allowed in the target path.") from exc
        if exc.errno == errno.ENOTDIR:
            raise LocalAnalysisError(
                "The target path contains a symlink or a non-directory component."
            ) from exc
        raise LocalAnalysisError("The target could not be opened safely.") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)

    if file_fd is None:
        raise LocalAnalysisError("The target could not be opened safely.")

    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise LocalAnalysisError("Only regular files are accepted.")
        if before.st_size > MAX_FILE_BYTES:
            raise LocalAnalysisError(f"Files larger than {MAX_FILE_BYTES} bytes are not accepted.")

        digest = hashlib.sha256()
        prefix = bytearray()
        size_bytes = 0
        while size_bytes <= MAX_FILE_BYTES:
            block = os.read(
                file_fd,
                min(_READ_CHUNK_BYTES, MAX_FILE_BYTES + 1 - size_bytes),
            )
            if not block:
                break
            digest.update(block)
            if len(prefix) < 32:
                prefix.extend(block[: 32 - len(prefix)])
            size_bytes += len(block)
        if size_bytes > MAX_FILE_BYTES:
            raise LocalAnalysisError(f"Files larger than {MAX_FILE_BYTES} bytes are not accepted.")

        after = os.fstat(file_fd)
        before_state = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_state != after_state or size_bytes != after.st_size:
            raise LocalAnalysisError("The target changed while it was being read.")
        return bytes(prefix), size_bytes, digest.hexdigest()
    except OSError as exc:
        raise LocalAnalysisError("The target could not be read safely.") from exc
    finally:
        os.close(file_fd)


def _identify_format(prefix: bytes) -> str | None:
    for signature, format_name in _SIGNATURES:
        if prefix.startswith(signature):
            return format_name
    if len(prefix) >= 12 and prefix.startswith(b"RIFF"):
        if prefix[8:12] == b"WAVE":
            return "WAVE"
        if prefix[8:12] == b"WEBP":
            return "WebP"
    return None
