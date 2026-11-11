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
    "This lightweight identification result does not include structural parsing; the full analysis pipeline parses bounded PE, ELF, and Mach-O metadata.",
    "Archives are not listed, extracted, or decompressed; executable code is not disassembled or executed.",
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


@dataclass(frozen=True)
class LocalFileContent:
    """Bytes and digest from one safely opened local regular file."""

    source_path: Path
    content: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.content)


def analyze_local_file(request: AnalysisRequest) -> LocalFileAnalysis:
    """Read at most the configured limit, hash bytes, and inspect known signatures."""
    loaded = read_local_file(request)
    format_name = identify_format(loaded.content)
    extension = loaded.source_path.suffix.lower() or None

    if format_name is not None:
        method: Literal["signature", "filename_extension_only", "none"] = "signature"
    elif extension is not None:
        method = "filename_extension_only"
    else:
        method = "none"

    return LocalFileAnalysis(
        source_path=loaded.source_path,
        size_bytes=loaded.size_bytes,
        sha256=loaded.sha256,
        format_name=format_name,
        identification_method=method,
        extension_hint=extension,
    )


def read_local_file(
    request: AnalysisRequest,
    max_bytes: int = MAX_FILE_BYTES,
) -> LocalFileContent:
    """Acquire one file with no-follow traversal and a strict size bound."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be an integer")
    if not 0 <= max_bytes <= MAX_FILE_BYTES:
        raise ValueError(f"max_bytes must be between 0 and {MAX_FILE_BYTES}")
    target = request.target
    if any(part == ".." for part in target.parts):
        raise LocalAnalysisError("Parent-directory components are not allowed in the target path.")

    try:
        source_path = Path(os.path.abspath(os.fspath(target)))
    except (OSError, TypeError, ValueError) as exc:
        raise LocalAnalysisError("The target path is invalid.") from exc

    content, digest = _read_file_safely(source_path, max_bytes)
    return LocalFileContent(source_path, content, digest)


def read_local_file_at(
    directory_fd: int,
    filename: str,
    source_path: Path,
    max_bytes: int = MAX_FILE_BYTES,
) -> LocalFileContent:
    """Read one entry relative to an already-open directory without path re-resolution."""
    _validate_max_bytes(max_bytes)
    if os.name == "nt":
        raise LocalAnalysisError(
            "Secure descriptor-relative directory reads are unavailable on Windows."
        )
    if not isinstance(directory_fd, int) or isinstance(directory_fd, bool):
        raise TypeError("directory_fd must be an integer file descriptor")
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")
    if (
        not filename
        or filename in (".", "..")
        or os.sep in filename
        or (os.altsep is not None and os.altsep in filename)
    ):
        raise ValueError("filename must be a single path component")
    if not isinstance(source_path, Path) or not source_path.is_absolute():
        raise TypeError("source_path must be an absolute pathlib.Path")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        raise LocalAnalysisError(
            "This platform does not support secure no-follow file access."
        )

    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise LocalAnalysisError("The containing descriptor is not a directory.")
        file_fd = os.open(filename, file_flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LocalAnalysisError("Symbolic links are not allowed in the target path.") from exc
        raise LocalAnalysisError("The target could not be opened safely.") from exc
    try:
        content, digest = _read_open_file(file_fd, max_bytes)
    finally:
        os.close(file_fd)
    return LocalFileContent(source_path, content, digest)


def _read_file_safely(path: Path, max_bytes: int) -> tuple[bytes, str]:
    if os.name == "nt":
        from .windows_file_access import read_windows_file

        return read_windows_file(path, max_bytes)
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
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        file_flags |= getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(path.name, file_flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LocalAnalysisError("Symbolic links are not allowed in the target path.") from exc
        if exc.errno == errno.ENOTDIR:
            raise LocalAnalysisError(
                "The target path contains a symlink or a non-directory component."
            ) from exc
        raise LocalAnalysisError("The target could not be opened safely.") from exc
    except ValueError as exc:
        raise LocalAnalysisError("The target path is invalid.") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)

    if file_fd is None:
        raise LocalAnalysisError("The target could not be opened safely.")

    try:
        return _read_open_file(file_fd, max_bytes)
    finally:
        os.close(file_fd)


def _read_open_file(file_fd: int, max_bytes: int) -> tuple[bytes, str]:
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise LocalAnalysisError("Only regular files are accepted.")
        if before.st_size > max_bytes:
            raise LocalAnalysisError(f"Files larger than {max_bytes} bytes are not accepted.")

        digest = hashlib.sha256()
        content = bytearray()
        while len(content) <= max_bytes:
            block = os.read(
                file_fd,
                min(_READ_CHUNK_BYTES, max_bytes + 1 - len(content)),
            )
            if not block:
                break
            digest.update(block)
            content.extend(block)
        if len(content) > max_bytes:
            raise LocalAnalysisError(f"Files larger than {max_bytes} bytes are not accepted.")

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
        if before_state != after_state or len(content) != after.st_size:
            raise LocalAnalysisError("The target changed while it was being read.")
        return bytes(content), digest.hexdigest()
    except OSError as exc:
        raise LocalAnalysisError("The target could not be read safely.") from exc


def _validate_max_bytes(max_bytes: int) -> None:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be an integer")
    if not 0 <= max_bytes <= MAX_FILE_BYTES:
        raise ValueError(f"max_bytes must be between 0 and {MAX_FILE_BYTES}")


def identify_format(prefix: bytes) -> str | None:
    """Recognize documented file families from bounded header bytes only."""
    return identify_format_with_range(prefix)[0]


def identify_format_with_range(content: bytes) -> tuple[str | None, int]:
    """Return a recognized family and exclusive end of the bytes supporting it."""
    for signature, format_name in _SIGNATURES:
        if content.startswith(signature):
            return format_name, len(signature)
    if content.startswith(b"MZ") and len(content) >= 64:
        pe_offset = int.from_bytes(content[0x3C:0x40], "little")
        if pe_offset <= len(content) - 4 and content[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            return "PE", pe_offset + 4
    if content.startswith(b"\x7fELF"):
        return "ELF", 4
    if content.startswith(
        (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    ):
        return "Mach-O", 4
    if len(content) >= 12 and content.startswith(b"RIFF"):
        if content[8:12] == b"WAVE":
            return "WAVE", 12
        if content[8:12] == b"WEBP":
            return "WebP", 12
    return None, 0
