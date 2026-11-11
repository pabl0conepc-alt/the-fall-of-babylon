"""Bounded no-follow inventory and static analysis of local directories."""

import errno
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .domain.contracts import (
    DirectoryAnalysisItem,
    DirectoryAnalysisReport,
    DirectoryEntryKind,
    DirectoryItemStatus,
    DirectoryRequest,
)
from .local_analysis import MAX_FILE_BYTES, LocalAnalysisError, read_local_file_at
from .orchestrator import AnalysisOrchestrator, create_default_analyzer

MAX_DIRECTORY_DEPTH = 3
MAX_DIRECTORY_FILES = 50
MAX_DIRECTORY_ENTRIES = 100
MAX_DIRECTORY_BYTES = 16 * 1024 * 1024


class DirectoryAnalysisError(Exception):
    """Expected refusal or root-directory traversal failure."""


@dataclass
class _TraversalState:
    items: list[DirectoryAnalysisItem] = field(default_factory=list)
    files_seen: int = 0
    bytes_read: int = 0
    truncated: bool = False
    stop: bool = False


def analyze_local_directory(
    request: DirectoryRequest,
    analyzer: AnalysisOrchestrator | None = None,
) -> DirectoryAnalysisReport:
    """Inventory a directory within strict depth, count, and byte ceilings."""
    target = request.target
    if any(part == ".." for part in target.parts):
        raise DirectoryAnalysisError("Parent-directory components are not allowed in the target path.")
    try:
        root_path = Path(os.path.abspath(os.fspath(target)))
    except (OSError, TypeError, ValueError) as exc:
        raise DirectoryAnalysisError("The target directory path is invalid.") from exc

    root_fd = _open_directory_safely(root_path)
    engine = analyzer or create_default_analyzer()
    state = _TraversalState()
    try:
        scanned = _walk_directory(
            root_fd,
            root_path,
            Path(),
            0,
            engine,
            state,
        )
    finally:
        os.close(root_fd)
    if not scanned:
        raise DirectoryAnalysisError("The target directory could not be enumerated safely.")

    return DirectoryAnalysisReport(
        job_id=str(uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(),
        root_path=root_path,
        max_depth=MAX_DIRECTORY_DEPTH,
        max_files=MAX_DIRECTORY_FILES,
        max_entries=MAX_DIRECTORY_ENTRIES,
        max_total_bytes=MAX_DIRECTORY_BYTES,
        items=tuple(state.items),
        truncated=state.truncated,
    )


def _open_directory_safely(path: Path) -> int:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.scandir not in getattr(os, "supports_fd", set())
    ):
        raise DirectoryAnalysisError(
            "This platform does not support secure no-follow directory traversal."
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    try:
        directory_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            os.close(directory_fd)
            directory_fd = None
            raise DirectoryAnalysisError("The target must be a local directory.")
        return directory_fd
    except OSError as exc:
        if directory_fd is not None:
            os.close(directory_fd)
        if exc.errno == errno.ELOOP:
            raise DirectoryAnalysisError("Symbolic links are not allowed in the target path.") from exc
        raise DirectoryAnalysisError("The target directory could not be opened safely.") from exc


def _walk_directory(
    directory_fd: int,
    absolute_path: Path,
    relative_directory: Path,
    depth: int,
    analyzer: AnalysisOrchestrator,
    state: _TraversalState,
) -> bool:
    duplicate_fd = os.dup(directory_fd)
    try:
        iterator = os.scandir(duplicate_fd)
    except OSError:
        os.close(duplicate_fd)
        return False

    with iterator:
        try:
            for entry in iterator:
                if len(state.items) >= MAX_DIRECTORY_ENTRIES:
                    state.truncated = True
                    state.stop = True
                    return True
                relative_path = relative_directory / entry.name
                item_path = relative_path.as_posix()
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    state.items.append(
                        DirectoryAnalysisItem(
                            item_path,
                            DirectoryEntryKind.UNKNOWN,
                            DirectoryItemStatus.REJECTED_UNREADABLE,
                        )
                    )
                    continue

                mode = metadata.st_mode
                if stat.S_ISLNK(mode):
                    state.items.append(
                        DirectoryAnalysisItem(
                            item_path,
                            DirectoryEntryKind.SYMLINK,
                            DirectoryItemStatus.REJECTED_SYMLINK,
                        )
                    )
                elif stat.S_ISDIR(mode):
                    _process_directory(
                        entry.name,
                        absolute_path / entry.name,
                        relative_path,
                        depth,
                        directory_fd,
                        analyzer,
                        state,
                        item_path,
                    )
                elif stat.S_ISREG(mode):
                    _process_file(
                        directory_fd,
                        entry.name,
                        absolute_path / entry.name,
                        item_path,
                        metadata.st_size,
                        analyzer,
                        state,
                    )
                else:
                    state.items.append(
                        DirectoryAnalysisItem(
                            item_path,
                            DirectoryEntryKind.SPECIAL,
                            DirectoryItemStatus.REJECTED_SPECIAL,
                        )
                    )
                if state.stop:
                    return True
            return True
        except OSError:
            state.truncated = True
            return False
        finally:
            os.close(duplicate_fd)


def _process_directory(
    name: str,
    absolute_path: Path,
    relative_path: Path,
    depth: int,
    parent_fd: int,
    analyzer: AnalysisOrchestrator,
    state: _TraversalState,
    item_path: str,
) -> None:
    if depth >= MAX_DIRECTORY_DEPTH:
        state.truncated = True
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.DIRECTORY,
                DirectoryItemStatus.SKIPPED_DEPTH_LIMIT,
            )
        )
        return

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.DIRECTORY,
                DirectoryItemStatus.REJECTED_UNREADABLE,
            )
        )
        return

    item_index = len(state.items)
    state.items.append(
        DirectoryAnalysisItem(
            item_path,
            DirectoryEntryKind.DIRECTORY,
            DirectoryItemStatus.DIRECTORY_TRAVERSED,
        )
    )
    try:
        if not _walk_directory(
            child_fd,
            absolute_path,
            relative_path,
            depth + 1,
            analyzer,
            state,
        ):
            state.items[item_index] = DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.DIRECTORY,
                DirectoryItemStatus.REJECTED_UNREADABLE,
            )
    finally:
        os.close(child_fd)


def _process_file(
    parent_fd: int,
    filename: str,
    absolute_path: Path,
    item_path: str,
    size_bytes: int,
    analyzer: AnalysisOrchestrator,
    state: _TraversalState,
) -> None:
    state.files_seen += 1
    if state.files_seen > MAX_DIRECTORY_FILES:
        state.truncated = True
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.REGULAR_FILE,
                DirectoryItemStatus.SKIPPED_FILE_LIMIT,
                size_bytes,
            )
        )
        return
    if size_bytes > MAX_FILE_BYTES:
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.REGULAR_FILE,
                DirectoryItemStatus.REJECTED_FILE_TOO_LARGE,
                size_bytes,
            )
        )
        return

    remaining_bytes = MAX_DIRECTORY_BYTES - state.bytes_read
    if size_bytes > remaining_bytes:
        state.truncated = True
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.REGULAR_FILE,
                DirectoryItemStatus.SKIPPED_TOTAL_BYTES_LIMIT,
                size_bytes,
            )
        )
        return

    try:
        loaded = read_local_file_at(
            parent_fd,
            filename,
            absolute_path,
            max_bytes=min(MAX_FILE_BYTES, remaining_bytes),
        )
    except LocalAnalysisError:
        status = (
            DirectoryItemStatus.SKIPPED_TOTAL_BYTES_LIMIT
            if remaining_bytes == 0 and size_bytes > 0
            else DirectoryItemStatus.REJECTED_UNREADABLE
        )
        if status is DirectoryItemStatus.SKIPPED_TOTAL_BYTES_LIMIT:
            state.truncated = True
        state.items.append(
            DirectoryAnalysisItem(
                item_path,
                DirectoryEntryKind.REGULAR_FILE,
                status,
                size_bytes,
            )
        )
        return

    analysis = analyzer.analyze_loaded(loaded)
    state.bytes_read += loaded.size_bytes
    state.items.append(
        DirectoryAnalysisItem(
            item_path,
            DirectoryEntryKind.REGULAR_FILE,
            DirectoryItemStatus.ANALYZED,
            loaded.size_bytes,
            analysis,
        )
    )
