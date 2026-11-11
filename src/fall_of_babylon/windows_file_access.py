"""Handle-relative Windows file access that refuses reparse-point traversal."""

import ctypes
import os
from pathlib import Path

from .local_analysis import LocalAnalysisError, _read_open_file


def read_windows_file(path: Path, max_bytes: int) -> tuple[bytes, str]:
    if os.name != "nt":
        raise LocalAnalysisError("Windows handle access is unavailable on this platform.")
    if not path.drive or path.drive.startswith("\\\\"):
        raise LocalAnalysisError("Only local drive paths are accepted on Windows.")

    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_void_p),
            ("Information", ctypes.c_size_t),
        ]

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", FileTime),
            ("access_time", FileTime),
            ("write_time", FileTime),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    ntdll.NtCreateFile.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    )
    ntdll.NtCreateFile.restype = wintypes.LONG
    ntdll.RtlNtStatusToDosError.argtypes = (wintypes.LONG,)
    ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG

    invalid_handle = ctypes.c_void_p(-1).value
    file_attribute_directory = 0x10
    file_attribute_device = 0x40
    file_attribute_reparse_point = 0x400
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    open_existing = 3
    generic_read = 0x80000000
    file_read_data = 0x0001
    file_list_directory = 0x0001
    file_traverse = 0x0020
    file_read_attributes = 0x0080
    synchronize = 0x00100000
    file_share_read = 0x0001
    file_share_all = 0x0007
    file_open = 1
    file_directory_file = 0x00000001
    file_non_directory_file = 0x00000040
    file_synchronous_io_nonalert = 0x00000020
    file_open_reparse_point = 0x00200000
    object_case_insensitive = 0x00000040
    object_dont_reparse = 0x00001000
    status_reparse_point_encountered = 0xC000050B
    handles: list[int] = []
    file_fd: int | None = None

    def file_info(handle: int) -> ByHandleFileInformation:
        info = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise LocalAnalysisError("The target could not be inspected safely.")
        return info

    def verify_handle(handle: int, directory: bool) -> None:
        attributes = file_info(handle).attributes
        if attributes & file_attribute_reparse_point:
            raise LocalAnalysisError("Reparse points are not allowed in the target path.")
        if not directory and attributes & file_attribute_device:
            raise LocalAnalysisError("Only regular files are accepted.")
        if bool(attributes & file_attribute_directory) != directory:
            raise LocalAnalysisError(
                "The target path contains an unexpected file or directory component."
            )

    def open_relative(parent: int, name: str, directory: bool) -> int:
        encoded_name = ctypes.create_unicode_buffer(name)
        name_bytes = len(name.encode("utf-16-le"))
        unicode_name = UnicodeString(
            name_bytes,
            name_bytes + 2,
            ctypes.cast(encoded_name, wintypes.LPWSTR),
        )
        object_name = ObjectAttributes(
            ctypes.sizeof(ObjectAttributes),
            parent,
            ctypes.pointer(unicode_name),
            object_case_insensitive | object_dont_reparse,
            None,
            None,
        )
        io_status = IoStatusBlock()
        output_handle = wintypes.HANDLE()
        options = file_open_reparse_point | file_synchronous_io_nonalert
        options |= file_directory_file if directory else file_non_directory_file
        access = file_read_attributes | synchronize
        access |= file_list_directory | file_traverse if directory else file_read_data
        status = ntdll.NtCreateFile(
            ctypes.byref(output_handle),
            access,
            ctypes.byref(object_name),
            ctypes.byref(io_status),
            None,
            0,
            file_share_all if directory else file_share_read,
            file_open,
            options,
            None,
            0,
        )
        if status < 0:
            if status & 0xFFFFFFFF == status_reparse_point_encountered:
                raise LocalAnalysisError(
                    "Reparse points are not allowed in the target path."
                )
            error = ntdll.RtlNtStatusToDosError(status)
            raise OSError(error, "The target could not be opened safely.")
        if output_handle.value is None:
            raise LocalAnalysisError("The target handle could not be opened safely.")
        handle_value = int(output_handle.value)
        try:
            verify_handle(handle_value, directory)
        except LocalAnalysisError:
            kernel32.CloseHandle(handle_value)
            raise
        return handle_value

    root = kernel32.CreateFileW(
        str(path.anchor),
        generic_read,
        file_share_all,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    raw_root = getattr(root, "value", root)
    root_value_raw = None if raw_root is None else ctypes.c_void_p(raw_root).value
    if root_value_raw in (None, invalid_handle):
        raise LocalAnalysisError("The target root could not be opened safely.")
    root_value = int(root_value_raw)
    handles.append(root_value)
    try:
        verify_handle(root_value, directory=True)
        parent = root_value
        for component in path.parts[1:-1]:
            if (
                component in ("", ".", "..")
                or "\\" in component
                or "/" in component
                or ":" in component
            ):
                raise LocalAnalysisError("The target path is invalid.")
            parent = open_relative(parent, component, directory=True)
            handles.append(parent)
        if (
            not path.name
            or path.name in (".", "..")
            or "\\" in path.name
            or "/" in path.name
            or ":" in path.name
        ):
            raise LocalAnalysisError("The target must be a regular file.")
        file_handle = open_relative(parent, path.name, directory=False)
        try:
            file_fd = msvcrt.open_osfhandle(
                file_handle,
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
        except OSError:
            kernel32.CloseHandle(file_handle)
            raise
        return _read_open_file(file_fd, max_bytes)
    except OSError as exc:
        raise LocalAnalysisError("The target could not be opened or read safely.") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)
