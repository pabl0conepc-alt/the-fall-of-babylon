"""Smoke-test an installed Babylon command and its bundled local UI."""

import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def _put16(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 2] = value.to_bytes(2, "little")


def _put32(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _put64(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 8] = value.to_bytes(8, "little")


def _format_fixtures() -> dict[str, bytes]:
    pe = bytearray(368)
    pe[:2] = b"MZ"
    _put32(pe, 0x3C, 64)
    pe[64:68] = b"PE\0\0"
    _put16(pe, 68, 0x8664)
    _put16(pe, 70, 1)
    _put16(pe, 84, 240)
    _put16(pe, 86, 2)
    _put16(pe, 88, 0x20B)
    _put32(pe, 104, 0x1000)

    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    _put16(elf, 16, 2)
    _put16(elf, 18, 62)
    _put32(elf, 20, 1)
    _put64(elf, 24, 0x400000)
    _put16(elf, 52, 64)

    macho = bytearray(32)
    macho[:4] = b"\xcf\xfa\xed\xfe"
    _put32(macho, 4, 0x01000007)
    _put32(macho, 12, 2)
    return {"PE": bytes(pe), "ELF": bytes(elf), "Mach-O": bytes(macho)}


def _smoke_test_format_parser(executable: str) -> None:
    with tempfile.TemporaryDirectory(prefix="babylon-native-smoke-") as directory:
        for format_name, content in _format_fixtures().items():
            path = Path(directory) / f"synthetic-{format_name.lower().replace('-', '')}.bin"
            path.write_bytes(content)
            result = subprocess.run(
                [
                    executable,
                    "analyze",
                    str(path),
                    "--authorization-basis",
                    "owned synthetic packaging fixture",
                    "--format",
                    "json",
                ],
                capture_output=True,
                check=True,
                text=True,
                timeout=15,
            )
            report = json.loads(result.stdout)
            engine = next(
                item
                for item in report["engines"]
                if item["id"] == "native-structural-format"
            )
            if engine["status"] != "completed":
                raise SystemExit(f"native parser failed on {format_name}: {engine['error']}")
            observation = next(
                finding["evidence"]
                for finding in report["findings"]
                if finding["title"] == f"{format_name} structural metadata"
            )
            if "parse_status=valid" not in observation or content.hex() in result.stdout:
                raise SystemExit(f"native parser did not safely report {format_name}")
            if path.read_bytes() != content:
                raise SystemExit(f"native parser modified the {format_name} fixture")


def main() -> None:
    executable = shutil.which("babylon")
    if executable is None:
        raise SystemExit("babylon was not found on PATH")

    help_result = subprocess.run(
        [executable, "--help"],
        capture_output=True,
        check=True,
        text=True,
        timeout=15,
    )
    if "analyze-directory" not in help_result.stdout or "ui" not in help_result.stdout:
        raise SystemExit("babylon --help did not list the expected CLI commands")

    _smoke_test_format_parser(executable)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    server = subprocess.Popen(
        [executable, "ui", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        url = f"http://127.0.0.1:{port}/"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise SystemExit(f"babylon ui exited early with status {server.returncode}")
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    html = response.read().decode("utf-8")
                    if response.status != 200:
                        raise SystemExit(f"babylon ui returned HTTP {response.status}")
                    if "<title>Babylon" not in html or "__BABYLON_CSRF_TOKEN__" in html:
                        raise SystemExit("babylon ui did not serve the bundled HTML correctly")
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(0.2)
        else:
            raise SystemExit("babylon ui did not become ready within 15 seconds")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    print("Babylon CLI and bundled UI smoke tests passed.")


if __name__ == "__main__":
    main()
