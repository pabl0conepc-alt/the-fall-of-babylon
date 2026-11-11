"""Loopback-only browser interface for explicit, bounded local file selection."""

import json
import os
import re
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

from .domain.contracts import AnalysisRequest
from .local_analysis import MAX_FILE_BYTES, LocalAnalysisError
from .orchestrator import create_default_analyzer

_HTML_PATH = Path(__file__).with_name("web") / "index.html"
_SAFE_SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,16}\Z")
_MAX_FILENAME_LENGTH = 255


class _BabylonServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int) -> None:
        self.csrf_token = uuid4().hex + uuid4().hex
        super().__init__(("127.0.0.1", port), _RequestHandler)


class _RequestHandler(BaseHTTPRequestHandler):
    server: _BabylonServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if not self._valid_host():
            self._send_json(403, {"error": "Host header is not allowed."})
            return
        if self.path != "/":
            self._send_json(404, {"error": "Not found."})
            return
        html = _HTML_PATH.read_text(encoding="utf-8").replace(
            "__BABYLON_CSRF_TOKEN__", self.server.csrf_token
        )
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._valid_host():
            self._send_json(403, {"error": "Host header is not allowed."})
            return
        if self.path != "/api/analyze":
            self._send_json(404, {"error": "Not found."})
            return
        expected_origin = f"http://127.0.0.1:{self.server.server_port}"
        if self.headers.get_all("Origin", []) != [expected_origin]:
            self._send_json(403, {"error": "Request origin is not allowed."})
            return
        if self.headers.get_all("X-Babylon-Token", []) != [self.server.csrf_token]:
            self._send_json(403, {"error": "Request token is invalid."})
            return
        if self.headers.get_all("Content-Type", []) != ["application/octet-stream"]:
            self._send_json(415, {"error": "Expected an octet-stream file upload."})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._send_json(400, {"error": "Chunked request bodies are not accepted."})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self._send_json(411, {"error": "One Content-Length header is required."})
            return
        try:
            content_length = int(lengths[0])
        except ValueError:
            self._send_json(400, {"error": "Content-Length is invalid."})
            return
        if not 0 <= content_length <= MAX_FILE_BYTES:
            self._send_json(
                413,
                {"error": f"Files larger than {MAX_FILE_BYTES} bytes are not accepted."},
            )
            return
        filenames = self.headers.get_all("X-File-Name", [])
        filename = self._decode_filename(filenames[0]) if len(filenames) == 1 else None
        if filename is None:
            self._send_json(400, {"error": "A valid selected filename is required."})
            return
        content = self.rfile.read(content_length)
        if len(content) != content_length:
            self._send_json(400, {"error": "Upload ended before its declared length."})
            return
        try:
            report = self._analyze_upload(filename, content)
        except LocalAnalysisError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, {"report": report})

    def _valid_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        return hosts == [f"127.0.0.1:{self.server.server_port}"]

    @staticmethod
    def _decode_filename(header: str) -> str | None:
        try:
            filename = unquote(header, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return None
        if (
            not filename
            or len(filename) > _MAX_FILENAME_LENGTH
            or filename in (".", "..")
            or "/" in filename
            or "\\" in filename
            or any(ord(character) < 32 or ord(character) == 127 for character in filename)
        ):
            return None
        return filename

    @staticmethod
    def _analyze_upload(filename: str, content: bytes) -> dict[str, object]:
        suffix = Path(filename).suffix
        if not _SAFE_SUFFIX.fullmatch(suffix):
            suffix = ""
        with tempfile.TemporaryDirectory(prefix="babylon-ui-") as private_dir:
            target = Path(private_dir) / f"selected{suffix}"
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as temporary_file:
                temporary_file.write(content)
            report = create_default_analyzer().analyze(
                AnalysisRequest(target, "User confirmed authorization in the local UI")
            )
            data = report.to_dict()
            evidence = data["evidence"]
            if isinstance(evidence, dict):
                evidence["path"] = filename
            return data

    def _send_json(self, status: int, data: dict[str, object]) -> None:
        body = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"babylon-ui: {format_string % args}", file=sys.stderr)


def create_ui_server(port: int = 8765) -> ThreadingHTTPServer:
    """Create the UI server bound exclusively to IPv4 loopback."""
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return _BabylonServer(port)


def serve_ui(port: int = 8765) -> None:
    """Serve the local UI until interrupted by the user."""
    server = create_ui_server(port)
    address = f"http://127.0.0.1:{server.server_port}/"
    print(f"Babylon local UI: {address}\nPress Ctrl-C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Babylon local UI.", flush=True)
    finally:
        server.server_close()
