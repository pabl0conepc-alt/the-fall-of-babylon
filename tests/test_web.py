import hashlib
import http.client
import json
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from fall_of_babylon.local_analysis import MAX_FILE_BYTES
from fall_of_babylon import web
from fall_of_babylon.web import create_ui_server


class WebUiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_ui_server(0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.thread.join, 2)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.origin = self.url

    def _post(self, body: bytes, **headers: str):
        request_headers = {
            "Origin": self.origin,
            "X-Babylon-Token": self.server.csrf_token,
            "Content-Type": "application/octet-stream",
            "X-File-Name": "sample.png",
        }
        request_headers.update(headers)
        request = Request(
            f"{self.url}/api/analyze",
            data=body,
            headers=request_headers,
            method="POST",
        )
        return urlopen(request, timeout=5)

    def test_serves_local_html_without_remote_assets(self) -> None:
        with urlopen(self.url, timeout=5) as response:
            html = response.read().decode("utf-8")

        self.assertEqual(response.status, 200)
        self.assertIn('type="file"', html)
        self.assertIn("Download JSON report", html)
        self.assertIn(self.server.csrf_token, html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script src=", html)

    def test_upload_runs_core_and_returns_provenance_without_temporary_path(self) -> None:
        content = b"\x89PNG\r\n\x1a\nlocal fixture"
        created_directories: list[Path] = []
        original_temporary_directory = web.tempfile.TemporaryDirectory

        def capture_temporary_directory(*args, **kwargs):
            temporary_directory = original_temporary_directory(*args, **kwargs)
            created_directories.append(Path(temporary_directory.name))
            return temporary_directory

        with patch(
            "fall_of_babylon.web.tempfile.TemporaryDirectory",
            side_effect=capture_temporary_directory,
        ):
            with self._post(content) as response:
                payload = json.loads(response.read())

        report = payload["report"]
        self.assertEqual(response.status, 200)
        self.assertEqual(report["evidence"]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(report["evidence"]["size_bytes"], len(content))
        self.assertEqual(report["evidence"]["path"], "sample.png")
        self.assertNotIn("babylon-ui-", report["evidence"]["path"])
        self.assertEqual(report["evidence"]["recovery_status"], "not_attempted")
        self.assertEqual(len(report["findings"]), 3)
        self.assertTrue(
            all(
                finding["provenance"]["artifact_sha256"] == report["evidence"]["sha256"]
                for finding in report["findings"]
            )
        )
        self.assertEqual(len(created_directories), 1)
        self.assertFalse(created_directories[0].exists())

    def test_rejects_bad_origin_token_and_non_filename_paths(self) -> None:
        for headers, expected_status in (
            ({"Origin": "http://attacker.invalid"}, 403),
            ({"X-Babylon-Token": "invalid"}, 403),
            ({"X-File-Name": "../server-file"}, 400),
        ):
            with self.subTest(headers=headers):
                with self.assertRaises(HTTPError) as error:
                    self._post(b"fixture", **headers)
                self.assertEqual(error.exception.code, expected_status)
                error.exception.close()

    def test_rejects_wrong_host_and_oversized_upload(self) -> None:
        with self.assertRaises(HTTPError) as host_error:
            self._post(b"fixture", Host="attacker.invalid")
        self.assertEqual(host_error.exception.code, 403)
        host_error.exception.close()

        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.addCleanup(connection.close)
        connection.request(
            "POST",
            "/api/analyze",
            body=b"x",
            headers={
                "Host": f"127.0.0.1:{self.server.server_port}",
                "Origin": self.origin,
                "X-Babylon-Token": self.server.csrf_token,
                "X-File-Name": "large.bin",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(MAX_FILE_BYTES + 1),
            },
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        self.assertIn("larger than", json.loads(response.read())["error"])


if __name__ == "__main__":
    unittest.main()
