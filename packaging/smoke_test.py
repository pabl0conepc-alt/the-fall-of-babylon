"""Smoke-test an installed Babylon command and its bundled local UI."""

import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request


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
