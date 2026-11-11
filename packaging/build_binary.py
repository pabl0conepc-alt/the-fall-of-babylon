"""Build the standalone Babylon CLI executable used by native installers."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build" / "pyinstaller")
    parser.add_argument("--native-dir", type=Path, default=ROOT / "build" / "native")
    args = parser.parse_args()

    native_dir = args.native_dir.resolve()
    native_build_dir = args.work_dir.resolve() / "native-cmake"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging" / "build_native.py"),
            "--build-dir",
            str(native_build_dir),
            "--install-dir",
            str(native_dir),
        ],
        cwd=ROOT,
        check=True,
    )
    parser_name = (
        "babylon-format-parser.exe" if sys.platform == "win32" else "babylon-format-parser"
    )
    native_helper = native_dir / parser_name
    if not native_helper.is_file():
        raise FileNotFoundError(f"Native parser build did not produce {native_helper}")

    html_file = ROOT / "src" / "fall_of_babylon" / "web" / "index.html"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--name",
        "babylon",
        "--paths",
        str(ROOT / "src"),
        "--add-data",
        f"{html_file}{os.pathsep}fall_of_babylon/web",
        "--add-binary",
        f"{native_helper}{os.pathsep}native",
        "--distpath",
        str(args.dist_dir.resolve()),
        "--workpath",
        str((args.work_dir / "work").resolve()),
        "--specpath",
        str((args.work_dir / "spec").resolve()),
        str(ROOT / "packaging" / "entrypoint.py"),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
