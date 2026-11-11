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
    args = parser.parse_args()

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
