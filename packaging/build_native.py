"""Build and test the bounded native format parser."""

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build" / "native-cmake")
    parser.add_argument("--install-dir", type=Path, default=ROOT / "build" / "native")
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    install_dir = args.install_dir.resolve()

    subprocess.run(
        [
            "cmake",
            "-S",
            str(ROOT / "native"),
            "-B",
            str(build_dir),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=ON",
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build_dir), "--config", "Release"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "ctest",
            "--test-dir",
            str(build_dir),
            "-C",
            "Release",
            "--output-on-failure",
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "cmake",
            "--install",
            str(build_dir),
            "--prefix",
            str(install_dir),
            "--config",
            "Release",
        ],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()
