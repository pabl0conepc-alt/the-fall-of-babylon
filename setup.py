"""Build the native parser helper into non-editable installations and wheels."""

import platform
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent


class BuildWithHelper(build_py):
    def run(self) -> None:
        super().run()
        # Editable installs use the helper built by packaging/build_native.py.
        if self.editable_mode:
            return
        build_temp = Path(self.get_finalized_command("build").build_temp)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "packaging" / "build_native.py"),
                "--build-dir",
                str((build_temp / "native-cmake").resolve()),
                "--install-dir",
                str((Path(self.build_lib) / "fall_of_babylon" / "native").resolve()),
            ],
            check=True,
        )


class PlatformDistribution(Distribution):
    def has_ext_modules(self) -> bool:
        return True


class PlatformWheel(bdist_wheel):
    def get_tag(self) -> tuple[str, str, str]:
        # The helper is platform-specific but independent of the Python ABI.
        _, _, platform_tag = super().get_tag()
        # CMake builds only for the host architecture, even under universal2 Python.
        return "py3", "none", platform_tag.replace("universal2", platform.machine())


setup(
    distclass=PlatformDistribution,
    cmdclass={"build_py": BuildWithHelper, "bdist_wheel": PlatformWheel},
)
