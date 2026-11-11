#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python3 packaging/build_binary.py
version="$(python3 -c 'import tomllib; print(tomllib.loads(open("pyproject.toml", "rb").read().decode())["project"]["version"])')"
stage="$(mktemp -d "${TMPDIR:-/tmp}/babylon-pkg.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT

install -Dm755 dist/babylon "$stage/usr/local/bin/babylon"
install -Dm644 README.md "$stage/usr/local/share/doc/babylon/README.md"
install -Dm644 packaging/README.md "$stage/usr/local/share/doc/babylon/INSTALL.md"
mkdir -p dist
pkgbuild \
  --root "$stage" \
  --identifier com.pabl0conepc.babylon \
  --version "$version" \
  --install-location / \
  "dist/babylon_${version}_macos.pkg"
