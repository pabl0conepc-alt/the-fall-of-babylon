#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python3 packaging/build_binary.py
version="$(python3 -c 'import tomllib; print(tomllib.loads(open("pyproject.toml", "rb").read().decode())["project"]["version"])')"
architecture="$(dpkg --print-architecture)"
stage="$(mktemp -d "${TMPDIR:-/tmp}/babylon-deb.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT

install -Dm755 dist/babylon "$stage/usr/bin/babylon"
install -Dm644 README.md "$stage/usr/share/doc/babylon/README.md"
install -Dm644 packaging/README.md "$stage/usr/share/doc/babylon/INSTALL.md"
install -d "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<EOF
Package: babylon
Version: ${version}
Section: utils
Priority: optional
Architecture: ${architecture}
Depends: libc6 (>= 2.35)
Maintainer: Babylon project maintainers
Description: Local-first authorized static file analysis
 Standalone Babylon command-line application with its offline local browser UI.
EOF

mkdir -p dist
dpkg-deb --build --root-owner-group "$stage" "dist/babylon_${version}_${architecture}.deb"
