# Architecture

## Current MVP

The package uses a small layered structure:

- `domain/contracts.py` contains immutable request, finding, and report data types.
- `ports.py` defines the typed `Analyzer` interface without providing an implementation.
- `local_analysis.py` securely opens one local regular file, hashes at most 1 MiB, and checks a small signature allowlist.
- `cli.py` requires an authorization basis and emits the result as JSON on stdout.
- `tests/` contains standard-library tests for the contracts, file handling, and CLI.

The domain layer has no filesystem or process side effects. The local analysis layer does not resolve paths or follow symlinks: it walks absolute path components using directory descriptors and no-follow flags. It rejects `..`, symlinks, non-regular files, files over 1 MiB, and files that change while being read. Platforms without the required no-follow descriptor APIs are refused rather than handled with weaker checks.

The report contains the source path, byte count, SHA-256, identification result and method, extension hint, and limitations. Identification recognizes only PDF, PNG, JPEG, GIF, ZIP, GZIP, SQLite, WAVE, and WebP signatures. An extension without a matching signature is reported only as a hint. The CLI requires a non-empty caller-supplied authorization statement but cannot independently verify authorization. The file is read to hash it, but its contents are not interpreted, and neither the source nor report is written by the tool.

## Scope boundary

This MVP does not implement content parsing, binary analysis, archive listing/extraction, decompression, decompilation, dynamic execution, network access, website scanning, phishing intelligence, exploitation, or reconstruction. In particular, dynamic analysis remains blocked until a separately designed and tested sandbox exists. Future capabilities should be isolated behind the domain contracts and added only with explicit scope and safety review.
