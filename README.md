# The Fall of Babylon

The Fall of Babylon is a local-first foundation for authorized static file analysis and digital forensics. It provides a command-line interface, an offline browser interface, optional local report storage, and native installer packages.

## What it does

The current implementation performs bounded, read-only analysis of one caller-authorized local file or a caller-authorized local directory. It records SHA-256 acquisition provenance for files, identifies a small set of file signatures, reports byte-profile and text-encoding validity hints, and extracts bounded structural metadata from PE, ELF, and Mach-O files without emitting source content. It does not execute samples or provide a safety verdict.

Use it only with material you own or are explicitly authorized to analyze. The CLI rejects symlinks/reparse points, non-regular files, parent-directory components, and inputs larger than 1 MiB. It requires a non-empty authorization statement for every request; that statement is a caller declaration, not independently verified. Analysis is offline and has no external engine or plugin loader. By default, the report is printed to stdout; the source file is never modified. Windows supports single-file analysis and the UI; directory traversal remains unsupported there.

Built-in engines report header-signature matches, byte-frequency/entropy/printable-byte statistics, strict encoding validity hints, and structural metadata for PE/COFF, ELF32/64, and Mach-O thin/universal headers and tables. Parsing is bounded to 1 MiB and reports truncation, malformed structures, or unsupported variants explicitly; metadata is observational and is not a verdict. The signature engine also recognizes PDF, PNG, JPEG, GIF, ZIP, GZIP, SQLite, WAVE, and WebP; an extension without a matching signature is only a hint.

## Install

Python 3.11 or newer is required. Runtime code uses only the Python standard library. To install the package in editable mode and provide the `babylon` command:

```sh
python -m pip install -e .
```

Native installer packages are built by CI and provided as workflow artifacts; the repository does not automatically publish GitHub Releases. Current package platforms, architectures, installation instructions, and build details are documented in [packaging/README.md](packaging/README.md). Those CI artifact targets are not a guarantee of support for every release or OS configuration.

## Use

Run commands from the repository root during development:

```sh
# Analyze one explicitly authorized local file
PYTHONPATH=src python -m fall_of_babylon analyze ./sample.pdf \
  --authorization-basis "I own this file"

# Inventory and analyze a bounded local directory
PYTHONPATH=src python -m fall_of_babylon analyze-directory ./evidence \
  --authorization-basis "I own this directory"

# Launch the offline browser interface (open the loopback URL printed)
PYTHONPATH=src python -m fall_of_babylon ui
```

Use `--format json` on `analyze`, `analyze-directory`, `jobs`, and `export` for machine-readable output; human-readable text is the default. Analysis reports are not stored unless you explicitly provide `--database PATH` to an analysis command:

```sh
PYTHONPATH=src python -m fall_of_babylon analyze ./sample.pdf \
  --authorization-basis "I own this file" --database ./babylon.sqlite3
PYTHONPATH=src python -m fall_of_babylon jobs --database ./babylon.sqlite3
PYTHONPATH=src python -m fall_of_babylon export JOB_ID --database ./babylon.sqlite3
```

The selected SQLite database is created or updated transactionally, must already have private permissions if it exists, and must not be the analyzed source or be inside the inventoried directory. Missing parent directories are not created. `jobs` and `export` read the existing database without writing to it.

The browser UI binds only to `127.0.0.1`, requires same-origin requests and a per-run request token, and accepts only bytes from the browser's explicit single-file selection (maximum 1 MiB). It does not accept a filesystem path from the browser, create report databases, or send data off-device. Uploads are analyzed through the same core inside a private temporary directory that is removed after the response. The downloaded JSON report is the only persistent browser export; page state is otherwise transient.

The native parser runs as a bundled helper process. It receives only the already-acquired bytes through stdin, has no path or network access, and is subject to input, response, and time limits. Directory analysis has fixed ceilings: depth 3 below the selected root, 50 regular files, 100 recorded entries, 1 MiB per file, and 16 MiB total read. Symlinks and special files are recorded as rejected without following or opening them; over-limit, unreadable, and skipped entries receive explicit statuses. The directory report marks truncated traversal. Any selected database must be outside the analyzed directory.

## Development

Install CMake and a C++17 compiler, then build/test the bundled helper before source-mode analysis:

```sh
python packaging/build_native.py
```

Run the test suite with:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [ARCHITECTURE.md](ARCHITECTURE.md) for module boundaries, supported signatures, limitations, and deferred capabilities. Project history is summarized in [CHANGELOG.md](CHANGELOG.md).

## Community and security

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations, [SECURITY.md](SECURITY.md) for vulnerability reporting guidance, and [AUTHORS.md](AUTHORS.md) for authorship information. This project is distributed under the [MIT License](LICENSE).
