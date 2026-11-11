# the-fall-of-babylon

Local-first platform foundation for authorized static file analysis and digital forensics.

## Project status

The current implementation performs bounded, read-only analysis of one caller-authorized local file or a caller-authorized local directory. It records SHA-256 acquisition provenance for files, identifies a small set of file signatures, and reports byte-profile and text-encoding validity hints without emitting source content. It does not execute samples or structurally parse file formats.

The project is intended for local use on material you own or are explicitly authorized to analyze. The CLI rejects symlinks, non-regular files, parent-directory components, and inputs larger than 1 MiB. It requires a non-empty authorization statement for every request; that statement is a caller declaration, not independently verified. Analysis is offline and has no external engine/plugin loader. By default, the report is only printed to stdout; the source file is never modified.

## Development

- Requires Python 3.11 or newer.
- Runtime code uses only the Python standard library.
- Run the tests with `PYTHONPATH=src python -m unittest discover -s tests -v`.
- Run a local analysis with `PYTHONPATH=src python -m fall_of_babylon analyze ./sample.pdf --authorization-basis "I own this file"`.
- Inventory a directory with `PYTHONPATH=src python -m fall_of_babylon analyze-directory ./evidence --authorization-basis "I own this directory"`.
- Opt in to local persistence with `--database ./babylon.sqlite3`.
- List saved jobs with `PYTHONPATH=src python -m fall_of_babylon jobs --database ./babylon.sqlite3`.
- Export a saved report with `PYTHONPATH=src python -m fall_of_babylon export JOB_ID --database ./babylon.sqlite3`.

Without `--database`, the command prints a JSON report and creates no database. When explicitly enabled, it creates or updates the selected SQLite database and stores the report and source metadata in a transaction; it does not create missing parent directories and refuses to use the analyzed source as the database. Newly created databases have owner-only permissions on POSIX, and existing databases must already be private. `jobs` and `export` read the existing database without writing to it; export prints JSON to stdout. Built-in engines report header-signature matches, byte-frequency/entropy/printable-byte statistics, and strict encoding validity hints; these are observations, not a verdict, and do not expose literal source contents. Installing the package in editable mode with `python -m pip install -e .` provides the `babylon` command.

Directory analysis has fixed conservative ceilings: depth 3 below the selected root, 50 regular files, 100 recorded entries, 1 MiB per file, and 16 MiB total read. Symlinks and special files are recorded as rejected without following or opening them; over-limit, unreadable, and skipped entries receive explicit statuses. The directory report marks truncated traversal. Any selected database must be outside the analyzed directory.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module boundaries, supported signatures, limitations, and deferred capabilities.
