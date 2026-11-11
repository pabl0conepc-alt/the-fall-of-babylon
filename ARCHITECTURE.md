# Architecture

## Current implementation

The package uses explicit contracts, ports, engines, and an orchestrator:

- `domain/contracts.py` defines immutable requests, evidence records, byte-range provenance, findings, recovery status, engine results, and JSON job reports.
- `ports.py` defines the `Analyzer` and `AnalysisEngine` interfaces.
- `local_analysis.py` securely opens one local regular file and acquires at most 1 MiB in bounded chunks while hashing it.
- `directory_analysis.py` traverses local directories through no-follow directory descriptors, records rejected entries, and delegates regular files to the same safe reader and engines.
- `engines.py` provides three deterministic built-in engines: signature-family identification, byte-frequency profiling, and streaming encoding validation.
- `orchestrator.py` registers a fixed ordered engine set, acquires the file once, and runs each engine against the same immutable evidence digest.
- `report_store.py` optionally saves complete versioned JSON reports in a local SQLite database using parameterized SQL and transactions; list/export access is read-only.
- `cli.py` requires an authorization basis and emits a versioned JSON report to stdout.
- `tests/` covers contracts, safe file and directory access, provenance, all engines, orchestration, SQLite storage/migration, and CLI behavior.

The domain layer has no filesystem or process side effects. The local analysis layer does not resolve paths through symlinks: it walks absolute path components using directory descriptors and no-follow flags. It rejects `..`, symlinks, non-regular files, files over 1 MiB, and files that change while being read. Platforms without the required no-follow descriptor APIs are refused rather than handled with weaker checks. The payload is held in memory only for the bounded analysis (at most 1 MiB, plus fixed-size statistics); built-in engines perform linear work over those bytes with no regex or decompression. No hard wall-clock preemption is provided for arbitrary Python code injected through the library API, so only trusted in-process engines should be registered.

File reports record a job ID, UTC acquisition time, source path, byte count, SHA-256, acquisition method, and `recovery_status: not_attempted`. Findings reference the artifact digest, byte range, method, and observation. The signature engine recognizes PDF, PNG, JPEG, GIF, ZIP, GZIP, SQLite, WAVE, WebP, ELF, Mach-O, and PE header signatures; this is identification only, not format validation. An extension without a matching signature is only a hint. The byte-profile engine reports Shannon entropy, printable ASCII byte count, and NUL byte count; those values are descriptive and not a malware verdict. The encoding engine checks strict UTF-8 or BOM-indicated UTF-16/32 validity incrementally; it never includes literal file content in the report and does not claim that valid bytes are necessarily a text file.

Directory reports record entries up to explicit limits and contain per-file reports only for regular files that pass the existing no-follow reader. Symlinks and special entries are never opened; exceeded depth/file/byte/entry caps are explicit and set the report's `truncated` flag. The CLI requires a non-empty caller-supplied authorization statement but cannot independently verify authorization. Reports omit the statement itself and print to stdout; they are not persisted unless `analyze --database PATH` or `analyze-directory --database PATH` is explicitly supplied.

The SQLite store uses application ID `0x42414259` and schema version 2, migrating version 1 file-report databases transactionally when the next report is saved. It stores file or directory report JSON and searchable job metadata in one transaction. A new database is created with mode `0600` on POSIX; pre-existing databases must be regular files with no group/other permissions. Existing unversioned databases containing user objects and databases with unknown application/schema versions are refused. A database must not be any analyzed file or be located inside the directory being inventoried. No parent directories are created. `jobs` and `export` open the database read-only, use bound parameters, and never write. The report store is local only; it performs no network access.

Directory traversal ceilings are depth 3 below root, 50 regular files, 100 recorded entries, 1 MiB per file, and 16 MiB total acquired bytes. Traversal uses `os.scandir` on an opened directory descriptor, reads entry metadata without following symlinks, and opens child directories with `O_NOFOLLOW`. Each regular file is subsequently re-opened through the existing no-follow reader before analysis.

## Scope boundary

This implementation does not structurally parse file formats, inspect executable internals, list/extract archives, decompress, recover deleted data, decompile, execute samples, scan websites/targets, provide phishing intelligence, exploit, or reconstruct projects. Directory inventory is limited to the explicitly selected local directory and the fixed traversal bounds above. Persistence is opt-in and limited to the caller-selected local SQLite database; callers may also redirect stdout themselves. Dynamic analysis remains blocked until a separately designed and tested sandbox exists. Any future capability must be isolated behind the domain contracts and added only with explicit scope and safety review.
