# the-fall-of-babylon

Universal Reverse Engineering &amp; Reconstruction Platform. A modular toolkit for deep file, binary, application, and website analysis, automated extraction, digital forensics, and project reconstruction.

## Project status

Those capabilities are the project's long-term goals. The current MVP performs bounded, read-only identification and SHA-256 hashing of one caller-authorized local file. It does not execute or parse the file.

The project is intended for local use on material you own or are explicitly authorized to analyze. The CLI rejects symlinks, non-regular files, parent-directory components, and inputs larger than 1 MiB. It requires a non-empty authorization statement for every request; that statement is a caller declaration, not independently verified.

## Development

- Requires Python 3.11 or newer.
- Runtime code uses only the Python standard library.
- Run the tests with `PYTHONPATH=src python -m unittest discover -s tests -v`.
- Run a local analysis with `PYTHONPATH=src python -m fall_of_babylon analyze ./sample.pdf --authorization-basis "I own this file"`.

The command prints a JSON report to stdout and does not write a report or modify the source file. Installing the package in editable mode with `python -m pip install -e .` provides the `babylon` command.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module boundaries, supported signatures, limitations, and deferred capabilities.
