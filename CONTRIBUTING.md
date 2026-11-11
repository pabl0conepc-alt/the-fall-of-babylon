# Contributing

Contributions to The Fall of Babylon are welcome. Before starting substantial work, open an issue to discuss the proposed change and its scope.

## Development setup

- Use Python 3.11 or newer.
- Runtime code uses only the Python standard library.
- Run the test suite from the repository root:

  ```sh
  PYTHONPATH=src python -m unittest discover -s tests -v
  ```

- When changing documented behavior, update the relevant documentation as well.

## Changes and pull requests

- Keep changes focused and consistent with the existing module boundaries and safety limits.
- Add or update tests for behavior changes and bug fixes.
- Do not add a runtime dependency without explaining why it is needed.
- Describe the behavior changed, the reason for the change, and the checks you ran.
- Do not submit samples or reports containing data you are not authorized to share.

Contributions are subject to review; no particular response time or acceptance is guaranteed.
