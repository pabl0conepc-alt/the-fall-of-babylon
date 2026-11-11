# Security policy

## Scope and limitations

The project is intended for bounded, offline analysis of local material that the caller owns or is explicitly authorized to analyze. The authorization statement is a caller declaration and is not independently verified.

The implementation does not execute samples, decompress archives, disassemble code, or provide a sandbox. A bounded C++ helper parses selected PE, ELF, and Mach-O structural metadata in a separate process; malformed input can still expose parser defects, so keep the application updated and treat the output as descriptive only. Its findings are not a malware verdict. Refer to [ARCHITECTURE.md](ARCHITECTURE.md) for the current boundaries and limitations. Do not rely on this project as a substitute for a dedicated security product or controlled forensic environment.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue. Check the repository's GitHub **Security** tab for a private vulnerability reporting option and use it if available. A dedicated security contact or private reporting channel is not documented in this repository; if GitHub private reporting is unavailable, do not post sensitive details publicly.

There is no published response-time commitment or supported-version policy.
