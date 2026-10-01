# Changelog

This file records notable user-facing and repository-level changes to SOC Lab.

## Unreleased

No unreleased changes are currently recorded.

## [1.0.0] - 2026-10-01

### Added

- MIT project license
- security policy and responsible vulnerability-reporting guidance
- reproducible runtime and development dependency constraints
- documented automated-response configuration
- read-only operator, monitoring and reporting boundaries
- deterministic JSON, Markdown and PDF reporting support
- GitHub Actions CI matrix for CPython 3.12, 3.13 and 3.14

### Changed

- repository-wide LF text normalization and explicit Git text attributes
- runtime and bootstrap documentation for reproducible installs
- executable policy for the Linux/WSL engine launcher
- dependency ownership so directly imported runtime packages are explicitly declared
- SQLite connections are explicitly closed after context-managed use
- Threema gateway compatibility supports Python 3.14 through a local asyncio compatibility bridge
- Linux runtime entrypoint now propagates terminal signals directly to the Python process
- documented Python support now covers CPython 3.12, 3.13 and 3.14 on Linux x86_64

### Security

- release-readiness audits for secrets, environment files, local paths and repository history
- explicit protected-target configuration for automated response workflows
- defensive repository hygiene guidance for credentials and local runtime data
- read-only SOC monitor boundaries use bounded query surfaces and detached projections

### Validation

- full regression inventory contains 737 tests with warnings treated as errors
- dependency health is validated with `pip check`
- Linux entrypoint syntax is validated with `bash -n`
- native Ubuntu startup and graceful SIGINT shutdown were validated without residual SOC processes
- CPython 3.12.14, 3.13.15 and 3.14.7 were manually validated on Linux x86_64
- GitHub Actions Python CI run #1 completed successfully for Python 3.12, 3.13 and 3.14

## Release policy

Future tagged releases should move the applicable entries from `Unreleased` into a versioned section and record the release date.
