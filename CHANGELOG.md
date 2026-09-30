# Changelog

This file records notable user-facing and repository-level changes to SOC Lab.

The project has not published a tagged release yet. Until the first release tag is created, validated changes remain grouped under `Unreleased`.

## Unreleased

### Added

- MIT project license
- security policy and responsible vulnerability-reporting guidance
- reproducible runtime and development dependency constraints
- documented automated-response configuration
- read-only operator, monitoring and reporting boundaries
- deterministic JSON, Markdown and PDF reporting support

### Changed

- repository-wide LF text normalization and explicit Git text attributes
- runtime and bootstrap documentation for reproducible installs
- executable policy for the Linux/WSL engine launcher
- dependency ownership so directly imported runtime packages are explicitly declared

### Security

- release-readiness audits for secrets, environment files, local paths and repository history
- explicit protected-target configuration for automated response workflows
- defensive repository hygiene guidance for credentials and local runtime data

### Validation

- full regression suite currently contains 732 passing tests with warnings treated as errors
- dependency health is validated with `pip check`

## Release policy

Future tagged releases should move the applicable entries from `Unreleased` into a versioned section and record the release date.
