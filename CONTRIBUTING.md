# Contributing

Thank you for considering improvements to SOC Lab.

This repository is an educational and defensive security laboratory under active development. Contributions should preserve that scope and avoid introducing workflows intended for unauthorized access, disruption or surveillance.

## Development baseline

The validated development baseline currently supports CPython 3.12, 3.13 and 3.14 on Linux x86_64.

On Debian/Ubuntu, install the native libsodium runtime required by
the Threema/libnacl dependency before creating the environment:

```bash
sudo apt update
sudo apt install libsodium23
```

Then create and activate the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the development dependencies with the validated constraint set:

```bash
python3 -m pip install -r requirements-dev.txt -c constraints-dev.txt
```

## Branching

Use a short-lived feature, fix, documentation or maintenance branch created from the current `main` branch.

Keep each change focused on one concern and avoid mixing unrelated formatting, refactoring or dependency changes into the same commit.

## Validation

Before proposing a change, run:

```bash
python3 -m pip check
python3 -m pytest -q -W error
git diff --check
git status --short
```

The repository currently treats the full pytest suite with warnings promoted to errors as a merge gate.

## Repository hygiene

Do not commit real credentials, API keys, private keys, tokens, `.env` files, production logs, personal data or sensitive incident material.

Use synthetic or laboratory-only values in tests and examples.

Respect the repository text policy defined in `.gitattributes` and preserve LF line endings.

## Security-related changes

For vulnerabilities or security-sensitive reports, follow `SECURITY.md` rather than disclosing exploitable details in a public issue.

## Documentation

When behavior, configuration, supported commands, repository structure or operational expectations change, update the relevant documentation in the same change.

## Commit scope

Prefer small commits with descriptive messages that explain the purpose of the change.

Validated branches should be integrated into `main` only after the relevant tests, hygiene checks and security boundaries pass.
