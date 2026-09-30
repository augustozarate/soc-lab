# Security Policy

## Project scope

SOC Lab is an educational and defensive security laboratory under active development.
It is not presented as a production-ready SOC platform and should not be relied on as a sole security control.

## Supported versions

Security fixes are applied to the current `main` branch.
Older commits, experimental branches and unreleased snapshots are not maintained as supported security versions.

## Reporting a vulnerability

Please do not publish a security vulnerability, credential, exploit transcript or sensitive environment data in a public issue before the problem has been reviewed.

When reporting a vulnerability, include enough information to reproduce and assess the issue while excluding real credentials, private keys, personal data and unrelated sensitive information.

Useful reports should include:

- the affected component or file
- the observed security impact
- reproducible steps using a controlled laboratory environment
- relevant logs with secrets and personal data removed
- a suggested mitigation, when known

Until a dedicated private reporting channel is published, avoid posting exploit details that would expose users or systems to unnecessary risk. A public issue may be opened for non-sensitive security hardening discussions that do not disclose an exploitable vulnerability.

## Responsible use

Security testing, monitoring, simulation and response features in this repository are intended for systems you own or are explicitly authorized to assess.

Do not use the project to access, disrupt, monitor or modify third-party systems without authorization.

## Secrets and local data

Never commit real API keys, passwords, private keys, tokens, `.env` files, production logs or sensitive incident data.

The repository includes `.env.example` only as a configuration template. Replace laboratory example values as appropriate for your environment and keep local secrets outside version control.

## Dependency and disclosure notes

The project depends on third-party packages whose vulnerabilities and security policies are maintained by their respective upstream projects.

If a report concerns only an upstream dependency and does not introduce a SOC Lab-specific weakness, report it to the upstream project through its documented security process.
