# Security Policy

This repository contains intentionally vulnerable code samples that mirror the STRIDE checklist in `checklist.txt`. **Do not treat this project as production-ready software.** It is designed for demonstrations, workshops, and testing security tooling.

## Supported Versions

Security fixes are **not** provided. Each commit is meant to preserve specific insecure behaviors. Automated dependency upgrades, code scanning “auto-fix” PRs, or other security bots should be disabled to avoid changing the scenarios.

## Reporting Vulnerabilities

If you discover an issue outside the documented scenarios (for example, something that could impact your own environment when running the demos), you can:

1. Open an issue with the details, noting that the repository is intentionally vulnerable.
2. Alternatively, email the maintainer if you prefer private disclosure.

Because this is a training repo, reports may be acknowledged without code changes.

## Usage Guidelines

- Run the vulnerable app only in isolated, disposable environments.
- Never deploy the vulnerable sample to the public internet.
- When referencing these examples in other projects, add clear warnings so automated tools and CI systems do not “fix” the vulnerabilities unless you explicitly want that behavior.
