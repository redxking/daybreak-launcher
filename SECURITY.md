---
title: Daybreak Launcher Security Policy
author: Angelis Pseftis
creator: Angelis Pseftis
---

# Security policy

Daybreak Launcher is experimental. The current preview has macOS test evidence; native Windows/Linux qualification and live scan-to-PR testing remain incomplete. See README.md and test-results.txt for the evidence boundary.

## Report a vulnerability privately

Use this repository's [private vulnerability reporting form](https://github.com/redxking/daybreak-launcher/security/advisories/new). Do not include credentials, authorization codes, private source, or customer data in public issues. Reports should identify the affected version, reproduction steps, expected and observed behavior, and impact. Use synthetic data where possible.

There is no guaranteed response time or support SLA for this preview. Routine bugs without sensitive security details can be reported through GitHub Issues.

## Operation and disclosure

The launcher runs the official Codex Security CLI with the user's operating-system permissions. Its separate checkout is not a sandbox. Use an isolated development environment for untrusted code and keep unrelated credentials out of that environment.

Default operation creates draft requests automatically. Requests on public repositories disclose their code and vulnerability descriptions publicly. Use `--scan-only` for private review before disclosure. Keep generated scan results, login state, and local configuration out of public repositories.

Suggested tests and model-reported verification are not an independent security certification. Review the actual patch, test evidence, coverage gaps, and required CI results before merging.
