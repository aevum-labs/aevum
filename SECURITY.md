# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (pre-release) | Current development |

Once 1.0 is released, only the most recent minor version receives security fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by emailing:

**security@aevum.dev**

Include:
- A description of the vulnerability
- Steps to reproduce
- The version of `aevum-core` affected
- Any relevant code or configuration

## Response Process

- **Acknowledgement:** within 48 hours of receipt
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 90 days for confirmed vulnerabilities
- **Public disclosure:** coordinated with the reporter after a fix is available

We follow responsible disclosure. We will not take legal action against researchers
who report vulnerabilities in good faith following this policy.

## Scope

The following are in scope:

- `aevum-core` and all packages in the `aevum-labs/aevum` monorepo
- The Aevum protocol specification (`aevum-labs/aevum-spec`)
- The conformance test suite (`aevum-labs/aevum-conformance`)

The following are out of scope:

- Vulnerabilities in dependencies (report to the dependency maintainer)
- Vulnerabilities that require physical access to the system
- Social engineering attacks
