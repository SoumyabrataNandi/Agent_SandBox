# Security policy

sandboxd exists to run untrusted code safely, so a way around its isolation is the most important kind of bug it can have. Thank you for reporting one.

## Reporting a vulnerability
**Please don't open a public issue.** Report it privately through GitHub:
**Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Please include:
- the sandboxd version (`sandboxd version`) and OS;
- the policy and config used (redact tokens and paths you don't want to share);
- the guest program or request that triggers it, and what you observed versus what you expected.

## What we aim for
| Step | Target |
|---|---|
| Acknowledge the report | within 3 working days |
| Confirm or reject, with an initial severity | within 7 working days |
| Fix a critical issue (sandbox escape, cross-principal access) | release within 14 days of confirmation |
| Disclosure | a GitHub security advisory with credit (unless you prefer not), after the fix is released |

## In scope
- **Sandbox escape:** guest code reading, writing or executing anything on the host outside what its policy mounts, or reaching the network without a policy grant.
- **Policy or limit bypass:** exceeding wall-clock, CPU (fuel), memory, output, file or network limits; using a capability the policy doesn't grant.
- **Cross-run, cross-session or cross-principal leakage:** observing another run's, session's or principal's code, data or output (including through pooled memory or snapshots).
- **Authentication and authorization:** using the HTTP or MCP API without a valid token; acting on another principal's sessions.
- **Audit evasion:** a capability use that isn't recorded, or forging audit records.
- **Host denial of service through the API** that limits and admission control should prevent (for example, crashing or wedging the server with one request).
- **Supply chain:** tampered or unpinned interpreter assets, or a release archive that doesn't match its checksum or attestation.

## Out of scope
- Anything a policy intentionally grants (for example, a host directory mounted read-write, or an allowlisted network destination).
- Vulnerabilities in the operator's own environment (an exposed server without TLS in front of it, a leaked token).
- Bugs that only crash the guest program itself.

The threat model is in [THREAT_MODEL.md](THREAT_MODEL.md); the adversarial tests are in [tests/escape-suite](tests/escape-suite). Residual risks we have accepted are listed there (R1–R13), and the most important is a vulnerability in wasmtime itself. We track RustSec advisories daily (the `security` workflow) and patch quickly.

## Supported versions
Only the latest release gets security fixes. sandboxd is pre-1.0, so a fix may ship in a new minor version.
