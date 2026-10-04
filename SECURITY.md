# Security Policy

## Reporting a Vulnerability

Security issues are reported as regular [GitHub issues](https://github.com/fschaefer/ngx-oidc-module/issues).

Please include:

- a short description of the problem,
- the affected version (git commit or release),
- a minimal reproducer or the relevant configuration, where possible,
- the expected vs. actual behaviour.

There is no private reporting channel and no bug bounty. Reports are handled
on a best-effort basis, with no fixed response or fix timeline.

## Supported Versions

Only the `main` branch (latest release) is supported. Security fixes are
released for the latest version only; older versions are not patched.

## Scope

The following count as security issues and should be reported as described above:

- authentication or authorization bypass,
- session hijacking or session-cookie handling flaws,
- leakage of tokens, client secrets, or session keys,
- failures to validate signatures, `nonce`, `state`, issuer, or audience,
- TLS/HTTPS verification flaws.

Everything else — crashes, build problems, configuration questions, feature
requests — is a regular bug and can be filed as a normal issue.
