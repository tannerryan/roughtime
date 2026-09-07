# Security Policy

## Supported versions

Only the latest tagged release receives security fixes. Users of older releases
should upgrade before reporting an issue.

## Reporting a vulnerability

Report vulnerabilities through [GitHub's private vulnerability reporting
form](https://github.com/tannerryan/roughtime/security/advisories/new). Do not
open a public issue or discussion for an undisclosed vulnerability.

Include the affected release, component, and protocol version. Describe the
impact and prerequisites, and provide a minimal reproducer or test vector when
possible. Test only systems you own or have permission to use. Do not test
availability against public servers or submit real private keys.

## Scope

Relevant reports include:

- authentication or trust bypasses in signatures, certificates, nonces, Merkle
  proofs, version negotiation, chains, or timestamp proofs.
- untrusted inputs that cause a panic, hang, excessive resource use, or unsafe
  amplification.
- flaws in root-key handling, delegation, or key-file operations.

A trusted server signing an inaccurate time is not by itself an implementation
vulnerability: callers control trust roots and witness selection. The known
experimental and interoperability limits of the non-IETF ML-DSA-44 extension are
also not vulnerabilities, although implementation flaws in that extension are in
scope.

This policy covers this repository's code. Third-party servers listed in
`ecosystem.json` are operated by their respective owners.
