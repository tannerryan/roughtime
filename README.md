# roughtime

[![Go
Reference](https://pkg.go.dev/badge/github.com/tannerryan/roughtime.svg)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![License](https://img.shields.io/github/license/tannerryan/roughtime.svg)](LICENSE)

A Go implementation of [RFC 10049](https://www.rfc-editor.org/rfc/rfc10049.html)
with client and [protocol](protocol) packages, a server, and command-line tools.

Clients and protocol APIs default to RFC version 1. Flex mode also supports
Google-Roughtime, IETF drafts 01-19, and the experimental ML-DSA-44 extension.
Clients use `-flex`, the server uses `-flex-port`, and the Go API uses
`protocol.Flex`. The high-level client advertises drafts 05-19 in flex mode.
Earlier drafts are available through the protocol package and debug command.

## Build

Requires Go 1.27 or newer.

```sh
make build
```

Builds the five commands described below. Use `-h` for their flags.

## Server

Generate an Ed25519 root key, print its public key, and start the server:

```sh
roughtime -keygen /path/to/root.key
roughtime -pubkey /path/to/root.key
roughtime -root-key-file /path/to/root.key
```

The server has two modes:

- **Normal:** RFC 10049 v1 over UDP and TCP on `-port` (default 5319).
- **Flex:** Normal plus supported IETF drafts and Google-Roughtime. Add
  `-flex-port 2002` to enable a separate UDP/TCP listener.

Both port numbers can be overridden. The normal listener keeps its normal
profiles when the flex listener is enabled. Omitting `-flex-port` disables the
additional listener. `-listen-address` applies to all listeners. The server
requires Unix.

Seed files must be regular files of at most 4 KiB, without group or other
permissions. Symlinks and key-file overwrites are rejected. Delegations refresh
automatically. With `-offline-delegation`, keys are read once and the server
stops when the delegation leaves its validity window.

The server advertises 3 seconds of total uncertainty, including clock error,
leap-second ambiguity, and timestamp rounding. Keep the host clock synchronized
so the combined error fits that bound. The server does not measure or correct
clock error. It greases 1% of replies by default. Use `-grease-rate 0` for
deterministic replies. UDP and TCP replies never exceed the request size. Short
TCP requests that cannot accommodate a reply are closed without a response.

Google-Roughtime uses UDP only. Typed draft replies use the drafts 16-19 Merkle
convention.

**Either mode can also enable ML-DSA-44 over TCP.** This is a project extension
specified by neither RFC 10049 nor any IETF Roughtime draft. Generate its root
with `-pq-keygen` and enable it with `-pq-root-key-file`. Client commands
require `-flex` for ML-DSA-44 on either port. Both roots may be configured. With
two roots, RFC, drafts 10+, and ML-DSA-44 TCP requests need `SRV` to select a
root.

The ML-DSA-44 extension follows the RFC v1 wire format with version ID
`0x90000001` and larger keys and signatures. Flex clients send 8192-byte request
packets including framing, or 8192-byte bodies with `-standard-size`. Signatures
cover the RFC context prefix and message with an empty FIPS 204 context. Peers
using the earlier draft signature format must update.

`-metrics-addr` enables unauthenticated `/metrics` and `/healthz` endpoints.
Bind to loopback unless external access controls protect them.

### Docker

```sh
docker build -t roughtime .
mkdir -p keys
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/keys:/keys" \
  roughtime -keygen /keys/root.key
docker run --read-only --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 5319:5319/udp -p 5319:5319/tcp -v "$PWD/keys:/keys:ro" \
  roughtime -root-key-file /keys/root.key
```

The host user owns the generated key. The image defaults to UID 65532. For both
ports, add `-flex-port 2002` and publish port 2002 as well.

## Commands

### roughtime-client

Query a server with `-addr` and `-pubkey`, or use `-servers` for a server list
and `-name` to select an entry.

```sh
roughtime-client -addr localhost:5319 -pubkey <key>
```

Strict server-list measurements require at least three endpoint-domain groups
and three distinct roots, queried twice in the same random order through one
causal chain. The default samples up to five groups. `-all` queries every
compatible entry. Domain grouping is a heuristic. Choose independent operators.
Use `-name` for a single entry. Unfiltered strict list queries require both
passes even with `-two-pass=false`.

Flex mode defaults to one pass. `-two-pass` requires a complete measurement, and
`-chain=false` queries concurrently. Single queries and partial chains are not
complete RFC measurements.

Strict requests have a 1024-byte body plus a 12-byte frame. Flex mode uses
1024-byte total packets unless `-standard-size` is set. Strict clients fall back
from UDP to TCP at the same endpoint. Retries use fresh nonces. Caller-supplied
nonces stay fixed, with delay limits covering all attempts and backoff.

Authenticated causal contradictions are saved locally to a private temporary
JSON file. The client prints its path.

Drift depends on network asymmetry. Clock status checks overlap between the
signed window and local exchange interval. The median does not prove agreement.

The bundled `ecosystem.json` contains flex-mode server entries:

```sh
roughtime-client -flex -servers ecosystem.json -all
```

RFC server lists use integer versions, `publicKeyType: "ed25519"`, base64 keys,
and UDP or TCP endpoints. Optional `sources` and `reports` URLs require HTTPS.
Client and stamp commands also read textual versions, hex keys, and ML-DSA-44
entries without `-flex`. That flag controls wire compatibility. Direct flex
queries offer RFC and drafts. Select Google through a server list.

### roughtime-debug

Inspect authenticated response fields and timing. Strict mode probes version 1.
`-flex` scans all implemented versions, including typed and untyped draft-12
forms. `-ver` selects one version.

```sh
roughtime-debug -addr localhost:5319 -pubkey <key>
```

`-scan-timeout` bounds the run. Flex UDP draft probes try both padding sizes.
Single-leaf replies cannot distinguish the drafts 14-15 and 16-19 Merkle orders.

### roughtime-bench

Generate load against servers you control. Strict mode authenticates replies,
uses fresh cryptographic nonces, and shares retry backoff across workers. Each
query opens a connection.

```sh
roughtime-bench -addr localhost:5319 -pubkey <key> -workers 64 -duration 10s
```

Flex mode uses persistent sockets without reconnect backoff. Add `-verify` to
authenticate replies. Otherwise, malformed replies may count as successes.
Throughput counts successes. RTT excludes verification. Percentiles sample up to
100,000 replies. Results are not a production-capacity estimate.

### roughtime-stamp

Create or verify a document timestamp receipt. Stamping queries three compatible
endpoint-domain groups twice in the same order. Strict verification requires
that complete structure. Flex mode also accepts self-contained one-pass receipts
with at least two distinct trusted roots.

```sh
roughtime-stamp -doc document.pdf -servers servers.json -out document.proof
roughtime-stamp -mode verify -doc document.pdf -servers servers.json \
  -in document.proof
```

The document is hashed before querying and saving the proof. Verification checks
document binding, the causal chain, and witness trust. Retain a trusted server
list with the document and proof. Key revocation policy is the caller's
responsibility.

The first witness and network observers see the document's SHA-256 digest, which
can reveal repeat stamps or known contents. Input must be a regular file,
possibly reached through a symlink.

Causal contradictions are saved locally as `<out>.malfeasance.*`.

## Go API

The zero `Client` uses strict mode. Use `Query` for one server, `QueryAll` for
concurrent queries, or `QueryChain` and `QueryChainWithNonce` for causal chains.
Chain methods query the supplied order once. Complete RFC measurements require
independent operators and both passes supplied by the caller.

```go
client := &roughtime.Client{}
response, err := client.Query(ctx, roughtime.Server{
    PublicKey: rootPublicKey,
    Addresses: []roughtime.Address{{Transport: "udp", Address: "example.com:5319"}},
})
```

Set `Client.Mode = protocol.Flex` for compatibility. Protocol parsers,
verifiers, and builders also default to strict mode. Their `WithMode` or
`WithOptions` forms enable flex behavior. Proofs retain their selected mode.
Require both `proof.Verify()` and `proof.Trust(trustedServers)` to succeed.
These authenticate the chain and witnesses without establishing measurement
completeness.

See the [protocol
API](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol) for legacy
encoding options. Flex verification accepts both draft Merkle conventions. RFC
paths always use RFC ordering.

Google chains use the reference's double-hash nonce derivation. Flex mode also
verifies older single-hash proofs. MJD leap seconds add one second of
uncertainty when converted to Go time.

`NewCertificate` advertises version 1. Use `NewCertificateWithVersions` for
other version sets. Flex mode accepts draft signature contexts in version-1
packets, including RFC Appendix B. Strict mode requires RFC protocol contexts.

## Development

```sh
make deps        # install development tools
make test        # tests
make test-race   # race detector
make fuzz        # parser and verifier fuzzers
make lint        # go vet and staticcheck
make vuln        # reachable-vulnerability scan
make check       # dependencies, vendor, format, lint, security, build, race
```

Regenerate vendor files with `go mod vendor`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by the [BSD 2-Clause License](LICENSE).
