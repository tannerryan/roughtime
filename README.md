# roughtime

[![Go
Reference](https://pkg.go.dev/badge/github.com/tannerryan/roughtime.svg)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![License](https://img.shields.io/github/license/tannerryan/roughtime.svg)](LICENSE)

A Go implementation of Google-Roughtime and IETF Roughtime drafts 01–19. The
repository contains a high-level client package, the low-level
[protocol](protocol) package, a high-throughput server, and client, debug,
benchmark, and document-stamping commands.

Drafts 12–19 share wire version `0x8000000c`. Drafts 14–19 add the `TYPE`
exchange without changing that value, so clients must support both typed and
untyped peers.

Try the public server:

```sh
go run ./cmd/roughtime-client -addr time.txryan.com:2002 \
  -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
```

> ML-DSA-44 support is an experimental, non-IETF extension. It uses the FIPS
> 204 context parameter and TCP framing because its replies exceed the UDP
> amplification budget. It is not interoperable with standard Roughtime
> implementations.

## Build

Go 1.27 or newer is required.

```sh
make build
```

This produces `roughtime`, `roughtime-client`, `roughtime-debug`,
`roughtime-bench`, and `roughtime-stamp`. Run any command with `-h` for its
complete flag list.

## Server

The server accepts IETF Ed25519 requests over UDP and TCP and Google-Roughtime
over UDP. The experimental ML-DSA-44 suite uses TCP only. The Linux UDP path
uses one `SO_REUSEPORT` socket per `GOMAXPROCS` worker and batched I/O. OpenBSD
7.2 or later is required for `recvmmsg`/`sendmmsg`. OpenBSD batches I/O and
signs on one goroutine per socket. Its wildcard binds use one socket per address
family because it lacks IPv4-mapped IPv6. Other Unix systems use a portable
socket loop. Windows is not supported.

Generate a root key and start the server:

```sh
roughtime -keygen /path/to/root.key
roughtime -root-key-file /path/to/root.key
```

Use `-pq-keygen` and `-pq-root-key-file` for ML-DSA-44, or configure both root
files. Seed-file permissions are no broader than `0600`, and existing files are
never overwritten. Online delegation certificates refresh automatically. With
`-offline-delegation`, root files are read only during startup and the server
stops when the delegation leaves its validity window.

The host clock must stay within the advertised radius (3 seconds by default).
The server does not discipline it. With both root keys configured, drafts 10+
and ML-DSA-44 TCP requests must include `SRV` to select their root.

By default the server greases 1% of responses to exercise client error paths.
Set `-grease-rate 0` when deterministic replies are required.

UDP and TCP share `-port` (default 2002). On multihomed hosts, `-listen-address`
binds both listeners to the advertised local address so UDP replies retain that
source. `-metrics-addr` enables unauthenticated Prometheus `/metrics` and
`/healthz` endpoints. Bind it to loopback unless an external access-control
layer protects it.

### Docker

```sh
docker build -t roughtime .
mkdir -p keys
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/keys:/keys" \
  roughtime -keygen /keys/root.key
docker run --read-only --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 2002:2002/udp -p 2002:2002/tcp -v "$PWD/keys:/keys:ro" \
  roughtime -root-key-file /keys/root.key
```

The example uses the host user so the generated private key remains readable.
Without `--user`, the runtime image uses UID 65532 and mounted files must be
readable by that UID.

## Commands

### roughtime-client

Query one server with `-addr` and `-pubkey`, or an ecosystem with `-servers`.
Multi-server queries form a one-pass causal chain unless `-chain=false` is set.
The default samples up to five endpoint-domain groups. `-all` disables sampling
and queries every transport-compatible entry. That grouping is a diversity
heuristic, not authenticated operator identity or Sybil resistance.

`-two-pass` requires two complete passes in the same order across at least three
endpoint-domain groups and three distinct trust roots. `-standard-size` sends
message-sized padding for peers that require it. The default retains legacy
packet sizing. Direct queries select IETF versions. Use an ecosystem entry for
Google-Roughtime.

Drift is an RTT-center estimate, affected by asymmetric network delay. Clock
status tests whether the signed time window overlaps the local exchange
interval. The median summarizes endpoint samples, not clock agreement. A valid
partial chain is not a complete measurement.

```sh
go run ./cmd/roughtime-client -servers ecosystem.json -all
```

### roughtime-debug

Probe supported versions and inspect authenticated response structure and timing
data. A full scan tries draft 12 in typed and untyped forms. With `-ver
draft-12`, untyped is tried only if typed probing fails.

Failed probes share exponential backoff capped at 3 seconds. The default
5-minute `-scan-timeout` allows all forms and padding fallbacks at the default
attempt settings. The high-level client keeps its 24-hour backoff cap.
Legacy-sized UDP probes also try standard padding before reporting failure. A
`draft-14+` result cannot distinguish drafts 14–19 because a single-leaf reply
does not test their differing multi-leaf Merkle conventions.

```sh
go run ./cmd/roughtime-debug -addr time.txryan.com:2002 \
  -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
```

### roughtime-bench

A closed-loop load generator intended for servers you control. `-verify` checks
each signature and Merkle proof. Without it, results measure transport only and
may count malformed replies.

There is no target rate or reconnect backoff. Throughput counts successful
replies. Verification consumes client CPU but is excluded from RTT. Percentiles
use a uniform sample of at most 100,000 replies. Closed-loop results, including
in-flight requests at shutdown, are not a production-capacity estimate.

```sh
go run ./cmd/roughtime-bench -addr 127.0.0.1:2002 -pubkey <key> \
  -workers 64 -duration 10s -verify
```

### roughtime-stamp

Create or verify a document timestamp receipt. New receipts select three
compatible endpoint-domain groups and query them twice in the same order. The
document is hashed before querying and again immediately before the proof is
durably persisted. Verification checks the document, the full causal chain, and
the trusted ecosystem. Existing self-contained one-pass proofs remain readable
and are reported as legacy receipts. Keep a copy of the ecosystem from a trusted
source with the document and proof. Decide separately how to handle later key
revocations.

The first witness and on-path observers see the document's SHA-256 digest and
can recognize repeat stamps or guess known contents. `-standard-size` selects
message-sized request padding. Legacy packet sizing remains the default. Input
paths must name regular files (symlinks to regular files are accepted).

Causal contradictions are saved beside the requested output as
`<out>.malfeasance.*`, without replacing a successful receipt or reporting to an
external service.

```sh
go run ./cmd/roughtime-stamp -doc README.md -servers ecosystem.json \
  -out README.md.proof
go run ./cmd/roughtime-stamp -mode verify -doc README.md \
  -servers ecosystem.json -in README.md.proof
```

## Go API

The top-level package provides `Client.Query`, concurrent `QueryAll`, causal
`QueryChain`, document-bound `QueryChainWithNonce`, consensus helpers, proof
serialization and offline verification, and ecosystem parsing.

```go
pk, err := roughtime.DecodePublicKey(encodedKey)
if err != nil {
    return err
}
server := roughtime.Server{
    Name:      "example",
    PublicKey: pk,
    Addresses: []roughtime.Address{{
        Transport: "udp",
        Address:   "example.com:2002",
    }},
}
response, err := new(roughtime.Client).Query(ctx, server)
```

Accept an offline proof only after both `proof.Verify()` and
`proof.Trust(trustedServers)` succeed. Valid signatures alone do not establish
witness trust.

The [protocol
package](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol) exposes
request parsing/building, reply creation and verification, transports, version
negotiation, chaining, and malfeasance reports.

Compatibility details for low-level callers:

- IETF request builders use a 1024-byte body, and ML-DSA-44 uses 8192 bytes. The
  12-byte `ROUGHTIM` frame is additional.
- `RequestOptions.LegacyPacketSize` produces the historical 1024/8192-byte total
  packet size required by some deployed peers. The high-level client uses it by
  default. Set `Client.StandardPacketSize` to request the full message-sized
  form instead.
- `RequestOptions.OmitTYPE` produces the untyped drafts 12/13 request.
- `VerifyOptions.RequireTYPE` requires the draft-14+ typed exchange. The default
  verifier accepts both forms.
- `ReplyOptions.Draft14NodeFirst` selects the node-first Merkle convention from
  drafts 14–15. The default builder and server command use the draft-16+
  hash-first form for backward compatibility. Verification accepts both forms.
  The server command has no node-first option for strict draft-14/15 peers.
- `NewCertificateWithVersions` binds the signed `VERS` list to a server's actual
  advertised versions.
- Outgoing version lists and typed exchanges are limited to 32 entries. Untyped
  input tolerates longer lists within the codec's size limits for compatibility
  with drafts before 13. Draft 13 introduced the cap without changing the
  draft-12 wire identifier.

`ComputeSRV(rootPublicKey)` returns the drafts 10+ server binding. Verifiers
check negotiated versions, signed `VERS`, `SRV`, delegation validity,
signatures, nonces, timestamps, and Merkle proofs.

## Development

```sh
make deps        # install development tools once
make test        # tests
make test-race   # race detector
make fuzz        # parser/verifier fuzzers (FUZZ_TIME defaults to 30s)
make lint        # go vet and staticcheck
make vuln        # reachable-vulnerability scan
make check       # dependency, vendor, format, lint, security, build, race
```

The vendor tree is excluded from source edits and is checked for reproducibility
with `make verify-vendor`.

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by the [BSD 2-Clause License](LICENSE).
