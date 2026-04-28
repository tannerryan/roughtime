# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)
![GitHub go.mod Go
version](https://img.shields.io/github/go-mod/go-version/tannerryan/roughtime?style=flat-square&color=blue)
[![Go Report
Card](https://goreportcard.com/badge/github.com/tannerryan/roughtime?style=flat-square)](https://goreportcard.com/report/github.com/tannerryan/roughtime)

A Go implementation of
[Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) covering
Google-Roughtime and IETF drafts 01–19. Ships a server, four CLIs (client,
debug, bench, stamp), and two Go packages: a high-level client in the [roughtime
package](roughtime.go) and wire primitives in the [protocol
package](protocol/protocol.go). Interop-tested with
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).
Drafts 12-19 share wire version `0x8000000c`; peers advertise this single tag
regardless of which draft they implement internally.

Try it against the public server at `time.txryan.com:2002`
([details](https://time.txryan.com)):

```bash
go run ./cmd/roughtime-client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
```

> ⚠️ **ML-DSA-44 (FIPS 204) is experimental and not part of any IETF draft.**
> Defined here as an ahead-of-spec extension, framed over TCP because replies
> exceed the UDP amplification cap. No interop guaranteed.

This implementation uses hash-first Merkle path verification across drafts
14–19, matching draft-16's spec. Drafts 14–15 specify node-first instead, so
multi-request batches against those two drafts diverge; single-request replies
have an empty PATH and are unaffected.

## Building

Requires Go 1.26 or newer.

```bash
make build
```

Produces five binaries at the repo root:

- `roughtime` — Roughtime server daemon
- `roughtime-client` — query servers, print timestamps
- `roughtime-debug` — diagnostic version probe
- `roughtime-bench` — closed-loop load generator
- `roughtime-stamp` — document timestamp proofs

To build one directly: `go build ./cmd/roughtime` (or any other `./cmd/<name>`).
See [Development](#development) for the full make targets.

## Server

Listens on a single port: UDP carries Ed25519 and Google-Roughtime, TCP carries
Ed25519 and the experimental ML-DSA-44 extension. Root keys are hex-encoded
seeds, and online delegation certificates auto-refresh before expiry. Set
`-root-key-file`, `-pq-root-key-file`, or both for dual-stack. `-keygen` and
`-pq-keygen` write a fresh seed (mode `0600`) and print its public key;
`-pubkey` and `-pq-pubkey` re-derive a public key from an existing seed.

```bash
roughtime -keygen /path/to/root.key
roughtime -pq-keygen /path/to/pq-root.key
roughtime -root-key-file /path/to/root.key -pq-root-key-file /path/to/pq-root.key
```

| Flag                | Default | Description                                    |
| ------------------- | ------- | ---------------------------------------------- |
| `-port`             | 2002    | Listen port (UDP and TCP)                      |
| `-root-key-file`    |         | Ed25519 root seed (UDP + TCP Ed25519)          |
| `-pq-root-key-file` |         | ML-DSA-44 root seed (TCP ML-DSA-44)            |
| `-grease-rate`      | 0.01    | Fraction of responses to grease (0 disables)   |
| `-log-level`        | info    | `debug`, `info`, `warn`, or `error`            |

### Architecture

Optimized for high throughput on Linux: per-CPU `SO_REUSEPORT` sockets, batched
syscalls, and amortized signing across up to 256 requests per round. Other Unix
systems use a single-socket fallback. TCP requests batch per scheme so each
connection gets its own Merkle proof from a shared signature. Windows is not
supported (`//go:build unix`).

### TCP framing

Each message is prefixed with an 8-byte `ROUGHTIM` magic and a little-endian
`uint32` length (12-byte header total). Google-Roughtime (no header) is
UDP-only; Ed25519 works over either transport; ML-DSA-44 is TCP-only. The TCP
server is hardened against malformed input: bad magic, request frames over 8192
bytes, zero-length bodies, and stalled reads close the connection.

### ML-DSA-44 wire variant (experimental)

An experimental post-quantum signature suite **not part of any IETF draft**,
defined here as an ahead-of-spec extension and advertised as version
`0x90000001` (`roughtime-ml-dsa-44`). The wire format is the modern IETF one;
only the signature algorithm and the FIPS 204 context replace Ed25519. Version
negotiation is per-scheme, so a client picks the highest mutually supported
version per suite. No interop guaranteed.

| Parameter          | Ed25519                  | ML-DSA-44                  |
| ------------------ | ------------------------ | -------------------------- |
| Public key size    | 32 bytes                 | 1312 bytes                 |
| Signature size     | 64 bytes                 | 2420 bytes                 |
| Context convention | byte-prefix (`ctx\|msg`) | FIPS 204 context parameter |
| Transport          | UDP or TCP               | TCP only                   |

### Docker

```bash
docker build -t roughtime:latest .
mkdir -p keys
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -keygen /keys/root.key
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -pq-keygen /keys/pq-root.key
docker run -d --name roughtime --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 2002:2002/udp -p 2002:2002/tcp -v "$PWD/keys:/keys:ro" \
  roughtime:latest -root-key-file /keys/root.key -pq-root-key-file /keys/pq-root.key
```

The distroless `nonroot` runtime writes keys as UID `65532`. If the host
`./keys` directory is owned by another UID, prefix the `-keygen` lines with
`--user "$(id -u):$(id -g)"` or `chown` the directory afterwards so the server
can read the seeds.

## CLIs

All four auto-detect the signature suite from the root public key length: 32
bytes for Ed25519, 1312 bytes for ML-DSA-44.

### client

Queries one or more servers and prints authenticated timestamps alongside clock
drift. With `-servers`, it samples 3 entries (or `-all`) and queries each twice
to surface pairwise inconsistencies. Multi-server queries are chained by
default.

```bash
go run ./cmd/roughtime-client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run ./cmd/roughtime-client -servers ecosystem.json [-all] [-tcp] [-chain=false]
```

| Flag       | Default | Description                                                     |
| ---------- | ------- | --------------------------------------------------------------- |
| `-servers` |         | JSON server list (mutually exclusive with `-addr`)              |
| `-addr`    |         | Single server `host:port` (requires `-pubkey`)                  |
| `-pubkey`  |         | Root public key (base64 or hex) for `-addr`                     |
| `-name`    |         | With `-servers`, query only the named server                    |
| `-tcp`     | false   | Force TCP; ML-DSA-44 keys always use TCP                        |
| `-all`     | false   | Query every entry in `-servers` (default samples 3)             |
| `-chain`   | true    | Causally chain queries (sequential; nonce derives from prev)    |
| `-timeout` | 500ms   | Read/write timeout per attempt                                  |
| `-retries` | 3       | Maximum attempts per server (1s × 1.5^(n-1) backoff)            |

### debug

Probes one server, lists supported versions, and dumps request, response,
signatures, and delegation certificate.

```bash
go run ./cmd/roughtime-debug -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= [-tcp] [-ver draft-12]
```

| Flag       | Default | Description                                          |
| ---------- | ------- | ---------------------------------------------------- |
| `-addr`    |         | Server `host:port`                                   |
| `-pubkey`  |         | Root public key (base64 or hex)                      |
| `-tcp`     | false   | Force TCP; ML-DSA-44 keys always use TCP             |
| `-ver`     |         | Probe only one version (e.g. `draft-12`, `Google`)   |
| `-timeout` | 500ms   | Per-version probe timeout                            |
| `-retries` | 3       | Maximum attempts per version                         |

### bench

Closed-loop load generator. Reports throughput, latency percentiles, and an
error breakdown. `-verify` signature-checks every reply client-side; since
ML-DSA-44 verification is materially slower than Ed25519, leave it off when
measuring raw throughput.

```bash
go run ./cmd/roughtime-bench -addr <host:port> -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s [-tcp] [-verify]
```

| Flag        | Default        | Description                                   |
| ----------- | -------------- | --------------------------------------------- |
| `-addr`     | 127.0.0.1:2002 | Server `host:port`                            |
| `-pubkey`   |                | Root public key (base64 or hex)               |
| `-tcp`      | false          | Force TCP; ML-DSA-44 keys always use TCP      |
| `-workers`  | 64             | Concurrent client sockets                     |
| `-duration` | 10s            | Measurement duration                          |
| `-warmup`   | 2s             | Warmup before measurement (samples discarded) |
| `-timeout`  | 500ms          | Per-request read/write timeout                |
| `-verify`   | false          | Verify every reply                            |

### stamp

Document timestamping. Produces an offline-verifiable proof binding a document
to a chain of witness signatures, and later re-validates that proof against the
document and a trusted ecosystem. Witnesses need 32-byte nonces (IETF Ed25519
drafts 05+ and experimental ML-DSA-44); Google-Roughtime entries are skipped.

```bash
go run ./cmd/roughtime-stamp -doc README.md -servers ecosystem.json -out README.md.proof
go run ./cmd/roughtime-stamp -mode verify -doc README.md -servers ecosystem.json -in README.md.proof
```

| Flag       | Default          | Description                       |
| ---------- | ---------------- | --------------------------------- |
| `-mode`    | stamp            | `stamp` (write proof) or `verify` |
| `-doc`     |                  | Document to timestamp / verify    |
| `-servers` | `ecosystem.json` | Ecosystem JSON (witness pool)     |
| `-out`     |                  | Proof output path (stamp mode)    |
| `-in`      |                  | Proof input path (verify mode)    |
| `-timeout` | 2s               | Per-server timeout                |
| `-retries` | 3                | Maximum retry attempts per server |

## Library

The CLIs are thin wrappers over two packages.

### High-level client — `github.com/tannerryan/roughtime`

```go
pk, _ := roughtime.DecodePublicKey("iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=")
server := roughtime.Server{
    Name:      "time.txryan.com",
    PublicKey: pk,
    Addresses: []roughtime.Address{{Transport: "udp", Address: "time.txryan.com:2002"}},
}

var c roughtime.Client
resp, err := c.Query(ctx, server)
// resp.Midpoint, resp.Radius, resp.RTT, resp.Drift(), resp.InSync()
```

Beyond a single `Query`, the package offers concurrent fan-out across servers
(`QueryAll`), causal-chained multi-server queries with offline-verifiable proofs
(`QueryChain`/`Proof`), and document timestamping (`QueryChainWithNonce`).
Helpers cover drift consensus, replay verification, and ecosystem JSON parsing.
Full API at [pkg.go.dev](https://pkg.go.dev/github.com/tannerryan/roughtime).

### Wire primitives — `github.com/tannerryan/roughtime/protocol`

Encodes and decodes Roughtime messages and round-trips them over UDP or TCP.
Full API on
[pkg.go.dev](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol).

```go
nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPublicKey, nonce, request)
```

`srv` is the server's public key, used for SRV-tag binding from drafts 10+. A
chain primitive supports multi-server measurement and malfeasance detection:

```go
var chain protocol.Chain
for _, server := range servers {
    link, err := chain.NextRequest(versions, server.PublicKey, rand.Reader)
    // ... send link.Request, set link.Response ...
    chain.Append(link)
}
err := chain.Verify()                     // nonce linkage + causal ordering
report, err := chain.MalfeasanceReport()  // JSON malfeasance report
```

Server side — parse and sign a batch:

```go
cert, err := protocol.NewCertificate(mint, maxt, onlineSK, rootSK)
req, err := protocol.ParseRequest(raw)
replies, err := protocol.CreateReplies(version, requests, midpoint, radius, cert)
```

## Example output

### client

Single server:

```text
$ go run ./cmd/roughtime-client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   udp://time.txryan.com:2002
Version:   draft-ietf-ntp-roughtime-12
Midpoint:  2026-04-28T00:57:28Z
Radius:    3s
Window:    [2026-04-28T00:57:25Z, 2026-04-28T00:57:31Z]
RTT:       51ms
Local:     2026-04-28T00:57:28.195661Z
Drift:     -170ms
Status:    in-sync
```

Ecosystem (chained, queried twice in opposite halves):

```text
$ go run ./cmd/roughtime-client -servers ecosystem.json -all
NAME                            ADDRESS                                    VERSION    MIDPOINT              RADIUS    RTT     DRIFT     STATUS
time.txryan.com                 udp://time.txryan.com:2002                 draft-12   2026-04-28T00:57:28Z  ±3s       49ms    -290ms    in-sync
time.txryan.com-pq              tcp://time.txryan.com:2002                 ml-dsa-44  2026-04-28T00:57:28Z  ±3s       50ms    -387ms    in-sync
Cloudflare-Roughtime-2          udp://roughtime.cloudflare.com:2003        draft-11   2026-04-28T00:57:28Z  ±1s       17ms    -423ms    in-sync
roughtime.se                    udp://roughtime.se:2002                    draft-12   2026-04-28T00:57:28Z  ±1s       146ms   -506ms    in-sync
sth1.roughtime.netnod.se        udp://sth1.roughtime.netnod.se:2002        draft-07   2026-04-28T00:57:28Z  ±66µs     139ms   12ms      out-of-sync
sth2.roughtime.netnod.se        udp://sth2.roughtime.netnod.se:2002        draft-07   2026-04-28T00:57:28Z  ±41µs     137ms   10ms      out-of-sync
time.teax.dev                   udp://time.teax.dev:2002                   draft-12   2026-04-28T00:57:28Z  ±3s       156ms   -943ms    in-sync
roughtime.sturdystatistics.com  udp://roughtime.sturdystatistics.com:2002  draft-12   2026-04-28T00:57:29Z  ±10s      184ms   -120ms    in-sync
TimeNL-Roughtime                udp://rough.time.nl:2002                   draft-12   2026-04-28T00:57:29Z  ±3s       148ms   -290ms    in-sync

9/9 servers responded
Consensus drift:    -290ms (median of 9 samples)
Corrected local:    2026-04-28T00:57:30Z (now + median drift)
Drift spread:       955ms (min=-943ms, max=12ms)
Chain:              ok (18 links verified)
```

### debug

```text
$ go run ./cmd/roughtime-debug -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
=== Version Probe: time.txryan.com:2002 (udp) ===
Timeout: 500ms
  draft-ietf-ntp-roughtime-12              OK
  draft-ietf-ntp-roughtime-11              OK
  draft-ietf-ntp-roughtime-10              OK
  draft-ietf-ntp-roughtime-09              OK
  draft-ietf-ntp-roughtime-08              OK
  draft-ietf-ntp-roughtime-07              OK
  draft-ietf-ntp-roughtime-06              OK
  draft-ietf-ntp-roughtime-05              OK
  draft-ietf-ntp-roughtime-04              OK
  draft-ietf-ntp-roughtime-03              OK
  draft-ietf-ntp-roughtime-02              OK
  draft-ietf-ntp-roughtime-01              OK
  Google-Roughtime                         OK

Supported versions: draft-12, draft-11, draft-10, draft-09, draft-08, draft-07, draft-06, draft-05, draft-04, draft-03, draft-02, draft-01, Google
Negotiated:         draft-ietf-ntp-roughtime-12

=== Request ===
Size: 1024 bytes
00000000  52 4f 55 47 48 54 49 4d  f4 03 00 00 05 00 00 00  |ROUGHTIM........|
00000010  04 00 00 00 24 00 00 00  44 00 00 00 48 00 00 00  |....$...D...H...|
00000020  56 45 52 00 53 52 56 00  4e 4f 4e 43 54 59 50 45  |VER.SRV.NONCTYPE|
00000030  5a 5a 5a 5a 0c 00 00 80  a8 f7 e4 05 17 82 a3 71  |ZZZZ...........q|
...

--- Request Tags ---
  VER:  0c000080 (draft-12)
  SRV: a8f7e4051782a37194a6cb51d94ac8f13d2c3c9e32d0c049ec3de42b40bc6c66
  NONC: 6f6614ece1871bb4b8c15e4c6f21e627fabaf520daf2f213aa148b79ed6fdb1d
  TYPE: 00000000 (request)
  ZZZZ: (900 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
...

--- Response Tags ---
  SIG: 68ac3af8a4baeef2c00b798f5be26767e5e5251aabdf82d6b0ea5691a232f19fc8f920c3a268a33ab1cf06b8f1b53d63db2057a4660ee97c5e1dee8a3fc1800b
  NONC: 6f6614ece1871bb4b8c15e4c6f21e627fabaf520daf2f213aa148b79ed6fdb1d
  TYPE: 01000000 (response)
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000

=== Verified Result ===
Round-trip time: 46.027917ms
Midpoint:        2026-04-28T00:57:30Z
Radius:          3s
Local time:      2026-04-28T00:57:30.622688Z
Clock drift:     -600ms
Amplification:   ok (reply 460 <= request 1024)

=== Response Details ===
Signature:       68ac3af8a4baeef2c00b798f5be26767e5e5251aabdf82d6b0ea5691a232f19fc8f920c3a268a33ab1cf06b8f1b53d63db2057a4660ee97c5e1dee8a3fc1800b
Nonce:           6f6614ece1871bb4b8c15e4c6f21e627fabaf520daf2f213aa148b79ed6fdb1d
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     2ecde0b0360b0bd0086c940b1dcf1385b86d0096b4099f05a85a8b51764efeae
Midpoint (raw):  1777337850 Unix-s (2026-04-28T00:57:30Z)
Radius (raw):    3 s
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       4bfcc753ecda7695784078a1d1583606186372dd9014666f7375258e778a3c18d0ef109deee538c9fd25daa6196a8a0d01e4fa4ca9bd50ae9ddb9d2114c90204
Online key:      502a004699b6805d67914caab3e6a46454aa77925494497fd34af7858d1bfc9b
Not before:      2026-04-27T13:36:14Z
Not after:       2026-04-28T13:36:14Z
Expires in:      12h38m44s
Cert validity:   ok (midpoint within window)
```

## Development

```bash
make deps             # install dev tools
make all              # default: fmt, vet, build, race tests
make build            # build all five binaries
make test             # unit tests
make test-race        # unit tests with race detector
make test-cover       # coverage (roughtime + protocol + cmd/roughtime)
make test-race-cover  # race + coverage profile (CI)
make fuzz             # all fuzz targets (FUZZ_TIME=30s each)
make verify           # go mod download + verify
make verify-tidy      # confirm go.mod and go.sum are tidy
make coverage-report  # per-function summary + HTML report
make lint             # vet + staticcheck + golangci-lint + gopls
make check            # full suite (verify, fmt, vet, lint, build, race+cover, report card)
make clean            # remove built binaries and coverage artifacts
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
