# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
01–19.

Note: Drafts 05–13 use node-first Merkle order; drafts 14–19 use hash-first
(draft-16 reversed the convention, and the implementation follows the latest
spec across the 14–19 range). Multi-request batches are therefore not strictly
conformant to drafts 14–15 only (drafts 16–19 match). Single-request replies are
unaffected.

Interoperability testing is available at
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

## Server

The root package is a UDP Roughtime server. It reads a hex-encoded Ed25519 root
key seed from disk, generates online delegation certificates, and automatically
refreshes them before expiry.

```
roughtime -keygen /path/to/root.key
roughtime -root-key-file /path/to/root.key [-port 2002] [-log-level info] [-grease-rate 0.01]
roughtime -version
```

Generate a root key pair with `-keygen`. The seed is written to the given path
(mode `0600`) and the public key is printed in hex and base64. Use `-pubkey` to
derive the public key from an existing seed file.

The root key file must be mode `0600` or stricter.

| Flag           | Default | Description                                    |
| -------------- | ------- | ---------------------------------------------- |
| `-grease-rate` | 0.01    | Fraction of responses to grease (0 to disable) |

On Linux, the server binds one `SO_REUSEPORT` socket per CPU and each worker
drains its own queue with `recvmmsg`/`sendmmsg`, batching up to 256 requests (or
1ms, whichever comes first) per signing round. On other Unix systems it falls
back to a single UDP socket feeding one batcher goroutine over a buffered
channel, with the same 256/1ms batch window. Windows is not supported.

## Client

The `client` command queries one or more Roughtime servers and prints
authenticated timestamps with clock drift. Multi-server queries are chained by
default.

When using `-servers`, the client randomly selects 3 servers from the ecosystem
and queries them twice in the same order so all pairwise inconsistencies can be
detected. Pass `-all` to query every server instead.

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -servers ecosystem.json
go run client/main.go -servers ecosystem.json -all
go run client/main.go -servers ecosystem.json -chain=false [-retries 3]
go run client/main.go -version
```

## Debug

The `debug` command probes a Roughtime server to discover its supported protocol
versions and prints a full diagnostic dump.

```
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= -retries 5
go run debug/main.go -version
```

## Public Server

A public Roughtime server is available at `time.txryan.com:2002`. Additional
details can be found at [time.txryan.com](https://time.txryan.com).

## Example Output

### Client

Single server:

```
$ go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   time.txryan.com:2002
Version:   draft-ietf-ntp-roughtime-12
Midpoint:  2026-04-16T03:31:06Z
Radius:    3s
Window:    [2026-04-16T03:31:03Z, 2026-04-16T03:31:09Z]
RTT:       48ms
Local:     2026-04-16T03:31:06.455974Z
Drift:     -456ms
Status:    in-sync
```

Multiple servers:

```
$ go run client/main.go -servers ecosystem.json
NAME                            ADDRESS                              VERSION   MIDPOINT              RADIUS    RTT     DRIFT     STATUS
roughtime.sturdystatistics.com  roughtime.sturdystatistics.com:2002  draft-12  2026-04-16T03:31:06Z  ±10s      180ms   -700ms    in-sync
roughtime.se                    roughtime.se:2002                    draft-12  2026-04-16T03:31:06Z  ±1s       141ms   -844ms    in-sync
time.txryan.com                 time.txryan.com:2002                 draft-12  2026-04-16T03:31:06Z  ±3s       50ms    -898ms    in-sync
roughtime.sturdystatistics.com  roughtime.sturdystatistics.com:2002  draft-12  2026-04-16T03:31:07Z  ±10s      182ms   -84ms     in-sync
roughtime.se                    roughtime.se:2002                    draft-12  2026-04-16T03:31:07Z  ±1s       141ms   -229ms    in-sync
time.txryan.com                 time.txryan.com:2002                 draft-12  2026-04-16T03:31:07Z  ±3s       52ms    -285ms    in-sync

6/6 servers responded
Consensus drift:    -844ms (median of 3 samples)
Consensus midpoint: 2026-04-16T03:31:06Z
Drift spread:       198ms (min=-898ms, max=-700ms)
Chain:              ok (6 links verified)
```

### Debug

```
$ go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
=== Version Probe: time.txryan.com:2002 ===
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
  VER: 0c000080
  SRV: a8f7e4051782a37194a6cb51d94ac8f13d2c3c9e32d0c049ec3de42b40bc6c66
  NONC: 9931117699a2b0b729d4cb422cb28dfed8e9e2ad0072f3d574167820d145f808
  TYPE: 00000000
  ZZZZ: (900 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
...

--- Response Tags ---
  SIG: 440215c33763c7b1893a7d576f67b58b5a82f36600c884c7de4f01d7e6e08c7ae013f203b6a0f5151a120090806afc7a6063edb23a84a15a387a06cb67847907
  NONC: 9931117699a2b0b729d4cb422cb28dfed8e9e2ad0072f3d574167820d145f808
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 49.931125ms
Midpoint:        2026-04-16T03:31:07Z
Radius:          3s
Local time:      2026-04-16T03:31:07.421811Z
Clock drift:     -422ms
Amplification:   ok (reply 460 ≤ request 1024)

=== Response Details ===
Signature:       440215c33763c7b1893a7d576f67b58b5a82f36600c884c7de4f01d7e6e08c7ae013f203b6a0f5151a120090806afc7a6063edb23a84a15a387a06cb67847907
Nonce:           9931117699a2b0b729d4cb422cb28dfed8e9e2ad0072f3d574167820d145f808
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     bcfea9809630e18bf48285cdfb0a069923838a1db3f9b6792c02cc183423f110
Midpoint (raw):  1776310267 (2026-04-16T03:31:07Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       d97b5bbed2b7acfa853285713de7072cb0ef1d8672486bc09c02ff6a2c771e72ea721370c79b162c05b344dc12da7514695ab43385cd1771a16802ef4a011f0f
Online key:      a593d831d1a4ceaf0048c737ae7a2ceaa98a94ca476ca73894192d34d7e95e8e
Not before:      2026-04-15T21:30:40Z
Not after:       2026-04-16T21:30:40Z
Expires in:      17h59m32s
Cert validity:   ok (midpoint within window)
```

## Protocol

The `protocol` package implements the Roughtime wire format for both server and
client use. See the [package
documentation](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol) for
the full API and wire group details.

### Client

Build a request, send it over UDP, and verify the signed response:

```go
nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPublicKey, nonce, request)
```

The optional `srv` parameter includes the SRV tag (drafts 10+) for server key
binding. `CreateRequestWithNonce` accepts a caller-supplied nonce for use cases
such as document timestamping, where the nonce is a cryptographic hash of the
payload.

### Chaining

For multi-server measurement and malfeasance detection:

```go
var chain protocol.Chain
for _, server := range servers {
    link, err := chain.NextRequest(versions, server.PublicKey, rand.Reader)
    // ... send link.Request, set link.Response ...
    chain.Append(link)
}
err := chain.Verify()            // checks nonce linkage + causal ordering
report, err := chain.MalfeasanceReport() // JSON malfeasance report
```

### Server

Parse incoming requests, sign a batch of responses:

```go
cert, err := protocol.NewCertificate(mint, maxt, onlineSK, rootSK)
req, err := protocol.ParseRequest(raw)
replies, err := protocol.CreateReplies(version, requests, midpoint, radius, cert)
```

## Docker

Build the image, generate a root key into `./keys`, and run the server with the
key mounted read-only:

```
docker build -t roughtime:latest .
mkdir -p keys
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -keygen /keys/root.key
docker run -d \
  --name roughtime \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 2002:2002/udp \
  -v "$PWD/keys:/keys:ro" \
  roughtime:latest -root-key-file /keys/root.key
```

## Benchmark

bench is a closed-loop UDP load generator for stress-testing a running server.
Each worker owns one socket, fires a well-formed request, waits for the reply,
and repeats. It reports throughput, latency percentiles, and an error breakdown.

```
go run bench/main.go -addr <host:port> -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s
```

With `-verify`, every reply is signature-checked against the root public key.
Verification adds ~100µs/reply of client CPU, so leave it off for pure
throughput numbers.

## Development

A Makefile is provided for building, testing, linting, and fuzzing.

```
make deps             # install dev tools
make build            # build roughtime, roughtime-client, roughtime-debug, roughtime-bench
make test             # unit tests
make test-race        # unit tests with race detector
make test-cover       # unit tests with coverage (protocol + server)
make test-race-cover  # race detector + coverage profile, protocol + server (used by CI)
make fuzz             # run all fuzz targets (FUZZ_TIME=30s each)
make verify           # go mod download + go mod verify (module integrity)
make coverage-report  # test-race-cover + per-function summary + HTML report
make lint             # vet + staticcheck + golangci-lint + gopls
make check            # full suite (verify, fmt, vet, lint, build, race+cover, report card)
make clean            # remove built binaries and coverage artifacts
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
