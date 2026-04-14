# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
01–19.

Note: the drafts 12–19 wire group uses the draft-16+ hash-first Merkle order, so
multi-request batches are not strictly conformant to drafts 14–15 (which
specified node-first before draft 16 reversed it). Single-request replies are
unaffected.

Interoperability testing is available at
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

## Server

The root package is a UDP Roughtime server. It reads a hex-encoded Ed25519 root
key seed from disk, generates online delegation certificates, and automatically
refreshes them before expiry.

```
roughtime -keygen /path/to/root.key
roughtime -pubkey /path/to/root.key
roughtime -root-key /path/to/root.key [-port 2002] [-log-level info] [-grease-rate 0.01]
roughtime -version
```

Generate a root key pair with `-keygen`. The seed is written to the given path
(mode `0600`) and the public key is printed in hex and base64. Use `-pubkey` to
derive the public key from an existing seed file.

The root key file must be mode `0600` or stricter.

| Flag                 | Default | Description                                     |
| -------------------- | ------- | ----------------------------------------------- |
| `-batch-max-size`    | 64      | Maximum requests per signing batch              |
| `-batch-max-latency` | 5ms     | Maximum wait before signing an incomplete batch |
| `-grease-rate`       | 0.01    | Fraction of responses to grease (0 to disable)  |

## Client

The `client` command queries one or more Roughtime servers and prints
authenticated timestamps with clock drift. Multi-server queries are chained by
default per Section 8.2.

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -servers ecosystem.json
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
Midpoint:  2026-04-12T02:10:00Z
Radius:    3s
Window:    [2026-04-12T02:09:57Z, 2026-04-12T02:10:03Z]
RTT:       50ms
Local:     2026-04-12T02:10:00.92334Z
Drift:     -923ms
Status:    in-sync
```

Multiple servers:

```
$ go run client/main.go -servers ecosystem.json
NAME                            ADDRESS                         VERSION         MIDPOINT              RADIUS    RTT         DRIFT         STATUS
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-12T02:10:01Z  ±3s       52ms        -49ms         in-sync
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-12T02:10:01Z  ±1s       18ms        -70ms         in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-12T02:10:01Z  ±1s       142ms       -213ms        in-sync
sth1.roughtime.netnod.se        sth1.roughtime.netnod.se:2002   draft-07        2026-04-12T02:10:01Z  ±62µs     132ms       -62ms         in-sync
time.teax.dev                   time.teax.dev:2002              draft-12        2026-04-12T02:10:01Z  ±3s       148ms       -498ms        in-sync
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-12T02:10:01Z  ±3s       48ms        -548ms        in-sync
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-12T02:10:01Z  ±1s       15ms        -567ms        in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-12T02:10:01Z  ±1s       142ms       -711ms        in-sync
sth1.roughtime.netnod.se        sth1.roughtime.netnod.se:2002   draft-07        2026-04-12T02:10:01Z  ±62µs     133ms       -63ms         in-sync
time.teax.dev                   time.teax.dev:2002              draft-12        2026-04-12T02:10:01Z  ±3s       148ms       -998ms        in-sync

10/10 servers responded
Consensus drift:    -356ms (median of 10 samples)
Consensus midpoint: 2026-04-12T02:10:01Z
Drift spread:       949ms (min=-998ms, max=-49ms)
Chain:              ok (10 links verified)
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
  NONC: ed8cd882163bce5b80eafcd5d7fe7df2f0b9b231e6bf8aed841b52f930776665
  TYPE: 00000000
  ZZZZ: (900 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
...

--- Response Tags ---
  SIG: c214f9ebb43aac39e032565a0584555282fe83438034208985c62b56dd2b78c490fab4dcd50040ca4a9a6a2968c8fc078dfde98dc1b421dc6cb4ab15839b2c0c
  NONC: ed8cd882163bce5b80eafcd5d7fe7df2f0b9b231e6bf8aed841b52f930776665
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 49.332333ms
Midpoint:        2026-04-12T02:10:02Z
Radius:          3s
Local time:      2026-04-12T02:10:02.352742Z
Clock drift:     -353ms
Amplification:   ok (reply 460 ≤ request 1024)

=== Response Details ===
Signature:       c214f9ebb43aac39e032565a0584555282fe83438034208985c62b56dd2b78c490fab4dcd50040ca4a9a6a2968c8fc078dfde98dc1b421dc6cb4ab15839b2c0c
Nonce:           ed8cd882163bce5b80eafcd5d7fe7df2f0b9b231e6bf8aed841b52f930776665
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     253382b5ee9072759359ba33029892007efec73351f4242bfe34ec52a558f256
Midpoint (raw):  1775959802 (2026-04-12T02:10:02Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       8a2b409ca1332d073fc96973539bc05817f1ab8e984bdb333ec7d21a04e09d04022194d55f2042961a9505a7ac8d5c67e24b1ac069f18a62592aba474e2fd00c
Online key:      413221d151ccee029e836bc5b4a566594748983452f1a7ec972573f533b24e0b
Not before:      2026-04-11T20:08:24Z
Not after:       2026-04-12T20:08:24Z
Expires in:      17h58m21s
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

For multi-server measurement and malfeasance detection (Section 8.2):

```go
var chain protocol.Chain
for _, server := range servers {
    link, err := chain.NextRequest(versions, server.PublicKey, rand.Reader)
    // ... send link.Request, set link.Response ...
    chain.Append(link)
}
err := chain.Verify()            // checks nonce linkage + causal ordering
report, err := chain.MalfeasanceReport() // JSON per Section 8.4
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
docker run --rm -v "$PWD/keys:/keys:ro" roughtime:latest -pubkey /keys/root.key
docker run -d \
  --name roughtime \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 2002:2002/udp \
  -v "$PWD/keys:/keys:ro" \
  roughtime:latest -root-key /keys/root.key
```

## Development

A Makefile is provided for building, testing, linting, and fuzzing.

```
make deps             # install dev tools
make build            # build roughtime, roughtime-client, roughtime-debug
make test             # unit tests
make test-race        # unit tests with race detector
make test-cover       # unit tests with coverage (protocol package)
make test-race-cover  # race detector + coverage profile, protocol package (used by CI)
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
