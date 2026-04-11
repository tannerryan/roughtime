# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
01–19.

Note: drafts 14 and 15 specify a node-first Merkle leaf-to-root hashing order
(`H(0x01 || node || hash)` when the path bit is 0) that was reversed to
hash-first in draft 16. This implementation uses the draft-16+ hash-first order
for all of the drafts 12–19 wire group, so it is not strictly conformant to
drafts 14 and 15 for multi-request batches. Single-request replies (the
overwhelming majority in practice) are unaffected.

Interoperability testing is available at
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

## Server

The root package is a UDP Roughtime server. It reads a hex-encoded Ed25519 root
key seed from disk, generates online delegation certificates, and automatically
refreshes them before expiry.

```
roughtime -root-key /path/to/seed.hex [-port 2002] [-log-level info] [-grease-rate 0.01]
roughtime -version
```

The root key file must be mode `0600` or stricter. Responses that would exceed
the request size are dropped per the amplification protection requirement. The
server shuts down gracefully on SIGINT/SIGTERM.

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

```json
{
  "name": "time.txryan.com",
  "version": "IETF-Roughtime",
  "publicKeyType": "ed25519",
  "publicKey": "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
  "addresses": [
    {
      "protocol": "udp",
      "address": "time.txryan.com:2002"
    }
  ]
}
```

## Protocol

The `protocol` package implements the Roughtime wire format for both server and
client use. See the [package
documentation](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol) for
the full API and wire group details.

```go
nonce, request, err := protocol.CreateRequest(
    []protocol.Version{protocol.VersionDraft12},
    rand.Reader,
)
// ... send request over UDP, receive reply ...
midpoint, radius, err := protocol.VerifyReply(
    []protocol.Version{protocol.VersionDraft12},
    reply, rootPublicKey, nonce, request,
)
```

## Development

A Makefile is provided for building, testing, linting, and fuzzing.

```
make deps             # install dev tools
make build            # build roughtime, roughtime-client, roughtime-debug
make test             # unit tests
make test-race        # unit tests with race detector
make test-cover       # unit tests with coverage
make test-race-cover  # race detector + coverage profile (used by CI)
make fuzz             # run all fuzz targets (FUZZ_TIME=30s each)
make verify           # go mod download + go mod verify (module integrity)
make coverage-report  # test-race-cover + per-function summary + HTML report
make lint             # vet + staticcheck + golangci-lint + gopls
make check            # full suite (verify, fmt, vet, lint, build, race+cover, report card)
make clean            # remove built binaries and coverage artifacts
```

## Example Output

### Client

Single server:

```
$ go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   time.txryan.com:2002
Version:   draft-ietf-ntp-roughtime-12
Midpoint:  2026-04-11T05:16:09Z
Radius:    3s
Window:    [2026-04-11T05:16:06Z, 2026-04-11T05:16:12Z]
RTT:       49ms
Local:     2026-04-11T05:16:09.792193Z
Drift:     -792ms
Status:    in-sync
```

Multiple servers:

```
$ go run client/main.go -servers ecosystem.json
NAME                            ADDRESS                         VERSION         MIDPOINT              RADIUS    RTT         DRIFT         STATUS
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-11T05:16:14Z  ±3s       52ms        -493ms        in-sync
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-11T05:16:14Z  ±1s       18ms        -513ms        in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-11T05:16:14Z  ±1s       141ms       -656ms        in-sync
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-11T05:16:14Z  ±3s       47ms        -706ms        in-sync
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-11T05:16:14Z  ±1s       17ms        -727ms        in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-11T05:16:14Z  ±1s       141ms       -870ms        in-sync

6/6 servers responded
Consensus drift:    -681ms (median of 6 samples)
Consensus midpoint: 2026-04-11T05:16:14Z
Drift spread:       377ms (min=-870ms, max=-493ms)
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
00000000  52 4f 55 47 48 54 49 4d  f4 03 00 00 04 00 00 00  |ROUGHTIM........|
00000010  04 00 00 00 24 00 00 00  28 00 00 00 56 45 52 00  |....$...(...VER.|
00000020  4e 4f 4e 43 54 59 50 45  5a 5a 5a 5a 0c 00 00 80  |NONCTYPEZZZZ....|
...

--- Request Tags ---
  VER: 0c000080
  NONC: f443f6ba64b0c25745e51a42016824db55b2a8a30fbc6a6db1b2a7d20dad7d79
  TYPE: 00000000
  ZZZZ: (940 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
...

--- Response Tags ---
  SIG: 6f415edf6c0d6b061dd649e712123d94134f20d0aea595cbbadea1eaf78312b56a9c3f4f35aa4a3aeb75b353aba4f8f7c66b72e373c6dad6ce45f7a0713f9604
  NONC: f443f6ba64b0c25745e51a42016824db55b2a8a30fbc6a6db1b2a7d20dad7d79
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 89.942792ms
Midpoint:        2026-04-11T05:16:19Z
Radius:          3s
Local time:      2026-04-11T05:16:19.69064Z
Clock drift:     -691ms
Amplification:   ok (reply 460 ≤ request 1024)

=== Response Details ===
Signature:       6f415edf6c0d6b061dd649e712123d94134f20d0aea595cbbadea1eaf78312b56a9c3f4f35aa4a3aeb75b353aba4f8f7c66b72e373c6dad6ce45f7a0713f9604
Nonce:           f443f6ba64b0c25745e51a42016824db55b2a8a30fbc6a6db1b2a7d20dad7d79
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     802485cd8b26c316ba1b5a2827eb4b5acace4793f7eca085a5babae1befcff81
Midpoint (raw):  1775884579 (2026-04-11T05:16:19Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       8315af750e9a4d5be33c64240c8ac579999111d95b4c73c51700c5c89dd7bda5e82f0e8f16002fb67756a82680b01ddc43b0b8e8f4e9e0439ba6a7036782a708
Online key:      3c62ad898ddb621ff1ff45b6084aec015afb6f4e7e31ea7f7f12360cbd3628bc
Not before:      2026-04-10T23:04:03Z
Not after:       2026-04-11T23:04:03Z
Expires in:      17h47m41s
Cert validity:   ok (midpoint within window)
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
