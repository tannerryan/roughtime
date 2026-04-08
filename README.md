# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
01–19.

Interoperability testing is available at
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

## Protocol

The `protocol` package implements the Roughtime wire format for both server and
client use. Ten wire format groups handle all version differences:

| Wire Group | Versions               | Key Differences                                               |
| ---------- | ---------------------- | ------------------------------------------------------------- |
| Google     | Google-Roughtime       | 64B nonce, SHA-512 (64B), Unix µs, no header                  |
| Draft 01   | 01                     | ROUGHTIM header, SHA-512/32B, MJD µs, 64B nonce, NONC in SREP |
| Draft 02   | 02                     | SHA-512/256 (distinct algorithm), NONC in SREP                |
| Draft 03   | 03, 04                 | NONC moved to top-level response                              |
| Draft 05   | 05, 06                 | 32B nonce                                                     |
| Draft 07   | 07                     | SHA-512/256, delegation context without trailing hyphens      |
| Draft 08   | 08, 09                 | Unix seconds, ZZZZ padding                                    |
| Draft 10   | 10, 11                 | SRV tag, RADI ≥ 3                                             |
| Draft 12   | 12, 13                 | New delegation context, full-packet Merkle leaf, VERS in SREP |
| Draft 14   | 14, 15, 16, 17, 18, 19 | TYPE tag in request and response                              |

Version negotiation selects the highest mutually supported version. Drafts 12–19
share version number `0x8000000c` on the wire; the TYPE tag in the request
distinguishes 12–13 from 14+.

### Server

`ParseRequest` auto-detects Google vs IETF framing and extracts request fields.
`SelectVersion` negotiates the best mutually supported version. `NewCertificate`
creates a signed online delegation certificate. `CreateReplies` builds signed
responses for a batch of requests.

### Client

`CreateRequest` builds a padded Roughtime request for any supported version.
`VerifyReply` authenticates the server's response: it verifies the delegation
certificate, the signed response signature, the Merkle proof, and validates that
the midpoint falls within the delegation window.

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

See `client/main.go` for a complete working example.

## Server

The root package is a UDP Roughtime server. It reads a hex-encoded Ed25519 root
key seed from disk, generates online delegation certificates, and automatically
refreshes them before expiry.

```
roughtime -root-key /path/to/seed.hex [-port 2002] [-log-level info]
roughtime -version
```

The root key file must be mode `0600` or stricter; the server refuses to start
otherwise. The server uses a fixed worker pool sized to the CPU count, a
`sync.Pool` for read buffers, and atomic certificate swaps for lock-free request
handling. Responses that would exceed the request size are dropped per the
amplification protection requirement. The server shuts down gracefully on
SIGINT/SIGTERM, draining in-flight requests before exiting. Operational
telemetry is emitted as structured JSON via
[zap](https://github.com/uber-go/zap), including a per-minute stats line with
received, responded, and dropped counters. Set `-log-level debug` to enable
per-request logging during troubleshooting.

## Client

The `client` command queries one or more Roughtime servers and prints
authenticated timestamps with clock drift. It supports single-server mode and
multi-server mode via a JSON server list. IETF servers receive all supported
versions in a single VER tag, letting the server pick the best match.

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -servers client/ecosystem.json
go run client/main.go -version
```

## Debug

The `debug` command probes a Roughtime server to discover its supported protocol
versions and prints a full diagnostic dump of the request, response, signatures,
and delegation certificate.

```
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
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

## Testing

```
go test ./protocol/
go test -race ./protocol/
```

## Example Output

### Client

Single server:

```
$ go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   time.txryan.com:2002
Version:   draft-ietf-ntp-roughtime-12
Midpoint:  2026-04-08T05:29:59Z
Radius:    3s
Window:    [2026-04-08T05:29:56Z, 2026-04-08T05:30:02Z]
RTT:       45ms
Local:     2026-04-08T05:29:59.050326Z
Drift:     -50ms
Status:    in-sync
```

Multiple servers:

```
$ go run client/main.go -servers client/ecosystem.json
NAME                            ADDRESS                         VERSION         MIDPOINT              RADIUS    RTT         DRIFT         STATUS
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-08T05:30:05Z  ±1s       18ms        -560ms        in-sync
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-08T05:30:05Z  ±3s       46ms        -565ms        in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-08T05:30:05Z  ±1s       202ms       -1.077s       in-sync

3/3 servers responded
Consensus drift:    -565ms (median of 3 samples)
Consensus midpoint: 2026-04-08T05:30:05Z
Drift spread:       517ms (min=-1.077s, max=-560ms)
```

### Debug

```
$ go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
=== Version Probe: time.txryan.com:2002 ===
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
00000030  d2 9f ab f3 7d bd 26 7c  bc 62 fa 02 92 99 24 86  |....}.&|.b....$.|
00000040  fa d8 6e c9 b0 63 52 27  8f bb b0 c5 4c b2 57 52  |..n..cR'....L.WR|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
...

--- Request Tags ---
  VER: 0c000080
  NONC: d29fabf37dbd267cbc62fa0292992486fad86ec9b06352278fbbb0c54cb25752
  TYPE: 00000000
  ZZZZ: (940 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
00000030  54 59 50 45 50 41 54 48  53 52 45 50 43 45 52 54  |TYPEPATHSREPCERT|
00000040  49 4e 44 58 85 25 49 33  3d 2b eb b6 4b e6 04 bc  |INDX.%I3=+..K...|
00000050  e7 f1 fb 72 b2 b9 58 e3  99 0c 26 f7 f6 35 df d8  |...r..X...&..5..|
...

--- Response Tags ---
  SIG: 852549333d2bebb64be604bce7f1fb72b2b958e3990c26f7f635dfd863abc4f08d3179497ad94f60b94da6f7ae38d833afd6ff251160c922382f742211d50803
  NONC: d29fabf37dbd267cbc62fa0292992486fad86ec9b06352278fbbb0c54cb25752
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 44.5795ms
Midpoint:        2026-04-08T05:30:08Z
Radius:          3s
Local time:      2026-04-08T05:30:09.538986Z
Clock drift:     -1.539s
Amplification:   ok (reply 460 ≤ request 1024)

=== Response Details ===
Signature:       852549333d2bebb64be604bce7f1fb72b2b958e3990c26f7f635dfd863abc4f08d3179497ad94f60b94da6f7ae38d833afd6ff251160c922382f742211d50803
Nonce:           d29fabf37dbd267cbc62fa0292992486fad86ec9b06352278fbbb0c54cb25752
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     e3fdbea2c883f1852b1a9d55a0fecb07a74517d6e9a6c5528e2c5b9a1c8fe050
Midpoint (raw):  1775626208 (2026-04-08T05:30:08Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       8aa232956ee7261165ae95809e369cb12feb58e6bbac3224779338e8d025cb02e2ac34792c4048c7bb25c193c0dd756d1183b91b44b7b40aa498179e71681b09
Online key:      0f6001fb8528d1cf269aaf9e3c4da640ec9a44d64a2c62a18437ee00571f6d3f
Not before:      2026-04-01T05:29:43Z
Not after:       2026-05-20T05:29:43Z
Expires in:      1007h59m33s
Cert validity:   ok (midpoint within window)
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
