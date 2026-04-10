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
otherwise. Online delegation certificates use a 24-hour DELE window and are
refreshed every ~15 hours. The server uses a fixed worker pool sized to the CPU
count, `sync.Pool` for read buffers, and atomic certificate swaps for lock-free
request handling. Responses that would exceed the request size are dropped per
the amplification protection requirement. The server shuts down gracefully on
SIGINT/SIGTERM, draining in-flight requests before exiting. Operational
telemetry is emitted as structured JSON via
[zap](https://github.com/uber-go/zap), including periodic stats with received,
responded, dropped, and panic counters. Set `-log-level debug` to enable
per-request logging during troubleshooting.

## Client

The `client` command queries one or more Roughtime servers and prints
authenticated timestamps with clock drift. It supports single-server mode and
multi-server mode via a JSON server list. Multi-server queries are chained by
default (`-chain`): each nonce is derived from the previous response per Section
8.2, enabling causal ordering verification and malfeasance detection.

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -servers client/ecosystem.json
go run client/main.go -servers client/ecosystem.json -chain=false
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
Midpoint:  2026-04-10T02:01:44Z
Radius:    3s
Window:    [2026-04-10T02:01:41Z, 2026-04-10T02:01:47Z]
RTT:       43ms
Local:     2026-04-10T02:01:44.666667Z
Drift:     -667ms
Status:    in-sync
```

Multiple servers:

```
$ go run client/main.go -servers client/ecosystem.json
NAME                            ADDRESS                         VERSION         MIDPOINT              RADIUS    RTT         DRIFT         STATUS
time.txryan.com                 time.txryan.com:2002            draft-12        2026-04-10T02:01:46Z  ±3s       40ms        -937ms        in-sync
Cloudflare-Roughtime-2          roughtime.cloudflare.com:2003   draft-11        2026-04-10T02:01:46Z  ±1s       23ms        -962ms        in-sync
roughtime.se                    roughtime.se:2002               draft-12        2026-04-10T02:01:47Z  ±1s       138ms       -101ms        in-sync

3/3 servers responded
Consensus drift:    -937ms (median of 3 samples)
Consensus midpoint: 2026-04-10T02:01:46Z
Drift spread:       861ms (min=-962ms, max=-101ms)
Chain:              ok (3 links verified)
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
00000030  d2 38 c6 16 2e 68 80 51  53 b1 29 f2 40 ba d4 f9  |.8...h.QS.).@...|
00000040  c2 3d a1 2b a9 33 9f ba  75 c9 43 e0 99 bf 8a 2d  |.=.+.3..u.C....-|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
...

--- Request Tags ---
  VER: 0c000080
  NONC: d238c6162e68805153b129f240bad4f9c23da12ba9339fba75c943e099bf8a2d
  TYPE: 00000000
  ZZZZ: (940 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
00000030  54 59 50 45 50 41 54 48  53 52 45 50 43 45 52 54  |TYPEPATHSREPCERT|
00000040  49 4e 44 58 9a c5 93 7f  1b 87 4b 00 bf c4 82 79  |INDX......K....y|
00000050  d1 84 c4 47 dd 3e 47 2a  38 20 58 45 ca f2 3b 19  |...G.>G*8 XE..;.|
...

--- Response Tags ---
  SIG: 9ac5937f1b874b00bfc48279d184c447dd3e472a38205845caf23b19ab74f6a2481523e7547cfa3b0a899131174afa4d5d6d3aacbfd4a89196c9c3eb9e26c00c
  NONC: d238c6162e68805153b129f240bad4f9c23da12ba9339fba75c943e099bf8a2d
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 41.1765ms
Midpoint:        2026-04-10T02:01:48Z
Radius:          3s
Local time:      2026-04-10T02:01:48.893572Z
Clock drift:     -894ms
Amplification:   ok (reply 460 ≤ request 1024)

=== Response Details ===
Signature:       9ac5937f1b874b00bfc48279d184c447dd3e472a38205845caf23b19ab74f6a2481523e7547cfa3b0a899131174afa4d5d6d3aacbfd4a89196c9c3eb9e26c00c
Nonce:           d238c6162e68805153b129f240bad4f9c23da12ba9339fba75c943e099bf8a2d
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     5b8b62fe0cec1f16c3b8569ec815366c2107d04fef345ab5fd47f0a19d305f99
Midpoint (raw):  1775786508 (2026-04-10T02:01:48Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       9e09d27d8f4bb2e94e220164733ec2aa729914c6883a8d3de9eec97c52bf745471b15862f943f81a4f29d05898190d50352dcfed72b0b74e6dd03bf9c964b90f
Online key:      b99eda1f9fec79c0707b7deb9b9e36e22092daee08458422e1a76fa8f6e3d7de
Not before:      2026-04-09T20:01:39Z
Not after:       2026-04-10T20:01:39Z
Expires in:      17h59m50s
Cert validity:   ok (midpoint within window)
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
