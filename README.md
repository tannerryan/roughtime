# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
01–19.

## Protocol

The `protocol` package implements the Roughtime wire format for both server and
client use. Ten wire format groups handle all version differences:

| Wire Group | Versions               | Key Differences                                               |
| ---------- | ---------------------- | ------------------------------------------------------------- |
| Google     | Google-Roughtime       | 64B nonce, SHA-512 (64B), Unix µs, no header                  |
| Draft 01   | 01                     | ROUGHTIM header, SHA-512/32B, MJD µs, 64B nonce, NONC in SREP |
| Draft 02   | 02                     | SHA-512/256 (distinct algorithm), NONC in SREP                |
| Draft 03   | 03, 04                 | NONC moved to top-level response, SHA-512/32B                 |
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
roughtime -root-key /path/to/seed.hex [-port 2002]
```

The server uses a fixed worker pool sized to the CPU count, a `sync.Pool` for
read buffers, and atomic certificate swaps for lock-free request handling.
Responses that would exceed the request size are dropped per the amplification
protection requirement. The server shuts down gracefully on SIGINT/SIGTERM,
draining in-flight requests before exiting.

## Client

The `client` command queries one or more Roughtime servers and prints
authenticated timestamps with clock drift. It supports single-server mode and
multi-server mode via a JSON server list. IETF servers receive all supported
versions in a single VER tag, letting the server pick the best match.

```
go run ./client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run ./client -servers ecosystem.json
```

## Debug

The `debug` command probes a Roughtime server to discover its supported protocol
versions and prints a full diagnostic dump of the request, response, signatures,
and delegation certificate.

```
go run ./debug -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
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

```
$ go run client/main.go -servers client/ecosystem.json
Cloudflare-Roughtime-2          draft-11        2026-04-06T05:54:04Z  ±1s      rtt=10ms      drift=-317ms
time.txryan.com                 draft-12        2026-04-06T05:54:04Z  ±3s      rtt=47ms      drift=-354ms
roughtime.se                    draft-12        2026-04-06T05:54:04Z  ±1s      rtt=144ms     drift=-451ms

3/3 servers responded
```

### Debug

```
$ go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
=== Version Probe: time.txryan.com:2002 ===
  draft-ietf-ntp-roughtime-12              OK
  draft-ietf-ntp-roughtime-11              OK
  draft-ietf-ntp-roughtime-10              OK
  draft-ietf-ntp-roughtime-08              OK
  draft-ietf-ntp-roughtime-07              OK
  draft-ietf-ntp-roughtime-06              OK
  draft-ietf-ntp-roughtime-05              OK
  draft-ietf-ntp-roughtime-01              OK
  Google-Roughtime                         OK

Supported versions: draft-12, draft-11, draft-10, draft-08, draft-07, draft-06, draft-05, draft-01, Google
Negotiated:         draft-ietf-ntp-roughtime-12

=== Request ===
Size: 1024 bytes
00000000  52 4f 55 47 48 54 49 4d  f4 03 00 00 04 00 00 00  |ROUGHTIM........|
00000010  04 00 00 00 24 00 00 00  28 00 00 00 56 45 52 00  |....$...(...VER.|
00000020  4e 4f 4e 43 54 59 50 45  5a 5a 5a 5a 0c 00 00 80  |NONCTYPEZZZZ....|
00000030  cf df 6a 2b 3c 7f 0d b3  f4 a9 4e 82 81 94 45 6d  |..j+<.....N...Em|
00000040  7e 4f 25 67 e7 12 56 29  b4 bc 16 51 47 af 8a e7  |~O%g..V)...QG...|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
...

--- Request Tags ---
  VER: 0c000080
  NONC: cfdf6a2b3c7f0db3f4a94e828194456d7e4f2567e7125629b4bc165147af8ae7
  TYPE: 00000000
  ZZZZ: (940 bytes of padding)

=== Response ===
Size: 472 bytes
00000000  52 4f 55 47 48 54 49 4d  cc 01 00 00 08 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 44 00 00 00  64 00 00 00 68 00 00 00  |@...D...d...h...|
00000020  68 00 00 00 f0 00 00 00  88 01 00 00 53 49 47 00  |h...........SIG.|
00000030  56 45 52 00 4e 4f 4e 43  54 59 50 45 50 41 54 48  |VER.NONCTYPEPATH|
00000040  53 52 45 50 43 45 52 54  49 4e 44 58 14 19 30 43  |SREPCERTINDX..0C|
00000050  c4 50 2e dd ab 83 58 6e  34 65 61 33 e4 66 42 18  |.P....Xn4ea3.fB.|
...

--- Response Tags ---
  SIG: 14193043c4502edd...d205753d499b5df1d06c240b
  VER: 0c000080
  NONC: cfdf6a2b3c7f0db3f4a94e828194456d7e4f2567e7125629b4bc165147af8ae7
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 45.260875ms
Midpoint:        2026-04-06T05:54:08Z
Radius:          3s
Local time:      2026-04-06T05:54:09.320258Z
Clock drift:     -1.32s

=== Response Details ===
Version:         0x8000000c (draft-ietf-ntp-roughtime-12)
Signature:       14193043c4502edd...d205753d499b5df1d06c240b
Nonce:           cfdf6a2b3c7f0db3f4a94e828194456d7e4f2567e7125629b4bc165147af8ae7
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     7ce214773d8658f45ebf06268b53eb669a365ae4c761198d5ec14fe3ec196672
Midpoint (raw):  1775454848 (2026-04-06T05:54:08Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, ..., draft-12

=== Certificate ===
Signature:       d7c29a2d28346a15...a1d8d002
Online key:      94a5cd8e2cdabb62dbd92d760e8dd177a27a2e42fc7d068744358d52bac05ed8
Not before:      2026-03-30T05:53:29Z
Not after:       2026-05-18T05:53:29Z
Expires in:      1007h59m20s
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
