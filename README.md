# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime is a protocol for secure rough time
synchronization, providing cryptographically signed timestamps with proof of
server authenticity. This implementation covers Google-Roughtime and IETF drafts
00–19.

## Protocol

The `protocol` package implements the Roughtime wire format for server-side use.
Seven wire format groups handle all version differences:

| Wire Group | Versions               | Key Differences                                               |
| ---------- | ---------------------- | ------------------------------------------------------------- |
| Google     | Google-Roughtime       | 64B nonce, SHA-512, Unix µs, no header                        |
| Draft 01   | 00, 01, 02, 03, 04     | ROUGHTIM header, SHA-512/32, MJD µs, NONC in SREP             |
| Draft 06   | 05, 06, 07             | 32B nonce, NONC moved to top-level                            |
| Draft 08   | 08, 09                 | Unix seconds, ZZZZ padding                                    |
| Draft 10   | 10, 11                 | SRV tag, RADI ≥ 3                                             |
| Draft 12   | 12, 13                 | New delegation context, full-packet Merkle leaf, VERS in SREP |
| Draft 14   | 14, 15, 16, 17, 18, 19 | TYPE tag in request and response                              |

Version negotiation selects the highest mutually supported version. Drafts 12–19
share version number `0x8000000c` on the wire; the TYPE tag in the request
distinguishes 12–13 from 14+.

## Server

The `main` package is a UDP Roughtime server. It reads a hex-encoded Ed25519
root key seed from disk, generates online delegation certificates, and
automatically refreshes them before expiry.

`roughtime -port 2002 -root-key /path/to/seed.hex`

The server uses a fixed worker pool sized to the CPU count, a `sync.Pool` for
read buffers, and atomic certificate swaps for lock-free request handling.
Responses that would exceed the request size are dropped per the amplification
protection requirement.

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

`go test ./protocol/`

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
