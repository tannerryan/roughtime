# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
protocol implementation in Go. Roughtime delivers cryptographically signed rough
timestamps with proof of server authenticity. Covers Google-Roughtime and IETF
drafts 01–19.

> ⚠️ **ML-DSA-44 (FIPS 204) support is experimental and not part of any IETF
> Roughtime draft.** It is an ahead-of-spec extension defined and implemented
> here only, framed over TCP because replies exceed the UDP amplification cap.
> No interop is guaranteed with other implementations. Do not depend on it for
> production.

The repository ships a server, three CLIs (`client`, `debug`, `bench`), and a Go
library split across `github.com/tannerryan/roughtime` (high-level client) and
`github.com/tannerryan/roughtime/protocol` (wire primitives).

Drafts 05–13 use node-first Merkle order; drafts 14–19 use hash-first (reversed
at draft-16; this implementation follows the latest spec). Multi-request batches
are therefore non-conformant to drafts 14–15 only; single-request replies are
unaffected.

Interoperability testing is available at
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

## Try it now

A public Roughtime server runs at `time.txryan.com:2002`
([details](https://time.txryan.com)).

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
```

## Server

The root package is a Roughtime server that speaks UDP (Ed25519 + Google) and
TCP (Ed25519 + ML-DSA-44) on the same port. It reads hex-encoded root key seeds
from disk, generates online delegation certificates, and refreshes them before
expiry. At least one of `-root-key-file` (Ed25519) or `-pq-root-key-file`
(ML-DSA-44) must be provided; supply both for dual-stack.

```
roughtime -keygen /path/to/root.key
roughtime -pq-keygen /path/to/pq-root.key
roughtime -root-key-file /path/to/root.key -pq-root-key-file /path/to/pq-root.key
roughtime -version
```

`-keygen` / `-pq-keygen` write a seed to the given path (mode `0600`) and print
the public key in hex and base64. `-pubkey` / `-pq-pubkey` re-derive the public
key from an existing seed file. Root key files must be mode `0600` or stricter.

| Flag                | Default | Description                                       |
| ------------------- | ------- | ------------------------------------------------- |
| `-port`             | 2002    | Listen port (shared by UDP and TCP)               |
| `-root-key-file`    |         | Ed25519 root key seed (enables UDP + TCP Ed25519) |
| `-pq-root-key-file` |         | ML-DSA-44 root key seed (enables TCP ML-DSA-44)   |
| `-grease-rate`      | 0.01    | Fraction of responses to grease (0 to disable)    |
| `-log-level`        | info    | Log level (debug, info, warn, error)              |

### Architecture

On Linux, the UDP listener binds one `SO_REUSEPORT` socket per CPU; each worker
drains its own queue with `recvmmsg`/`sendmmsg` and batches up to 256 requests
(or 1ms) per signing round. Other Unix systems fall back to a single socket
feeding one batcher over a buffered channel, with the same 256/1ms window.

The TCP listener handles one request/response at a time per connection. Requests
are routed to a per-scheme batcher grouped by `(version, request-type)` and
signed with one Ed25519 or ML-DSA-44 signature, fanning out replies with
per-client Merkle PATH proofs. Windows is not supported.

### TCP framing

TCP packets use the same framing as UDP:

```
+------------------------------+---------------------+------------------------+
| "ROUGHTIM" magic  (8 bytes)  | length (4 bytes)    | message (length bytes) |
+------------------------------+---------------------+------------------------+
                                 little-endian uint32
```

Google-Roughtime (no `ROUGHTIM` header) is UDP-only. Ed25519 runs on either
transport; ML-DSA-44 is TCP-only.

Declared lengths above 8192 bytes, bad magic, zero-length bodies, or bodies that
miss the read deadline close the connection. Idle connections close after 10s;
each request/response stage has a 5s deadline.

### ML-DSA-44 wire variant (experimental)

> ⚠️ See the warning at the top of this README. The wire format below is
> repository-local and out of scope for the IETF drafts.

The PQ variant uses version number `0x90000001`, reported as
`roughtime-ml-dsa-44`. The value sits in the private-use range (top bit set,
disjoint from the `0x80000000 + n` space IETF drafts consume) so it cannot
collide with a future draft assignment.

| Parameter          | Ed25519                  | ML-DSA-44                  |
| ------------------ | ------------------------ | -------------------------- |
| Public key size    | 32 bytes                 | 1312 bytes                 |
| Signature size     | 64 bytes                 | 2420 bytes                 |
| Context convention | byte-prefix (`ctx\|msg`) | FIPS 204 context parameter |
| Transport          | UDP or TCP               | TCP only                   |
| Wire format        | draft-12+ with TYPE      | draft-12+ with TYPE        |
| Nonce size         | 32 bytes                 | 32 bytes                   |
| Merkle hash        | SHA-512/256              | SHA-512/256                |

The PQ variant reuses the draft-12 request/response layout unchanged: same tags
(`SIG`, `SREP`, `CERT`, `DELE`, `PATH`, `INDX`, `NONC`, `VER`, `VERS`, `TYPE`,
`ROOT`, `MIDP`, `RADI`, `MINT`, `MAXT`, `PUBK`, `SRV`), same
request-as-Merkle-leaf rule, same SRV binding. Only the signature and
delegation-key material change. The Roughtime context strings (`"RoughTime v1
response signature\x00"` and `"RoughTime v1 delegation signature\x00"`) are
passed to ML-DSA as FIPS 204's native context parameter rather than prepended to
the signed message.

`VERS` in SREP is scoped per scheme: each listener signs with its own online key
and cannot attest the other scheme's versions, so scoping keeps the downgrade
check (`chosen == max(client_offered ∩ signed_VERS)`) tractable per suite
instead of forcing dual-stack clients to reject single-scheme replies.

With both root keys configured, the server accepts UDP (Ed25519 + Google), TCP
Ed25519, and TCP ML-DSA-44 concurrently on one port. Each suite refreshes its
delegation certificate independently.

### Docker

Build the image, generate one or both root keys into `./keys`, and run the
server with the keys mounted read-only. Expose both UDP and TCP on the listen
port:

```
docker build -t roughtime:latest .
mkdir -p keys
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -keygen /keys/root.key
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -pq-keygen /keys/pq-root.key
docker run -d \
  --name roughtime \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 2002:2002/udp \
  -p 2002:2002/tcp \
  -v "$PWD/keys:/keys:ro" \
  roughtime:latest -root-key-file /keys/root.key -pq-root-key-file /keys/pq-root.key
```

## CLIs

All three CLIs auto-detect the signature suite from the root public key length:
32 bytes Ed25519, 1312 bytes ML-DSA-44.

### client

Queries one or more Roughtime servers and prints authenticated timestamps with
clock drift. Multi-server queries are chained by default.

With `-servers`, the client randomly samples 3 entries and queries them twice in
the same order so pairwise inconsistencies surface. `-all` queries every entry.

ML-DSA-44 keys always use TCP. Ed25519 defaults to UDP and falls back to TCP
when only a TCP address is listed. `-tcp` forces TCP: with `-addr` for one
server, with `-servers` for every entry (entries with no TCP address — notably
Google — are skipped).

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= -tcp
go run client/main.go -addr time.txryan.com:2002 -pubkey <ML-DSA-44-pubkey-base64>
go run client/main.go -servers ecosystem.json
go run client/main.go -servers ecosystem.json -all
go run client/main.go -servers ecosystem.json -tcp
go run client/main.go -servers ecosystem.json -chain=false [-retries 3]
go run client/main.go -version
```

| Flag       | Default | Description                                                                  |
| ---------- | ------- | ---------------------------------------------------------------------------- |
| `-servers` |         | Path to a JSON server list (mutually exclusive with `-addr`)                 |
| `-addr`    |         | Single server `host:port` (requires `-pubkey`)                               |
| `-pubkey`  |         | Root public key (base64 or hex) for `-addr`                                  |
| `-name`    |         | When set with `-servers`, query only the named server                        |
| `-tcp`     | false   | Force TCP: with `-addr` for that server, with `-servers` filters every entry to its TCP address (Google entries are skipped); ML-DSA-44 keys always use TCP regardless |
| `-all`     | false   | Query every server in `-servers` (default samples 3)                         |
| `-chain`   | true    | Causally chain queries when more than one server is in play                  |
| `-timeout` | 500ms   | Read/write timeout per attempt                                               |
| `-retries` | 3       | Maximum attempts per server (backoff 1s × 1.5^(n-1), cap 24h)                |

### debug

Probes a single server to discover supported versions and dumps the request,
response, signatures, and delegation certificate. Auto-selects TCP for
ML-DSA-44; `-tcp` forces TCP for an Ed25519 key.

```
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= -tcp
go run debug/main.go -addr time.txryan.com:2002 -pubkey <ML-DSA-44-pubkey-base64>
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= -retries 5
go run debug/main.go -version
```

| Flag       | Default | Description                                                          |
| ---------- | ------- | -------------------------------------------------------------------- |
| `-addr`    |         | Server `host:port`                                                   |
| `-pubkey`  |         | Root public key (base64 or hex)                                      |
| `-tcp`     | false   | Force TCP; ML-DSA-44 keys always use TCP regardless                  |
| `-ver`     |         | Probe only this version (e.g. `draft-12`, `Google`, `ml-dsa-44`)     |
| `-timeout` | 500ms   | Per-version probe timeout                                            |
| `-retries` | 3       | Maximum attempts per version                                         |

### bench

Closed-loop load generator. Each worker owns one socket (UDP datagram or
persistent TCP connection), fires a request, waits for the reply, and repeats.
Reports throughput, latency percentiles, and an error breakdown.

```
go run bench/main.go -addr <host:port> -pubkey <ed25519-base64-or-hex> -workers 256 -duration 30s -warmup 2s
go run bench/main.go -addr <host:port> -pubkey <ed25519-base64-or-hex> -tcp -workers 256 -duration 30s
go run bench/main.go -addr <host:port> -pubkey <ml-dsa-44-base64-or-hex> -workers 64 -duration 30s
```

`-verify` signature-checks every reply. Verification is client-bound and caps
throughput before the server does; leave it off for pure throughput numbers.
ML-DSA-44 verify is ~10× the cost of Ed25519.

| Flag        | Default        | Description                                                       |
| ----------- | -------------- | ----------------------------------------------------------------- |
| `-addr`     | 127.0.0.1:2002 | Server `host:port`                                                |
| `-pubkey`   |                | Root public key (base64 or hex)                                   |
| `-tcp`      | false          | Force TCP; ML-DSA-44 keys always use TCP regardless               |
| `-workers`  | 64             | Concurrent client sockets                                         |
| `-duration` | 10s            | Measurement duration                                              |
| `-warmup`   | 2s             | Warmup before measurement (samples discarded; sockets persist)    |
| `-timeout`  | 500ms          | Per-request read/write timeout                                    |
| `-verify`   | false          | Verify every reply (slower, client-bound)                         |

## Library

Two packages are exposed; the CLIs are thin wrappers.

### High-level client — `github.com/tannerryan/roughtime`

Supply servers as Go structs, get back verified responses:

```go
import "github.com/tannerryan/roughtime"

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

`Client.QueryAll` fans out across many servers concurrently; `Client.QueryChain`
runs causal-chained queries and returns a `*protocol.Chain` suitable for
malfeasance reports. `ParseEcosystem` decodes the ecosystem JSON file format
directly into `[]Server`.

### Wire primitives — `github.com/tannerryan/roughtime/protocol`

Roughtime wire format for server and client use, plus transport primitives
(`RoundTripUDP`, `RoundTripTCP`). See the [package
documentation](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol) for
the full API.

Build a request, send it over UDP, and verify the signed response:

```go
nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPublicKey, nonce, request)
```

The optional `srv` parameter binds the request to a server key (SRV tag, drafts
10+). `CreateRequestWithNonce` accepts a caller-supplied nonce for use cases
such as document timestamping.

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

Server-side flow — parse requests and sign a batch:

```go
cert, err := protocol.NewCertificate(mint, maxt, onlineSK, rootSK)
req, err := protocol.ParseRequest(raw)
replies, err := protocol.CreateReplies(version, requests, midpoint, radius, cert)
```

## Example output

### client

Single server:

```
$ go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   udp://time.txryan.com:2002
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
NAME                            ADDRESS                                    VERSION   MIDPOINT              RADIUS    RTT     DRIFT     STATUS
roughtime.sturdystatistics.com  udp://roughtime.sturdystatistics.com:2002  draft-12  2026-04-16T03:31:06Z  ±10s      180ms   -700ms    in-sync
roughtime.se                    udp://roughtime.se:2002                    draft-12  2026-04-16T03:31:06Z  ±1s       141ms   -844ms    in-sync
time.txryan.com                 udp://time.txryan.com:2002                 draft-12  2026-04-16T03:31:06Z  ±3s       50ms    -898ms    in-sync
roughtime.sturdystatistics.com  udp://roughtime.sturdystatistics.com:2002  draft-12  2026-04-16T03:31:07Z  ±10s      182ms   -84ms     in-sync
roughtime.se                    udp://roughtime.se:2002                    draft-12  2026-04-16T03:31:07Z  ±1s       141ms   -229ms    in-sync
time.txryan.com                 udp://time.txryan.com:2002                 draft-12  2026-04-16T03:31:07Z  ±3s       52ms    -285ms    in-sync

6/6 servers responded
Consensus drift:    -844ms (median of 3 samples)
Consensus midpoint: 2026-04-16T03:31:06Z
Drift spread:       198ms (min=-898ms, max=-700ms)
Chain:              ok (6 links verified)
```

### debug

```
$ go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
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

## Development

Makefile targets for build, test, lint, and fuzz:

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
