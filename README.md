# roughtime

[![PkgGoDev](https://pkg.go.dev/badge/github.com/tannerryan/roughtime)](https://pkg.go.dev/github.com/tannerryan/roughtime)
[![GitHub
license](https://img.shields.io/github/license/tannerryan/roughtime.svg?style=flat-square)](https://github.com/tannerryan/roughtime/blob/main/LICENSE)
![GitHub go.mod Go
version](https://img.shields.io/github/go-mod/go-version/tannerryan/roughtime?style=flat-square&color=blue)
[![Go Report
Card](https://goreportcard.com/badge/github.com/tannerryan/roughtime?style=flat-square)](https://goreportcard.com/report/github.com/tannerryan/roughtime)

A [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
implementation in Go covering Google-Roughtime and IETF drafts 01–19. Ships the
`roughtime` server, four CLIs (`client`, `debug`, `bench`, `stamp`), and two Go
packages: `github.com/tannerryan/roughtime` (high-level client) and
`.../protocol` (wire primitives). Interop:
[ietf-wg-ntp/Roughtime-interop-code](https://github.com/ietf-wg-ntp/Roughtime-interop-code).

> ⚠️ **ML-DSA-44 (FIPS 204) is experimental and not part of any IETF draft.**
> Defined here as an ahead-of-spec extension and framed over TCP because replies
> exceed the UDP amplification cap. No interop guaranteed.

Merkle node order changed at draft-16 (node-first → hash-first). This
implementation applies hash-first to all of drafts 14–19, so multi-request
batches diverge from drafts 14–15 only; single-request replies are unaffected
(PATH is empty).

Try it against the public server at `time.txryan.com:2002`
([details](https://time.txryan.com)):

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
```

## Server

Speaks UDP (Ed25519 + Google) and TCP (Ed25519 + ML-DSA-44) on one port. Reads
hex-encoded root key seeds and refreshes online delegation certificates before
expiry. At least one of `-root-key-file` or `-pq-root-key-file` must be set;
supply both for dual-stack. `-keygen`/`-pq-keygen` write a seed (`0600`) and
print the public key; `-pubkey`/`-pq-pubkey` re-derive it.

```
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

UDP on Linux binds one `SO_REUSEPORT` socket per CPU; each worker drains its own
queue with `recvmmsg`/`sendmmsg` and batches up to 256 requests (or 1ms) per
signing round. Other Unix systems use a single socket feeding one batcher. TCP
serializes per connection, routes requests to a per-scheme batcher keyed on
`(version, hasType)`, signs once with Ed25519 or ML-DSA-44, and fans out
per-client Merkle PATH proofs. Windows is not supported (`//go:build unix`).

### TCP framing

```
+------------------------------+---------------------+------------------------+
| "ROUGHTIM" magic  (8 bytes)  | length (4 bytes)    | message (length bytes) |
+------------------------------+---------------------+------------------------+
                                 little-endian uint32
```

Google-Roughtime (no `ROUGHTIM` header) is UDP-only; Ed25519 runs on either
transport; ML-DSA-44 is TCP-only. Lengths above 8192 bytes, bad magic,
zero-length bodies, or a missed read deadline close the connection. Idle timeout
10s; per-stage deadline 5s.

### ML-DSA-44 wire variant (experimental)

Version `0x90000001` (`roughtime-ml-dsa-44`) — top bit set, disjoint from the
IETF `0x80000000 + n` range. Reuses the draft-12+ wire layout with the TYPE tag
(same tags, request-as-Merkle-leaf, SRV binding); only the signature material
and the context convention differ. `VERS` in SREP is per-scheme since each
listener can only attest its own scheme's versions, keeping the downgrade check
(`chosen == max(client_offered ∩ signed_VERS)`) tractable per suite.

| Parameter          | Ed25519                  | ML-DSA-44                  |
| ------------------ | ------------------------ | -------------------------- |
| Public key size    | 32 bytes                 | 1312 bytes                 |
| Signature size     | 64 bytes                 | 2420 bytes                 |
| Context convention | byte-prefix (`ctx\|msg`) | FIPS 204 context parameter |
| Transport          | UDP or TCP               | TCP only                   |

### Docker

```
docker build -t roughtime:latest .
mkdir -p keys
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -keygen /keys/root.key
docker run --rm -v "$PWD/keys:/keys" roughtime:latest -pq-keygen /keys/pq-root.key
docker run -d --name roughtime --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 2002:2002/udp -p 2002:2002/tcp -v "$PWD/keys:/keys:ro" \
  roughtime:latest -root-key-file /keys/root.key -pq-root-key-file /keys/pq-root.key
```

## CLIs

All four auto-detect the suite from the root public key length: 32 bytes
Ed25519, 1312 bytes ML-DSA-44.

### client

Queries one or more servers and prints authenticated timestamps with clock
drift. With `-servers`, samples 3 entries (or `-all`) and queries them twice to
surface pairwise inconsistencies. Multi-server queries chain by default.

```
go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
go run client/main.go -servers ecosystem.json [-all] [-tcp] [-chain=false]
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

```
go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= [-tcp] [-ver draft-12]
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
error breakdown. `-verify` signature-checks every reply client-side; ML-DSA-44
verify is materially slower than Ed25519, so leave `-verify` off for raw
throughput numbers.

```
go run bench/main.go -addr <host:port> -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s [-tcp] [-verify]
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

Document timestamping. Stamp hashes a file with SHA-256, binds the digest into a
causal-chained query across multiple witnesses, and writes a gzipped drafts-12+
malfeasance report. Verify re-validates that proof offline against the document
and a trusted ecosystem. Witnesses must use a 32-byte nonce (IETF Ed25519 drafts
05+ and experimental ML-DSA-44); Google-Roughtime entries are skipped.

```
go run stamp/main.go -doc README.md -servers ecosystem.json -out README.md.proof
go run stamp/main.go -mode verify -doc README.md -servers ecosystem.json -in README.md.proof
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

`QueryAll` fans out concurrently. `QueryChain` runs causal-chained queries and
returns a `*ChainResult` whose `Proof()` yields a `*Proof` with `MarshalGzip`,
`Verify`, `Trust`, `Links`, `SeedNonce`, `AttestationBound` for offline audit;
`ParseProof` reloads. `QueryChainWithNonce` seeds the first link's nonce so a
document hash binds to the chain — the high-level path for timestamping.
`Consensus` aggregates drift across `[]Result`; `Verify` re-validates a stored
`Request`/`Reply` pair; `ParseEcosystem` decodes the ecosystem JSON.

### Wire primitives — `github.com/tannerryan/roughtime/protocol`

Wire format and `RoundTripUDP` / `RoundTripTCP`. Full API on
[pkg.go.dev](https://pkg.go.dev/github.com/tannerryan/roughtime/protocol).

```go
nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPublicKey, nonce, request)
```

`srv` binds the request to a server key (SRV tag, drafts 10+);
`CreateRequestWithNonce` accepts a caller-supplied nonce. For multi-server
measurement and malfeasance detection:

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

```
$ go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
Address:   udp://time.txryan.com:2002
Version:   draft-ietf-ntp-roughtime-12
Midpoint:  2026-04-26T17:44:31Z
Radius:    3s
Window:    [2026-04-26T17:44:28Z, 2026-04-26T17:44:34Z]
RTT:       42ms
Local:     2026-04-26T17:44:31.208678Z
Drift:     -187ms
Status:    in-sync
```

Ecosystem (chained, queried twice in opposite halves):

```
$ go run client/main.go -servers ecosystem.json -all
NAME                            ADDRESS                                    VERSION    MIDPOINT              RADIUS    RTT     DRIFT     STATUS
time.txryan.com                 udp://time.txryan.com:2002                 draft-12   2026-04-26T17:44:31Z  ±3s       47ms    -298ms    in-sync
time.txryan.com-pq              tcp://time.txryan.com:2002                 ml-dsa-44  2026-04-26T17:44:31Z  ±3s       50ms    -394ms    in-sync
Cloudflare-Roughtime-2          udp://roughtime.cloudflare.com:2003        draft-11   2026-04-26T17:44:31Z  ±1s       17ms    -430ms    in-sync
roughtime.se                    udp://roughtime.se:2002                    draft-12   2026-04-26T17:44:31Z  ±1s       145ms   -514ms    in-sync
sth1.roughtime.netnod.se        udp://sth1.roughtime.netnod.se:2002        draft-07   2026-04-26T17:44:31Z  ±72µs     147ms   6ms       out-of-sync
sth2.roughtime.netnod.se        udp://sth2.roughtime.netnod.se:2002        draft-07   2026-04-26T17:44:31Z  ±30µs     140ms   3ms       out-of-sync
time.teax.dev                   udp://time.teax.dev:2002                   draft-12   2026-04-26T17:44:31Z  ±3s       155ms   -965ms    in-sync
roughtime.sturdystatistics.com  udp://roughtime.sturdystatistics.com:2002  draft-12   2026-04-26T17:44:32Z  ±10s      183ms   -140ms    in-sync
TimeNL-Roughtime                udp://rough.time.nl:2002                   draft-12   2026-04-26T17:44:32Z  ±3s       146ms   -308ms    in-sync
time.txryan.com                 udp://time.txryan.com:2002                 draft-12   2026-04-26T17:44:32Z  ±3s       47ms    -408ms    in-sync
time.txryan.com-pq              tcp://time.txryan.com:2002                 ml-dsa-44  2026-04-26T17:44:32Z  ±3s       44ms    -500ms    in-sync
Cloudflare-Roughtime-2          udp://roughtime.cloudflare.com:2003        draft-11   2026-04-26T17:44:32Z  ±1s       17ms    -535ms    in-sync
roughtime.se                    udp://roughtime.se:2002                    draft-12   2026-04-26T17:44:32Z  ±1s       146ms   -621ms    in-sync
sth1.roughtime.netnod.se        udp://sth1.roughtime.netnod.se:2002        draft-07   2026-04-26T17:44:32Z  ±72µs     137ms   1ms       out-of-sync
sth2.roughtime.netnod.se        udp://sth2.roughtime.netnod.se:2002        draft-07   2026-04-26T17:44:32Z  ±30µs     138ms   2ms       out-of-sync
time.teax.dev                   udp://time.teax.dev:2002                   draft-12   2026-04-26T17:44:33Z  ±3s       152ms   -56ms     in-sync
roughtime.sturdystatistics.com  udp://roughtime.sturdystatistics.com:2002  draft-12   2026-04-26T17:44:33Z  ±10s      185ms   -228ms    in-sync
TimeNL-Roughtime                udp://rough.time.nl:2002                   draft-12   2026-04-26T17:44:33Z  ±3s       144ms   -396ms    in-sync

18/18 servers responded
Consensus drift:    -308ms (median of 9 samples)
Consensus midpoint: 2026-04-26T17:44:33Z
Drift spread:       971ms (min=-965ms, max=6ms)
Chain:              ok (18 links verified)
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
  NONC: bfe7023ab4ed5cd16239b61cdf4d0f1135b8490f8da9e5279493dcccdeb1a842
  TYPE: 00000000
  ZZZZ: (900 bytes of padding)

=== Response ===
Size: 460 bytes
00000000  52 4f 55 47 48 54 49 4d  c0 01 00 00 07 00 00 00  |ROUGHTIM........|
00000010  40 00 00 00 60 00 00 00  64 00 00 00 64 00 00 00  |@...`...d...d...|
00000020  ec 00 00 00 84 01 00 00  53 49 47 00 4e 4f 4e 43  |........SIG.NONC|
...

--- Response Tags ---
  SIG: a994343e4e4eb889d082ddf6bda3ce105117ffedf4fe6b55f462681351b71b62afdea69c662a5b4c10030feb7007870e130193d088630bb44b827f7150d95706
  NONC: bfe7023ab4ed5cd16239b61cdf4d0f1135b8490f8da9e5279493dcccdeb1a842
  PATH: (empty)
  SREP: (136 bytes)
  CERT: (152 bytes)
  INDX: 00000000
  TYPE: 01000000

=== Verified Result ===
Round-trip time: 45.537708ms
Midpoint:        2026-04-26T17:44:33Z
Radius:          3s
Local time:      2026-04-26T17:44:33.61018Z
Clock drift:     -587ms
Amplification:   ok (reply 460 <= request 1024)

=== Response Details ===
Signature:       a994343e4e4eb889d082ddf6bda3ce105117ffedf4fe6b55f462681351b71b62afdea69c662a5b4c10030feb7007870e130193d088630bb44b827f7150d95706
Nonce:           bfe7023ab4ed5cd16239b61cdf4d0f1135b8490f8da9e5279493dcccdeb1a842
Merkle index:    0
Merkle path:     0 node(s)

=== Signed Response (SREP) ===
Merkle root:     08deee3fd4e3b11fdf20b22cdd1cd6e90d8157bd4a9ebb1733f61c7953b86ac0
Midpoint (raw):  1777225473 (2026-04-26T17:44:33Z)
Radius (raw):    3
VER in SREP:     0x8000000c (draft-ietf-ntp-roughtime-12)
VERS in SREP:    draft-01, draft-02, draft-03, draft-04, draft-05, draft-06, draft-07, draft-08, draft-09, draft-10, draft-11, draft-12

=== Certificate ===
Signature:       8dec91ab8c95b84476a9003e9d654d5a61b7ae605b103ab6a488c966f8707f211f92de68ea4d6b09ba107fc593dcc4afd4507b1f4b266f562da1c044de70430b
Online key:      4fde663e4fc597d004319f3815209a3748d56e85fb66f214f3a14294b80799f1
Not before:      2026-04-26T11:44:06Z
Not after:       2026-04-27T11:44:06Z
Expires in:      17h59m33s
Cert validity:   ok (midpoint within window)
```

## Development

```
make deps             # install dev tools
make build            # build all five binaries
make test             # unit tests
make test-race        # unit tests with race detector
make test-cover       # coverage (roughtime + protocol + server)
make test-race-cover  # race + coverage profile (CI)
make fuzz             # all fuzz targets (FUZZ_TIME=30s each)
make verify           # go mod download + verify
make coverage-report  # per-function summary + HTML report
make lint             # vet + staticcheck + golangci-lint + gopls
make check            # full suite (verify, fmt, vet, lint, build, race+cover, report card)
make clean            # remove built binaries and coverage artifacts
```

## License

Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.
