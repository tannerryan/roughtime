// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command client queries one or more Roughtime servers and prints the
// authenticated timestamps.
//
// Single server:
//
//	go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Multiple servers:
//
//	go run client/main.go -servers ecosystem.json
//
// Single server from a JSON list:
//
//	go run client/main.go -servers ecosystem.json -name time.txryan.com
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

// supportedVersions lists every protocol version this client supports, newest
// IETF first with Google-Roughtime last.
var supportedVersions = protocol.Supported()

// ietfVersions is supportedVersions without Google-Roughtime.
var ietfVersions = supportedVersions[:len(supportedVersions)-1]

var (
	serversFile = flag.String("servers", "", "path to JSON server list")
	nameFilter  = flag.String("name", "", "query only the named server from the JSON list")
	addr        = flag.String("addr", "", "host:port of a single Roughtime server")
	pubkey      = flag.String("pubkey", "", "Ed25519 root public key (base64 or hex, with -addr)")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "UDP read/write timeout")
	retries     = flag.Int("retries", 3, "max retry attempts per server (backoff 1s × 1.5^(n-1), cap 24h)")
	chain       = flag.Bool("chain", true, "chain queries: derive each nonce from the previous reply")
	all         = flag.Bool("all", false, "query every server in the ecosystem (default: random 3)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// serverConfig is one entry in a Roughtime ecosystem JSON file.
type serverConfig struct {
	Name          string      `json:"name"`
	Version       flexVersion `json:"version"`
	PublicKeyType string      `json:"publicKeyType"`
	PublicKey     string      `json:"publicKey"`
	Addresses     []struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
	} `json:"addresses"`
}

// flexVersion accepts a JSON "version" field encoded as either a string or an
// integer.
type flexVersion string

// UnmarshalJSON decodes v from a JSON string or integer.
func (v *flexVersion) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = flexVersion(s)
		return nil
	}
	var n uint32
	if err := json.Unmarshal(b, &n); err == nil {
		*v = flexVersion(fmt.Sprintf("%d", n))
		return nil
	}
	return fmt.Errorf("version must be a string or integer, got %s", string(b))
}

// serverList is the top-level JSON structure of an ecosystem file.
type serverList struct {
	Servers []serverConfig `json:"servers"`
}

// result is the outcome of querying a single server.
type result struct {
	Name     string
	Address  string
	Midpoint time.Time
	LocalNow time.Time
	Radius   time.Duration
	RTT      time.Duration
	Version  protocol.Version
	Err      error
}

// drift reports the signed offset between the server's midpoint and the
// client's best estimate of its own clock at the server's processing moment
// (LocalNow - RTT/2), removing the RTT/2 bias introduced by measuring LocalNow
// at reply receipt.
func (r result) drift() time.Duration {
	ref := r.LocalNow.Add(-r.RTT / 2)
	return r.Midpoint.Sub(ref)
}

// inSync reports whether the client's RTT-corrected clock falls within the
// server's uncertainty window.
func (r result) inSync() bool {
	d := r.drift()
	if d < 0 {
		d = -d
	}
	return d <= r.Radius
}

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "client: %s\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "client: %s\n", err)
		os.Exit(1)
	}
}

// validateFlags checks CLI flags are within permitted ranges.
func validateFlags() error {
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *retries < 1 {
		return fmt.Errorf("-retries %d must be >= 1", *retries)
	}
	return nil
}

// run queries the configured servers and prints results.
func run(ctx context.Context) error {
	servers, err := loadServers()
	if err != nil {
		return err
	}

	if len(servers) == 1 {
		r := queryServer(ctx, servers[0])
		if r.Err != nil {
			return fmt.Errorf("%s: %w", sanitize(r.Name), r.Err)
		}
		printSingleResult(r)
		return nil
	}

	nameW, addrW := 30, 30
	for _, s := range servers {
		nameW = max(nameW, len(s.Name))
		if len(s.Addresses) > 0 {
			addrW = max(addrW, len(s.Addresses[0].Address))
		}
	}
	rowFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%-8s  %%-20s  %%-8s  %%-6s  %%-8s  %%s\n", nameW, addrW)
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")
	errFmt := fmt.Sprintf("%%-%ds  %%-%ds  error: %%s\n", nameW, addrW)

	var results []result
	var pchain *protocol.Chain
	if *chain {
		// §8.2: two passes cross-check every server in both directions.
		// slices.Concat avoids aliasing from append(servers, servers...)
		results, pchain = queryChained(ctx, slices.Concat(servers, servers))
	} else {
		ch := make(chan result, len(servers))
		for _, srv := range servers {
			go func(srv serverConfig) {
				ch <- queryServer(ctx, srv)
			}(srv)
		}
		for range servers {
			results = append(results, <-ch)
		}
	}

	var drifts []time.Duration
	// Dedupe so chain mode's two passes don't double-weight servers
	seen := make(map[string]bool)
	var succeeded, failed int
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf(errFmt, sanitize(r.Name), sanitize(r.Address), r.Err)
			failed++
			continue
		}
		d := r.drift()
		key := r.Name + "|" + r.Address
		if !seen[key] {
			drifts = append(drifts, d)
			seen[key] = true
		}
		status := "out-of-sync"
		if r.inSync() {
			status = "in-sync"
		}
		fmt.Printf(rowFmt,
			sanitize(r.Name),
			sanitize(r.Address),
			r.Version.ShortString(),
			r.Midpoint.UTC().Format(time.RFC3339),
			"±"+r.Radius.String(),
			r.RTT.Round(time.Millisecond).String(),
			d.Round(time.Millisecond).String(),
			status,
		)
		succeeded++
	}

	fmt.Printf("\n%d/%d servers responded\n", succeeded, succeeded+failed)
	printConsensus(drifts)
	if pchain != nil && len(pchain.Links) > 0 {
		printChainStatus(pchain)
	}
	if succeeded == 0 {
		return fmt.Errorf("no servers responded")
	}
	return nil
}

// printSingleResult prints a vertical summary of one verified server response.
func printSingleResult(r result) {
	safeName := sanitize(r.Name)
	safeAddress := sanitize(r.Address)
	windowStart := r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339)
	windowEnd := r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339)
	status := "out-of-sync"
	if r.inSync() {
		status = "in-sync"
	}
	// In -addr mode Name and Address match; skip the redundant line
	if safeName != safeAddress {
		fmt.Printf("Server:    %s\n", safeName)
	}
	fmt.Printf("Address:   %s\n", safeAddress)
	fmt.Printf("Version:   %s\n", r.Version)
	fmt.Printf("Midpoint:  %s\n", r.Midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:    %s\n", r.Radius)
	fmt.Printf("Window:    [%s, %s]\n", windowStart, windowEnd)
	fmt.Printf("RTT:       %s\n", r.RTT.Round(time.Millisecond))
	fmt.Printf("Local:     %s\n", r.LocalNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:     %s\n", r.drift().Round(time.Millisecond))
	fmt.Printf("Status:    %s\n", status)
}

// printConsensus prints the median drift, consensus midpoint, and drift spread
// across per-server samples. No-op when empty.
func printConsensus(drifts []time.Duration) {
	if len(drifts) == 0 {
		return
	}
	median := medianDuration(drifts)
	lo, hi := slices.Min(drifts), slices.Max(drifts)
	consensus := time.Now().Add(median).UTC().Format(time.RFC3339)
	fmt.Printf("Consensus drift:    %s (median of %d samples)\n",
		median.Round(time.Millisecond), len(drifts))
	fmt.Printf("Consensus midpoint: %s\n", consensus)
	fmt.Printf("Drift spread:       %s (min=%s, max=%s)\n",
		(hi - lo).Round(time.Millisecond),
		lo.Round(time.Millisecond),
		hi.Round(time.Millisecond),
	)
}

// printChainStatus verifies c and prints the outcome.
func printChainStatus(c *protocol.Chain) {
	err := c.Verify()
	if err == nil {
		fmt.Printf("Chain:              ok (%d links verified)\n", len(c.Links))
	} else {
		fmt.Printf("Chain:              FAILED: %s\n", err)
	}
}

// medianDuration returns the median of d without mutating it. For an even count
// it averages the two middle values.
func medianDuration(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// defaultSampleSize is the number of servers randomly sampled when -all is
// unset.
const defaultSampleSize = 3

// Retry backoff per drafts 14+ §6.1: initial 1s, 1.5× multiplier, capped at
// 24h. The interval MUST NOT reset until a valid signed response is received;
// this CLI is one-shot so each query exits on the first success, preserving
// that invariant implicitly.
const (
	retryBackoffInitial = 1 * time.Second
	retryBackoffMax     = 24 * time.Hour
	retryBackoffFactor  = 1.5
)

// nextBackoff returns the next backoff interval, clamped to retryBackoffMax.
func nextBackoff(cur time.Duration) time.Duration {
	next := time.Duration(float64(cur) * retryBackoffFactor)
	if next > retryBackoffMax {
		return retryBackoffMax
	}
	return next
}

// maxEcosystemServers caps the size of a JSON server list.
const maxEcosystemServers = 1024

// maxEcosystemFileBytes caps the size of an ecosystem JSON file before decode.
// 1 MiB is well above any plausible list of 1024 servers.
const maxEcosystemFileBytes = 1 * 1024 * 1024

// loadServers resolves the server list from flags.
func loadServers() ([]serverConfig, error) {
	if *serversFile != "" {
		servers, err := loadServersFile(*serversFile)
		if err != nil {
			return nil, err
		}
		if *nameFilter != "" {
			for _, s := range servers {
				if s.Name == *nameFilter {
					return []serverConfig{s}, nil
				}
			}
			return nil, fmt.Errorf("server %q not found in %s", *nameFilter, *serversFile)
		}
		if !*all && len(servers) > defaultSampleSize {
			mrand.Shuffle(len(servers), func(i, j int) {
				servers[i], servers[j] = servers[j], servers[i]
			})
			servers = servers[:defaultSampleSize]
		}
		return servers, nil
	}
	if *addr != "" && *pubkey != "" {
		cleanAddr := sanitize(*addr)
		return []serverConfig{{
			Name:      cleanAddr,
			PublicKey: *pubkey,
			Addresses: []struct {
				Protocol string `json:"protocol"`
				Address  string `json:"address"`
			}{{Protocol: "udp", Address: cleanAddr}},
		}}, nil
	}
	return nil, fmt.Errorf("provide -servers <file> or -addr <host:port> -pubkey <base64-or-hex>")
}

// loadServersFile reads and parses a JSON server list from path.
func loadServersFile(path string) ([]serverConfig, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxEcosystemFileBytes))
	var list serverList
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("parsing server list: %w", err)
	}
	if len(list.Servers) == 0 {
		return nil, fmt.Errorf("no servers in %s", path)
	}
	if len(list.Servers) > maxEcosystemServers {
		return nil, fmt.Errorf("server list has %d entries (max %d)", len(list.Servers), maxEcosystemServers)
	}
	for i := range list.Servers {
		list.Servers[i].Name = sanitize(list.Servers[i].Name)
		for j := range list.Servers[i].Addresses {
			list.Servers[i].Addresses[j].Address = sanitize(list.Servers[i].Addresses[j].Address)
		}
	}
	return list.Servers, nil
}

// sanitize strips control characters and bidi format codes from s. The bidi
// overrides (U+202A-E, U+2066-9) defeat Trojan Source-style display attacks.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, s)
}

// decodePubKey decodes an Ed25519 root public key from standard base64, URL
// base64, or hex. It errors unless the result is 32 bytes.
func decodePubKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == ed25519.PublicKeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("public key %q is not 32 bytes of base64 or hex", s)
}

// queryServer queries a single Roughtime server. IETF servers receive every
// supported version in one VER tag.
func queryServer(ctx context.Context, srv serverConfig) result {
	r := result{Name: srv.Name}

	if len(srv.Addresses) == 0 {
		r.Err = fmt.Errorf("no addresses")
		return r
	}
	r.Address = srv.Addresses[0].Address

	rootPK, err := decodePubKey(srv.PublicKey)
	if err != nil {
		r.Err = fmt.Errorf("decoding public key: %w", err)
		return r
	}

	if strings.EqualFold(string(srv.Version), "Google-Roughtime") {
		return queryOnce(ctx, srv.Name, r.Address, rootPK, []protocol.Version{protocol.VersionGoogle}, *timeout)
	}

	return queryOnce(ctx, srv.Name, r.Address, rootPK, ietfVersions, *timeout)
}

// queryChained queries servers sequentially using protocol.Chain, deriving each
// nonce from the previous response per §8.2. Results are returned in server
// order.
func queryChained(ctx context.Context, servers []serverConfig) ([]result, *protocol.Chain) {
	var c protocol.Chain
	results := make([]result, len(servers))

	for i, srv := range servers {
		if ctx.Err() != nil {
			results[i].Name = srv.Name
			if len(srv.Addresses) > 0 {
				results[i].Address = srv.Addresses[0].Address
			}
			results[i].Err = ctx.Err()
			continue
		}
		r := &results[i]
		r.Name = srv.Name
		if len(srv.Addresses) == 0 {
			r.Err = fmt.Errorf("no addresses")
			continue
		}
		r.Address = srv.Addresses[0].Address

		rootPK, err := decodePubKey(srv.PublicKey)
		if err != nil {
			r.Err = fmt.Errorf("decoding public key: %w", err)
			continue
		}

		versions := ietfVersions
		if strings.EqualFold(string(srv.Version), "Google-Roughtime") {
			versions = []protocol.Version{protocol.VersionGoogle}
		}

		link, err := c.NextRequest(versions, rootPK, rand.Reader)
		if err != nil {
			r.Err = fmt.Errorf("creating chained request: %w", err)
			continue
		}

		parsed, err := protocol.ParseRequest(link.Request)
		if err != nil {
			r.Err = fmt.Errorf("parsing chained request: %w", err)
			continue
		}

		var reply []byte
		var rtt time.Duration
		var localNow time.Time
		var midpoint time.Time
		var radius time.Duration
		sleep := retryBackoffInitial
		ok := false
		for attempt := range *retries {
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
			reply, rtt, localNow, err = sendRequest(ctx, r.Address, link.Request, *timeout)
			if err == nil {
				midpoint, radius, err = protocol.VerifyReply(versions, reply, rootPK, parsed.Nonce, link.Request)
			}
			if err == nil {
				ok = true
				break
			}
			if attempt < *retries-1 {
				// Back off between retries; a verify failure may be grease (§7)
				if !sleepCtx(ctx, sleep) {
					err = ctx.Err()
					break
				}
				sleep = nextBackoff(sleep)
			}
		}
		if !ok {
			r.Err = err
			continue
		}
		r.RTT = rtt
		r.LocalNow = localNow
		link.Response = reply

		// Append only after verification to protect subsequent nonce derivation
		c.Append(link)

		r.Midpoint = midpoint
		r.Radius = radius
		if ver, ok := protocol.ExtractVersion(reply); ok {
			r.Version = ver
		} else if len(versions) == 1 {
			r.Version = versions[0]
		}
	}

	return results, &c
}

// replyBufPool pools max-sized UDP read buffers.
var replyBufPool = sync.Pool{
	New: func() any { b := make([]byte, 65535); return &b },
}

// sleepCtx sleeps for d, returning false if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// sendRequest sends a Roughtime request to address and returns the reply, RTT,
// and local receive time. Cancellation of ctx closes the socket to unblock the
// read.
func sendRequest(ctx context.Context, address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("resolving %s: %w", address, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set write deadline: %w", err)
	}
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("sending: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set read deadline: %w", err)
	}
	bufp := replyBufPool.Get().(*[]byte)
	defer replyBufPool.Put(bufp)
	n, err := conn.Read(*bufp)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		if errors.Is(err, net.ErrClosed) {
			return nil, 0, time.Time{}, err
		}
		return nil, 0, time.Time{}, fmt.Errorf("reading: %w", err)
	}
	out := make([]byte, n)
	copy(out, (*bufp)[:n])
	return out, time.Since(start), time.Now(), nil
}

// queryOnce sends one Roughtime request, verifies the response, and retries on
// failure with linear backoff.
func queryOnce(ctx context.Context, name, address string, rootPK []byte, versions []protocol.Version, timeout time.Duration) result {
	r := result{Name: name, Address: address}

	srv := protocol.ComputeSRV(rootPK)
	nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		r.Err = fmt.Errorf("creating request: %w", err)
		return r
	}

	var reply []byte
	var rtt time.Duration
	var localNow time.Time
	var midpoint time.Time
	var radius time.Duration
	sleep := retryBackoffInitial
	for attempt := range *retries {
		if ctx.Err() != nil {
			r.Err = ctx.Err()
			return r
		}
		var networkErr bool
		reply, rtt, localNow, err = sendRequest(ctx, address, request, timeout)
		if err != nil {
			networkErr = true
		} else {
			midpoint, radius, err = protocol.VerifyReply(versions, reply, rootPK, nonce, request)
		}
		if err == nil {
			break
		}
		if attempt == *retries-1 {
			if !networkErr {
				err = fmt.Errorf("verification: %w", err)
			}
			r.Err = err
			return r
		}
		// Back off between retries; a verify failure may be grease (§7)
		if !sleepCtx(ctx, sleep) {
			r.Err = ctx.Err()
			return r
		}
		sleep = nextBackoff(sleep)
	}
	r.RTT = rtt
	r.LocalNow = localNow

	r.Midpoint = midpoint
	r.Radius = radius
	if ver, ok := protocol.ExtractVersion(reply); ok {
		r.Version = ver
	} else if len(versions) == 1 {
		r.Version = versions[0]
	}
	return r
}
