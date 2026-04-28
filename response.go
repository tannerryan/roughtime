// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"strings"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// Response is the verified outcome of a single query, including raw Request and
// Reply bytes for archival.
type Response struct {
	// Server is the input server description.
	Server Server
	// Address is the endpoint dialed.
	Address Address
	// Version is the negotiated wire version.
	Version protocol.Version
	// Midpoint is the server's claimed midpoint timestamp.
	Midpoint time.Time
	// Radius is the half-width of the server's uncertainty window.
	Radius time.Duration
	// RTT is the measured round-trip time.
	RTT time.Duration
	// LocalNow is the local wall clock at reply receipt.
	LocalNow time.Time
	// Request is the verified request bytes, including the nonce.
	Request []byte
	// Reply is the verified reply bytes.
	Reply []byte
	// AmplificationOK reports that on UDP the reply fits within the request
	// size; always true on TCP.
	AmplificationOK bool
}

// Drift reports the signed offset between the server's midpoint and the
// RTT-corrected local clock.
func (r *Response) Drift() time.Duration {
	ref := r.LocalNow.Add(-r.RTT / 2)
	return r.Midpoint.Sub(ref)
}

// InSync reports whether |Drift| is within the server's uncertainty Radius
// using a closed interval.
func (r *Response) InSync() bool {
	d := r.Drift()
	if d < 0 {
		d = -d
	}
	return d <= r.Radius
}

// buildResponse assembles a [Response] from a successful verification.
func buildResponse(s Server, addr Address, request, reply []byte, midpoint time.Time, radius time.Duration, rtt time.Duration, localNow time.Time) *Response {
	r := &Response{
		Server:          s,
		Address:         addr,
		Midpoint:        midpoint,
		Radius:          radius,
		RTT:             rtt,
		LocalNow:        localNow,
		Request:         request,
		Reply:           reply,
		AmplificationOK: !strings.EqualFold(addr.Transport, "udp") || len(reply) <= len(request),
	}
	if ver, ok := protocol.ExtractVersion(reply); ok {
		r.Version = ver
	}
	return r
}
