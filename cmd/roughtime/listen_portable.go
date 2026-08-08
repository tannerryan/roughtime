// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix && !linux && !openbsd

package main

import (
	"context"
	"sync/atomic"
)

// socketRecvBuffer is the requested receive-buffer size for each UDP socket.
const socketRecvBuffer = 8 * 1024 * 1024

func listen(ctx context.Context, state *atomic.Pointer[certState]) error {
	return listenPortable(ctx, state)
}
