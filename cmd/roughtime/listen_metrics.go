// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Metrics-listener tunables.
const (
	// metricsContentType is the Prometheus text-format media type.
	metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	// metricsReadHeaderTimeout bounds slowloris-style header reads.
	metricsReadHeaderTimeout = 5 * time.Second
	// metricsReadTimeout bounds total request read time.
	metricsReadTimeout = 5 * time.Second
	// metricsWriteTimeout bounds total response write time.
	metricsWriteTimeout = 10 * time.Second
	// metricsIdleTimeout bounds keep-alive idle time.
	metricsIdleTimeout = 30 * time.Second
	// metricsMaxHeaderBytes caps the request header size.
	metricsMaxHeaderBytes = 8 * 1024
	// metricsShutdownTimeout bounds the graceful shutdown drain.
	metricsShutdownTimeout = 2 * time.Second
)

// scrapeBufPool recycles full-response buffers across scrapes.
var scrapeBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// listenMetrics serves /metrics and /healthz until cancellation or a listener
// failure.
func listenMetrics(ctx context.Context, addr string) error {
	log := logger.Named("metrics")
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/healthz", handleHealthz)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: metricsReadHeaderTimeout,
		ReadTimeout:       metricsReadTimeout,
		WriteTimeout:      metricsWriteTimeout,
		IdleTimeout:       metricsIdleTimeout,
		MaxHeaderBytes:    metricsMaxHeaderBytes,
		ErrorLog:          zap.NewStdLog(log),
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("binding metrics listener on %q: %w", addr, err)
	}
	log.Info("metrics endpoint listening",
		zap.String("addr", ln.Addr().String()),
	)

	// serveCtx fires on parent cancel or on Serve returning early. The deferred
	// wait ensures Shutdown drains handlers before we return.
	serveCtx, serveCancel := context.WithCancel(ctx)
	shutdownDone := make(chan struct{})
	defer func() {
		serveCancel()
		<-shutdownDone
	}()
	go func() {
		defer close(shutdownDone)
		<-serveCtx.Done()
		sctx, scancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer scancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("metrics shutdown returned an error", zap.Error(err))
		}
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics listener: %w", err)
	}
	log.Info("metrics endpoint stopped")
	return nil
}

// handleMetrics renders the registry in Prometheus text format. GET and HEAD
// only.
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", metricsContentType)
	h.Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	buf := scrapeBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer scrapeBufPool.Put(buf)
	writeRegistry(buf)
	_, _ = w.Write(buf.Bytes())
}

// handleHealthz reports metrics-listener liveness for GET and HEAD requests.
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}
