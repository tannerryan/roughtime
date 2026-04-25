package mldsa

// Stubs for functions that are implemented in the upstream
// crypto/internal/fips140/mldsa package, to minimize the diff.

import "sync"

func fipsPCT(priv *PrivateKey) {}

var fipsSelfTest = sync.OnceFunc(func() {})
