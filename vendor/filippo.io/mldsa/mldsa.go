// Package mldsa implements the post-quantum ML-DSA signature scheme specified
// in FIPS 204.
package mldsa

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"io"

	"filippo.io/mldsa/internal/fips140/mldsa"
	"filippo.io/mldsa/mldsacrypto"
)

const (
	PrivateKeySize = 32

	MLDSA44PublicKeySize = 1312
	MLDSA65PublicKeySize = 1952
	MLDSA87PublicKeySize = 2592

	MLDSA44SignatureSize = 2420
	MLDSA65SignatureSize = 3309
	MLDSA87SignatureSize = 4627
)

// Parameters represents one of the fixed parameter sets defined in FIPS 204.
//
// Most applications should use [MLDSA44].
type Parameters struct {
	name       string
	pubKeySize int
	sigSize    int
}

var (
	mldsa44 = &Parameters{"ML-DSA-44", MLDSA44PublicKeySize, MLDSA44SignatureSize}
	mldsa65 = &Parameters{"ML-DSA-65", MLDSA65PublicKeySize, MLDSA65SignatureSize}
	mldsa87 = &Parameters{"ML-DSA-87", MLDSA87PublicKeySize, MLDSA87SignatureSize}
)

// MLDSA44 returns the ML-DSA-44 parameter set defined in FIPS 204.
//
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements. The returned value is safe
// for concurrent use.
func MLDSA44() *Parameters { return mldsa44 }

// MLDSA65 returns the ML-DSA-65 parameter set defined in FIPS 204.
//
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements. The returned value is safe
// for concurrent use.
func MLDSA65() *Parameters { return mldsa65 }

// MLDSA87 returns the ML-DSA-87 parameter set defined in FIPS 204.
//
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements. The returned value is safe
// for concurrent use.
func MLDSA87() *Parameters { return mldsa87 }

// PublicKeySize returns the size of public keys for this parameter set, in bytes.
func (params *Parameters) PublicKeySize() int { return params.pubKeySize }

// SignatureSize returns the size of signatures for this parameter set, in bytes.
func (params *Parameters) SignatureSize() int { return params.sigSize }

// String returns the name of the parameter set, e.g. "ML-DSA-44".
func (params *Parameters) String() string { return params.name }

// PrivateKey is an in-memory ML-DSA private key. It implements [crypto.Signer]
// and the informal extended [crypto.PrivateKey] interface.
//
// A PrivateKey is safe for concurrent use.
type PrivateKey struct {
	key *mldsa.PrivateKey
}

// GenerateKey generates a new random ML-DSA private key.
func GenerateKey(params *Parameters) (*PrivateKey, error) {
	switch params {
	case mldsa44:
		return &PrivateKey{mldsa.GenerateKey44()}, nil
	case mldsa65:
		return &PrivateKey{mldsa.GenerateKey65()}, nil
	case mldsa87:
		return &PrivateKey{mldsa.GenerateKey87()}, nil
	default:
		return nil, errors.New("mldsa: invalid parameters")
	}
}

// NewPrivateKey creates a new ML-DSA private key from the given seed.
//
// The seed must be exactly [PrivateKeySize] bytes long.
func NewPrivateKey(params *Parameters, seed []byte) (*PrivateKey, error) {
	var key *mldsa.PrivateKey
	var err error
	switch params {
	case mldsa44:
		key, err = mldsa.NewPrivateKey44(seed)
	case mldsa65:
		key, err = mldsa.NewPrivateKey65(seed)
	case mldsa87:
		key, err = mldsa.NewPrivateKey87(seed)
	default:
		return nil, errors.New("mldsa: invalid parameters")
	}
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key}, nil
}

// Public returns the corresponding [PublicKey] for this private key.
//
// It implements the [crypto.Signer] interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.PublicKey()
}

// Equal reports whether sk and x are the same key (i.e. they are derived from
// the same seed).
//
// If x is not a *PrivateKey, Equal returns false.
func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(sk.Bytes(), other.Bytes()) == 1
}

// PublicKey returns the corresponding [PublicKey] for this private key.
func (sk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{sk.key.PublicKey()}
}

// Bytes returns the private key seed.
func (sk *PrivateKey) Bytes() []byte {
	return sk.key.Bytes()
}

// Sign returns a signature of the given message using this private key.
//
// If opts is nil or opts.HashFunc returns zero, the message is signed directly.
// If opts.HashFunc returns [crypto.MLDSAMu], the provided message must be a
// [pre-hashed μ message representative]. opts can be of type *[Options].
// The io.Reader argument is ignored.
//
// [pre-hashed μ message representative]: https://www.rfc-editor.org/rfc/rfc9881.html#externalmu
func (sk *PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch {
	case opts == nil || opts.HashFunc() == 0:
		// Sign the message directly.
		var context string
		if opts, ok := opts.(*Options); ok {
			context = opts.Context
		}
		return mldsa.Sign(sk.key, message, context)
	case opts.HashFunc() == mldsacrypto.MLDSAMu:
		// Sign the pre-hashed μ message representative.
		return mldsa.SignExternalMu(sk.key, message)
	default:
		return nil, errors.New("mldsa: invalid SignerOpts.HashFunc")
	}
}

// SignDeterministic works like [PrivateKey.Sign], but the signature is
// deterministic.
func (sk *PrivateKey) SignDeterministic(message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch {
	case opts == nil || opts.HashFunc() == 0:
		// Sign the message directly.
		var context string
		if opts, ok := opts.(*Options); ok {
			context = opts.Context
		}
		return mldsa.SignDeterministic(sk.key, message, context)
	case opts.HashFunc() == mldsacrypto.MLDSAMu:
		// Sign the pre-hashed μ message representative.
		return mldsa.SignExternalMuDeterministic(sk.key, message)
	default:
		return nil, errors.New("mldsa: invalid SignerOpts.HashFunc")
	}
}

// PublicKey is an ML-DSA public key. It implements the informal extended
// [crypto.PublicKey] interface.
//
// A PublicKey is safe for concurrent use.
type PublicKey struct {
	key *mldsa.PublicKey
}

// NewPublicKey creates a new ML-DSA public key from the given encoding.
func NewPublicKey(params *Parameters, seed []byte) (*PublicKey, error) {
	var key *mldsa.PublicKey
	var err error
	switch params {
	case mldsa44:
		key, err = mldsa.NewPublicKey44(seed)
	case mldsa65:
		key, err = mldsa.NewPublicKey65(seed)
	case mldsa87:
		key, err = mldsa.NewPublicKey87(seed)
	default:
		return nil, errors.New("mldsa: invalid parameters")
	}
	if err != nil {
		return nil, err
	}
	return &PublicKey{key}, nil
}

// Bytes returns the public key encoding.
func (pk *PublicKey) Bytes() []byte {
	return pk.key.Bytes()
}

// Equal reports whether pk and x are the same key (i.e. they have the same
// encoding).
//
// If x is not a *PublicKey, Equal returns false.
func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pk.Bytes(), other.Bytes()) == 1
}

// Parameters returns the parameters associated with this public key.
func (pk *PublicKey) Parameters() *Parameters {
	switch pk.key.Parameters() {
	case "ML-DSA-44":
		return mldsa44
	case "ML-DSA-65":
		return mldsa65
	case "ML-DSA-87":
		return mldsa87
	default:
		panic("mldsa: internal error: invalid parameters")
	}
}

// Verify reports whether signature is a valid signature of message by pk.
func Verify(pk *PublicKey, message []byte, signature []byte, opts *Options) error {
	var context string
	if opts != nil {
		context = opts.Context
	}
	return mldsa.Verify(pk.key, message, signature, context)
}

// Options contains additional options for signing and verifying ML-DSA signatures.
type Options struct {
	// Context can be used to distinguish signatures created for different
	// purposes. It must be at most 255 bytes long, and it is empty by default.
	//
	// The same context must be used when signing and verifying a signature.
	Context string
}

// HashFunc returns zero, to implement the [crypto.SignerOpts] interface.
func (opts *Options) HashFunc() crypto.Hash {
	return 0
}
