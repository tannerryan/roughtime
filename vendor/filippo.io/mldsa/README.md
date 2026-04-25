# filippo.io/mldsa

This package implements the [crypto/mldsa proposed API](https://go.dev/issue/77626).

Its API may change, and eventually this package will become a wrapper around the
final API in the standard library.

The actual implementation is merged from the internal upstream package
crypto/internal/fips140/mldsa, with very few changes (visible in the merge
commits in the git history).
