`draft07-independent.json` is an independently encoded, signed draft 07 vector.
It uses only standard-library Ed25519 and SHA-512/256, without calling this
project's codec, certificate, signing or Merkle functions.

The root seed is 32 bytes of 0x52 and the online seed is 32 bytes of 0x4f. MIDP
is 2024-11-15 12:00:00 UTC, the delegation spans one hour on either side, and
RADI is 1,000,000 microseconds. Three leaf nonces contain repeated 0x11, 0x22
and 0x33 bytes. The final leaf is repeated to fill the tree. The first leaf's
two-sibling proof follows the prose ordering in draft 07 section 6.4.1.
Delegation and response signatures use that draft's exact NUL-terminated
contexts.

The vector exercises the distinct SHA-512/256 and MJD combination in both a
regression test and the response-verification fuzzer. Test private keys have no
operational use.

`rfc10049-appendix-b.json` contains the malfeasance example from RFC 10049
Appendix B. Its signatures use the older `RoughTime` contexts. Strict
verification rejects them. Flex verification authenticates both replies and
detects their causal contradiction. RFC signature contexts and Merkle paths are
checked separately with standard-library cryptographic functions in
`rfc_test.go`.

`fuzz/FuzzParseMalfeasanceReport/modern-draft10` is an authenticated draft-10
report in modern JSON form. It checks conversion to the historical format, which
omits request/key metadata and the first link's unused blind.
