# Contributing

Contributions are welcome. Report security vulnerabilities using
[SECURITY.md](SECURITY.md), not a public issue.

For a substantial API or wire-protocol change, open an issue before investing in
an implementation.

## Development setup

The project requires Go 1.27 or newer and Make. Install the tools once, then run
the tests:

```sh
make deps
make test
```

## Making changes

- Keep changes focused, format Go code with `make fmt`, and add tests for
  behavior changes.
- Protocol changes should identify the affected RFC or draft, transport, and
  signature scheme. Keep strict mode aligned with RFC 10049 and preserve
  interoperability in flex mode.
- Parser and verifier fixes should include a regression case or fuzz seed when
  practical.
- Do not edit `vendor/` by hand. Dependency changes should update `go.mod`,
  `go.sum`, and the generated vendor tree with `go mod tidy` and `go mod vendor`.
- For `ecosystem.json` changes, provide a working endpoint and an
  operator-published root public key in the pull request description.

## Before submitting

Run the full check:

```sh
make check
```

`make check` formats files in place and checks dependencies, linting,
vulnerabilities, builds, and race-enabled tests. Changes to untrusted-input
paths should also run the fuzz targets:

```sh
make fuzz FUZZ_TIME=1m
```

In the pull request, explain the behavior being changed, the protocol versions
affected, and the tests performed. Avoid unrelated cleanup in the same change.
