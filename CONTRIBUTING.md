# Contributing

Thanks for your interest. This is a small, focused JWT/JOSE library; changes
are weighed against the design in [`spec.md`](spec.md).

## Reporting security issues

**Do not open a public issue for a vulnerability.** Use GitHub's private
vulnerability reporting (the *Report a vulnerability* button on the Security
tab). See [`SECURITY.md`](SECURITY.md).

## Scope

In scope: bug fixes, RFC-conformance gaps, test coverage, ergonomics that do
not widen the API surface. Out of scope: an OAuth 2.x authorization server,
OIDC relying-party flow orchestration, filesystem access, key generation
(see `spec.md` §2.2). New algorithms need an RFC citation and interop tests.

## Development

Requires Go 1.27+. No third-party runtime dependencies — keep it that way;
anything that would add a `require` to the root `go.mod` will not be merged.

```sh
go build ./...
go vet ./...
gofmt -l .                       # must print nothing
golangci-lint run ./...          # config in .golangci.yml, must be 0 issues
go test -race ./...

# cross-library interop (separate module, its own go.mod)
cd interop && go test ./...

# fuzz smoke
go test -run '^$' -fuzz '^FuzzParse$' -fuzztime 30s .
```

The `jwttest` sub-package ships fakes and shared conformance suites; run them
against any new `KeyProvider` / `RevocationStore` implementation.

## Style

- `gofmt`; every exported identifier has a doc comment starting with its name.
- Sentinel errors (`Err*`), checked with `errors.Is`; never substring matches.
- Table-driven tests for algorithm / claim matrices.
- No `panic` in non-test code; every fallible function returns `error`.
- Commit messages: lowercase, imperative, concise (e.g. `fix ECDH-ES+A256KW KDF`).

## Pull requests

1. Branch from `main`; keep the history linear (squash on merge).
2. `go test -race ./...`, `cd interop && go test ./...`, `golangci-lint run`
   and `gofmt -l .` all clean.
3. Update `spec.md`, `README.md` and `CHANGELOG.md` (`[Unreleased]`) when the
   public API or behaviour changes.
4. Once tagged `v1.0.0`, the CI `apidiff` job blocks incompatible API changes
   without a major version bump.
