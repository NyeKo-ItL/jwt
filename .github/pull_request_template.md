<!-- For a security vulnerability, do NOT open a PR — use the Security tab. -->

## What & why

<!-- One or two sentences. Link the issue if any. -->

## Checklist

- [ ] `go test -race ./...` passes
- [ ] `cd interop && go test ./...` passes (if JWS/JWE behaviour changed)
- [ ] `gofmt -l .` and `golangci-lint run ./...` are clean
- [ ] No new entry in the root `go.mod` `require` block
- [ ] `spec.md` / `README.md` / `CHANGELOG.md` updated for API or behaviour changes
- [ ] New algorithms cite the RFC and add interop coverage
