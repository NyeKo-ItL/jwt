<!-- For a security vulnerability, do NOT open a PR — use the Security tab. -->

## What & why

<!-- One or two sentences. Link the issue if any. -->

## Checklist

- [ ] `go test -race ./...` passes
- [ ] `cd interop && go test ./...` passes (if JWS/JWE behaviour changed)
- [ ] `gofmt -l .` and `golangci-lint run ./...` are clean
- [ ] No new entry in the root `go.mod` `require` block
- [ ] `README.md` / `CHANGELOG.md` / `spec.md` updated for API or behaviour changes
- [ ] `COMPLIANCE.md` updated if a standards requirement is affected
- [ ] Tests written first (fixes: the failing case and its neighbours; features: cases from the RFC text)
- [ ] New algorithms cite the RFC and add interop coverage
