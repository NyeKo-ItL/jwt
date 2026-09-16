# Standards watch

A weekly workflow ([`standards-watch.yml`](../workflows/standards-watch.yml))
checks whether the standards this library implements have changed, and opens
(or refreshes) **one** GitHub issue labelled `standards-watch` when they have.
It only reports: deciding what to do stays with a maintainer.

## What is checked

| Source | Endpoint | Detects |
|---|---|---|
| RFC Editor metadata | `https://www.rfc-editor.org/rfc/rfcNNNN.json` | status changes; new "obsoleted by" / "updated by" RFCs (e.g. RFC 9864 updating RFC 7518) |
| RFC Editor errata | `https://www.rfc-editor.org/api/v1/errata.json` | new errata and status changes (Reported → Verified, …) for tracked RFCs |
| IANA registries | `https://www.iana.org/assignments/{jose,jwt}/*.xml` | new, removed or changed algorithms, header / key parameters, curves, key operations, claims, confirmation methods — including implementation-requirement changes such as `EdDSA` → Deprecated |
| IETF Datatracker | `https://datatracker.ietf.org/doc/<draft>/doc.json` | new revisions, IESG / RFC Editor state, publication as an RFC |
| OpenID specifications | the specification pages | any content change (errata sets) |

What is tracked, and which files a change most likely affects, is configured
in [`tracked.json`](tracked.json). The last reviewed state is
[`baseline.json`](baseline.json).

## Triage

When the issue appears:

1. For each item, decide whether the library, [`COMPLIANCE.md`](../../COMPLIANCE.md)
   or [`SECURITY.md`](../../SECURITY.md) needs a change. Open a PR for it
   (tests first), or note in the issue why no change is needed.
2. Accept the new state:

   ```sh
   cd .github/standards
   go run . -accept
   ```

   `-accept` refuses to run if any source could not be fetched, so a partial
   snapshot never becomes the baseline.
3. Commit `baseline.json` in a PR that closes the issue.

To track another RFC, draft, registry or page, add it to `tracked.json`
(with an `impact` hint), run `go run . -accept`, and commit both files.

## Behaviour

- **Fetch failures** are listed in the report and annotated as workflow
  warnings. The baseline value is kept for that source, so an outage never
  shows up as a removal. A run with only failures opens no issue.
- **Repeated runs** re-edit the open issue only when the list of changes
  differs, so a pending review does not get a new comment every week.
- **Workflow permissions:** `contents: read` and `issues: write` only. No
  secrets, no third-party actions beyond the pinned `checkout` / `setup-go`,
  and no LLM: the same inputs always give the same report.
- **Tests:** `go test ./...` in this directory runs offline against
  `testdata/`, and runs in CI (`standards-watch-tool` job).

```sh
go run .            # check: writes report.md; sets changed=true|false in $GITHUB_OUTPUT
go run . -accept    # store the current state as baseline.json
go test ./...       # offline tests
```
