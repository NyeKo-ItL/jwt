package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureServer(t *testing.T, override map[string]http.HandlerFunc) (*httptest.Server, Endpoints) {
	t.Helper()

	files := map[string]string{
		"/rfc/rfc7519.json":                         "rfc7519.json",
		"/api/v1/errata.json":                       "errata.json",
		"/assignments/jose/jose.xml":                "jose.xml",
		"/assignments/jwt/jwt.xml":                  "jwt.xml",
		"/doc/draft-ietf-oauth-rfc8725bis/doc.json": "draft.json",
		"/specs/openid-connect-core-1_0.html":       "page.html",
	}

	mux := http.NewServeMux()
	for path, file := range files {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if h, ok := override[path]; ok {
				h(w, r)
				return
			}

			http.ServeFile(w, r, filepath.Join("testdata", file))
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, Endpoints{RFCEditor: srv.URL, IANA: srv.URL, Datatracker: srv.URL}
}

func fixtureConfig(pageURL string) Config {
	return Config{
		RFCs:   []int{7519},
		Drafts: []string{"draft-ietf-oauth-rfc8725bis"},
		IANA:   map[string][]string{"jose": nil, "jwt": {"claims"}},
		Pages:  map[string]string{"OpenID Connect Core 1.0": pageURL + "/specs/openid-connect-core-1_0.html"},
		Impact: map[string]string{
			"RFC7519": "jwt.go, claims.go",
			"jose/web-signature-encryption-algorithms": "alg.go",
			"OpenID Connect": "idtoken.go",
		},
	}
}

func TestCollectFromFixtures(t *testing.T) {
	srv, ep := fixtureServer(t, nil)

	snap, errs := Collect(context.Background(), srv.Client(), fixtureConfig(srv.URL), ep)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}

	rfc := snap.RFCs["RFC7519"]
	if rfc.Status != "PROPOSED STANDARD" || strings.Join(rfc.UpdatedBy, ",") != "RFC7797,RFC8725" || len(rfc.ObsoletedBy) != 0 {
		t.Fatalf("RFC metadata: %+v", rfc)
	}

	// Only errata of tracked RFCs are kept.
	if len(snap.Errata) != 1 || len(snap.Errata["RFC7519"]) != 3 || snap.Errata["RFC7519"]["5906"].Status != "Reported" {
		t.Fatalf("errata: %+v", snap.Errata)
	}

	algs := snap.Registries["jose/web-signature-encryption-algorithms"]
	if algs["EdDSA"].Requirements != "Deprecated" || strings.Join(algs["EdDSA"].References, " ") != "rfc8037#3.1 rfc9864#4.1.2" {
		t.Fatalf("algorithm registry: %+v", algs)
	}

	// Records sharing a value are keyed by value and usage.
	hdr := snap.Registries["jose/web-signature-encryption-header-parameters"]
	if _, ok := hdr["alg|JWS"]; !ok || len(hdr) != 2 {
		t.Fatalf("header registry keys: %v", hdr)
	}

	// Sub-registry filter: jwt/claims kept, jwt/status-mechanisms skipped.
	if _, ok := snap.Registries["jwt/claims"]["iss"]; !ok || snap.Registries["jwt/status-mechanisms"] != nil {
		t.Fatalf("jwt registries: %v", snap.Registries)
	}

	d := snap.Drafts["draft-ietf-oauth-rfc8725bis"]
	if d.Rev != "10" || d.IESGState != "RFC Ed Queue" || d.RFCEditorState != "EDIT" {
		t.Fatalf("draft: %+v", d)
	}

	if h := snap.Pages["OpenID Connect Core 1.0"]; len(h) != 64 {
		t.Fatalf("page hash: %q", h)
	}
}

func TestPageHashIgnoresWhitespaceOnlyChanges(t *testing.T) {
	a := hashPage([]byte("<p>errata  set 2</p>\n"))
	b := hashPage([]byte("<p>errata set 2</p>\r\n\n"))
	c := hashPage([]byte("<p>errata set 3</p>"))

	if a != b || a == c {
		t.Fatalf("hashPage: %s %s %s", a, b, c)
	}
}

func TestCollectReportsFailuresPerSource(t *testing.T) {
	srv, ep := fixtureServer(t, map[string]http.HandlerFunc{
		"/assignments/jose/jose.xml": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusBadGateway)
		},
		"/api/v1/errata.json": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		},
	})

	snap, errs := Collect(context.Background(), srv.Client(), fixtureConfig(srv.URL), ep)
	if len(errs) != 2 {
		t.Fatalf("errors = %v, want 2", errs)
	}

	var se *SourceError
	if !errors.As(errs[0], &se) {
		t.Fatalf("error type %T", errs[0])
	}

	if snap.RFCs["RFC7519"].Status == "" || snap.Registries["jwt/claims"] == nil {
		t.Fatal("healthy sources were not collected")
	}
}

func TestKeepFromBaselineAvoidsSpuriousRemovals(t *testing.T) {
	srv, ep := fixtureServer(t, nil)
	cfg := fixtureConfig(srv.URL)

	base, _ := Collect(context.Background(), srv.Client(), cfg, ep)

	broken, ep2 := fixtureServer(t, map[string]http.HandlerFunc{
		"/assignments/jose/jose.xml":          func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"/rfc/rfc7519.json":                   func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"/api/v1/errata.json":                 func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"/specs/openid-connect-core-1_0.html": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"/doc/draft-ietf-oauth-rfc8725bis/doc.json": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "x", 500)
		},
	})
	cfg.Pages["OpenID Connect Core 1.0"] = broken.URL + "/specs/openid-connect-core-1_0.html"

	cur, errs := Collect(context.Background(), broken.Client(), cfg, ep2)
	if len(errs) != 5 {
		t.Fatalf("errors = %v", errs)
	}

	cur.KeepFrom(base, errs)

	if changes := Diff(base, cur, cfg); len(changes) != 0 {
		t.Fatalf("fetch failures produced changes: %+v", changes)
	}
}

func TestCollectEnforcesSizeLimit(t *testing.T) {
	srv, ep := fixtureServer(t, map[string]http.HandlerFunc{
		"/rfc/rfc7519.json": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("a", 2<<20) + `"}`))
		},
	})

	cfg := fixtureConfig(srv.URL)
	cfg.MaxBytes = 1 << 20

	if _, errs := Collect(context.Background(), srv.Client(), cfg, ep); len(errs) != 1 || !strings.Contains(errs[0].Error(), "exceeds") {
		t.Fatalf("errors = %v", errs)
	}
}

func baseSnapshot() Snapshot {
	return Snapshot{
		RFCs: map[string]RFC{"RFC7519": {Title: "JWT", Status: "PROPOSED STANDARD", UpdatedBy: []string{"RFC8725"}}},
		Errata: map[string]map[string]Erratum{
			"RFC7519": {"5906": {Status: "Reported", Type: "Technical", Section: "4.1.3"}},
		},
		Registries: map[string]map[string]Record{
			"jose/web-signature-encryption-algorithms": {
				"EdDSA": {Description: "EdDSA signature algorithms", Usage: "alg", Requirements: "Optional"},
				"ES256": {Description: "ECDSA", Usage: "alg", Requirements: "Recommended+"},
			},
		},
		Drafts: map[string]Draft{"draft-ietf-oauth-rfc8725bis": {Rev: "09", State: "Active", IESGState: "In Last Call"}},
		Pages:  map[string]string{"OpenID Connect Core 1.0": "aaa"},
	}
}

func TestDiffNoChanges(t *testing.T) {
	if changes := Diff(baseSnapshot(), baseSnapshot(), Config{}); len(changes) != 0 {
		t.Fatalf("identical snapshots: %+v", changes)
	}
}

func TestDiffDetectsEveryKindOfChange(t *testing.T) {
	cur := baseSnapshot()
	cur.RFCs["RFC7519"] = RFC{Title: "JWT", Status: "PROPOSED STANDARD", UpdatedBy: []string{"RFC8725", "RFC9999"}, ObsoletedBy: []string{"RFC9998"}}
	cur.Errata["RFC7519"] = map[string]Erratum{
		"5906": {Status: "Verified", Type: "Technical", Section: "4.1.3"},
		"8000": {Status: "Reported", Type: "Editorial", Section: "2"},
	}
	algs := cur.Registries["jose/web-signature-encryption-algorithms"]
	algs["EdDSA"] = Record{Description: "EdDSA signature algorithms", Usage: "alg", Requirements: "Deprecated"}
	algs["Ed25519"] = Record{Description: "EdDSA using Ed25519", Usage: "alg", Requirements: "Optional"}
	delete(algs, "ES256")

	cur.Drafts["draft-ietf-oauth-rfc8725bis"] = Draft{Rev: "10", State: "RFC", IESGState: "RFC Published", RFC: "RFC9999"}
	cur.Pages["OpenID Connect Core 1.0"] = "bbb"

	cfg := Config{Impact: map[string]string{
		"RFC7519": "jwt.go",
		"jose/web-signature-encryption-algorithms": "alg.go",
		"OpenID Connect": "idtoken.go",
	}}

	changes := Diff(baseSnapshot(), cur, cfg)

	want := map[string]string{
		"RFC7519 is updated by RFC9999":                                                                                         "jwt.go",
		"RFC7519 is obsoleted by RFC9998":                                                                                       "jwt.go",
		"RFC7519 erratum 5906: Reported → Verified":                                                                             "jwt.go",
		"RFC7519 erratum 8000 (Editorial, §2): new, Reported":                                                                   "jwt.go",
		"jose/web-signature-encryption-algorithms EdDSA: requirements Optional → Deprecated":                                    "alg.go",
		"jose/web-signature-encryption-algorithms Ed25519: registered":                                                          "alg.go",
		"jose/web-signature-encryption-algorithms ES256: removed":                                                               "alg.go",
		"draft-ietf-oauth-rfc8725bis: rev 09 → 10; state Active → RFC; IESG In Last Call → RFC Published; published as RFC9999": "",
		"OpenID Connect Core 1.0: content changed":                                                                              "idtoken.go",
	}

	got := map[string]string{}
	for _, c := range changes {
		got[c.Summary] = c.Impact
	}

	for summary, impact := range want {
		gotImpact, ok := got[summary]
		if !ok {
			t.Errorf("missing change %q\n got: %v", summary, keys(got))
			continue
		}

		if gotImpact != impact {
			t.Errorf("%q impact = %q, want %q", summary, gotImpact, impact)
		}
	}

	if len(changes) != len(want) {
		t.Errorf("got %d changes, want %d: %v", len(changes), len(want), keys(got))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}

func TestReport(t *testing.T) {
	cur := baseSnapshot()
	cur.Pages["OpenID Connect Core 1.0"] = "bbb"
	changes := Diff(baseSnapshot(), cur, Config{Impact: map[string]string{"OpenID Connect": "idtoken.go"}})

	md := Report(changes, []error{&SourceError{Source: "IANA jose", Err: errors.New("status 502")}}, "2026-09-21")

	for _, want := range []string{
		"# Standards changes to review",
		"2026-09-21",
		"## Pages",
		"OpenID Connect Core 1.0: content changed",
		"idtoken.go",
		"## Fetch failures",
		"IANA jose: status 502",
		"COMPLIANCE.md",
		"go run . -accept",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q:\n%s", want, md)
		}
	}

	if empty := Report(nil, nil, "2026-09-21"); !strings.Contains(empty, "No changes") {
		t.Errorf("empty report: %s", empty)
	}
}

func TestRunWritesOutputsAndAccepts(t *testing.T) {
	srv, ep := fixtureServer(t, nil)
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "tracked.json")
	raw, _ := json.Marshal(fixtureConfig(srv.URL))
	_ = os.WriteFile(cfgPath, raw, 0o600)

	baseline := filepath.Join(dir, "baseline.json")
	report := filepath.Join(dir, "report.md")
	output := filepath.Join(dir, "github_output")

	opts := runOptions{config: cfgPath, baseline: baseline, report: report, githubOutput: output, endpoints: ep, client: srv.Client(), date: "2026-09-21"}

	// No baseline yet: everything is new, so there are changes.
	if err := run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	if out, _ := os.ReadFile(output); !strings.Contains(string(out), "changed=true") { //nolint:gosec // t.TempDir path
		t.Fatalf("GITHUB_OUTPUT = %q", out)
	}

	// Accept: the snapshot becomes the baseline...
	opts.accept = true
	if err := run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	// ...so the next check reports nothing.
	opts.accept = false
	_ = os.Remove(output)

	if err := run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	if out, _ := os.ReadFile(output); !strings.Contains(string(out), "changed=false") { //nolint:gosec // t.TempDir path
		t.Fatalf("after accept GITHUB_OUTPUT = %q", out)
	}

	if md, _ := os.ReadFile(report); !strings.Contains(string(md), "No changes") { //nolint:gosec // t.TempDir path
		t.Fatalf("after accept report = %s", md)
	}
}

func TestTrackedConfigIsValid(t *testing.T) {
	cfg, err := LoadConfig("tracked.json")
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.RFCs) == 0 || len(cfg.Drafts) == 0 || len(cfg.IANA) == 0 || len(cfg.Pages) == 0 {
		t.Fatalf("incomplete config: %+v", cfg)
	}

	for _, n := range cfg.RFCs {
		if _, ok := cfg.Impact[rfcID(n)]; !ok {
			t.Errorf("no impact hint for %s", rfcID(n))
		}
	}
}

func TestAcceptRefusesPartialSnapshot(t *testing.T) {
	srv, ep := fixtureServer(t, map[string]http.HandlerFunc{
		"/assignments/jwt/jwt.xml": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) },
	})
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "tracked.json")
	raw, _ := json.Marshal(fixtureConfig(srv.URL))
	_ = os.WriteFile(cfgPath, raw, 0o600)

	baseline := filepath.Join(dir, "baseline.json")
	opts := runOptions{config: cfgPath, baseline: baseline, report: filepath.Join(dir, "r.md"), endpoints: ep, client: srv.Client(), accept: true}

	if err := run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("accept with a failing source: %v", err)
	}

	if _, err := os.Stat(baseline); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a partial baseline was written")
	}
}
