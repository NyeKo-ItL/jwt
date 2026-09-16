package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is tracked.json: what to watch and where a change would land.
type Config struct {
	RFCs   []int               `json:"rfcs"`
	Drafts []string            `json:"drafts"`
	IANA   map[string][]string `json:"iana"`  // registry file (e.g. "jose") -> sub-registry ids; empty = all
	Pages  map[string]string   `json:"pages"` // display name -> URL
	// Impact maps a subject prefix (RFC id, "file/registry", draft name or
	// page name) to the code likely affected, shown next to each change.
	Impact   map[string]string `json:"impact"`
	MaxBytes int64             `json:"max_bytes,omitempty"`
}

// LoadConfig reads and validates tracked.json.
func LoadConfig(path string) (Config, error) {
	var cfg Config

	raw, err := os.ReadFile(path) //nolint:gosec // path is a CLI flag of this maintenance tool
	if err != nil {
		return cfg, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}

	return cfg, nil
}

// Endpoints are the base URLs of the data sources (overridden in tests).
type Endpoints struct {
	RFCEditor   string
	IANA        string
	Datatracker string
	RetryDelay  time.Duration
}

// DefaultEndpoints returns the production data sources.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		RFCEditor:   "https://www.rfc-editor.org",
		IANA:        "https://www.iana.org",
		Datatracker: "https://datatracker.ietf.org",
		RetryDelay:  5 * time.Second,
	}
}

// Snapshot is the normalized, comparable state of every tracked source.
type Snapshot struct {
	RFCs       map[string]RFC                `json:"rfcs"`
	Errata     map[string]map[string]Erratum `json:"errata"`
	Registries map[string]map[string]Record  `json:"registries"`
	Drafts     map[string]Draft              `json:"drafts"`
	Pages      map[string]string             `json:"pages"`
}

// RFC is the RFC Editor metadata that signals a standard has moved on.
type RFC struct {
	Title       string   `json:"title"`
	Status      string   `json:"status"`
	ObsoletedBy []string `json:"obsoleted_by,omitempty"`
	UpdatedBy   []string `json:"updated_by,omitempty"`
}

// Erratum is one RFC Editor erratum.
type Erratum struct {
	Status  string `json:"status"`
	Type    string `json:"type"`
	Section string `json:"section"`
}

// Record is one IANA registry entry.
type Record struct {
	Description  string   `json:"description,omitempty"`
	Usage        string   `json:"usage,omitempty"`
	Requirements string   `json:"requirements,omitempty"`
	References   []string `json:"references,omitempty"`
}

// Draft is the Datatracker state of an Internet-Draft.
type Draft struct {
	Title          string `json:"title,omitempty"`
	Rev            string `json:"rev"`
	State          string `json:"state"`
	IESGState      string `json:"iesg_state,omitempty"`
	RFCEditorState string `json:"rfceditor_state,omitempty"`
	StdLevel       string `json:"std_level,omitempty"`
	RFC            string `json:"rfc,omitempty"`
}

// SourceError is a failure to fetch or parse one source. The snapshot keeps
// the baseline value for it (KeepFrom), so an outage never looks like a change.
type SourceError struct {
	Source string // human-readable, e.g. "IANA jose"
	kind   string // "rfc", "errata", "iana", "draft", "page"
	key    string
	Err    error
}

func (e *SourceError) Error() string { return e.Source + ": " + e.Err.Error() }
func (e *SourceError) Unwrap() error { return e.Err }

func newSnapshot() Snapshot {
	return Snapshot{
		RFCs:       map[string]RFC{},
		Errata:     map[string]map[string]Erratum{},
		Registries: map[string]map[string]Record{},
		Drafts:     map[string]Draft{},
		Pages:      map[string]string{},
	}
}

func rfcID(n int) string { return "RFC" + strconv.Itoa(n) }

const defaultMaxBytes = 64 << 20

// Collect fetches every source concurrently. Failures are returned per
// source; everything else is still collected.
func Collect(ctx context.Context, client *http.Client, cfg Config, ep Endpoints) (Snapshot, []error) {
	snap := newSnapshot()
	maxBytes := cfg.MaxBytes

	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)

	fail := func(source, kind, key string, err error) {
		mu.Lock()
		defer mu.Unlock()

		errs = append(errs, &SourceError{Source: source, kind: kind, key: key, Err: err})
	}
	get := func(url string) ([]byte, error) { return fetch(ctx, client, url, maxBytes, ep.RetryDelay) }

	for _, n := range cfg.RFCs {
		id := rfcID(n)

		wg.Go(func() {
			raw, err := get(fmt.Sprintf("%s/rfc/rfc%d.json", ep.RFCEditor, n))
			if err == nil {
				var doc struct {
					Title       string   `json:"title"`
					Status      string   `json:"status"`
					ObsoletedBy []string `json:"obsoleted_by"`
					UpdatedBy   []string `json:"updated_by"`
				}
				if err = json.Unmarshal(raw, &doc); err == nil {
					mu.Lock()
					snap.RFCs[id] = RFC{Title: doc.Title, Status: doc.Status, ObsoletedBy: sorted(doc.ObsoletedBy), UpdatedBy: sorted(doc.UpdatedBy)}
					mu.Unlock()

					return
				}
			}

			fail("RFC Editor "+id, "rfc", id, err)
		})
	}

	wg.Go(func() {
		raw, err := get(ep.RFCEditor + "/api/v1/errata.json")
		if err == nil {
			var all []struct {
				ID      string `json:"errata_id"`
				Doc     string `json:"doc-id"`
				Status  string `json:"errata_status_code"`
				Type    string `json:"errata_type_code"`
				Section string `json:"section"`
			}
			if err = json.Unmarshal(raw, &all); err == nil {
				tracked := map[string]bool{}
				for _, n := range cfg.RFCs {
					tracked[rfcID(n)] = true
				}

				mu.Lock()
				for _, e := range all {
					if !tracked[e.Doc] {
						continue
					}

					if snap.Errata[e.Doc] == nil {
						snap.Errata[e.Doc] = map[string]Erratum{}
					}

					snap.Errata[e.Doc][e.ID] = Erratum{Status: e.Status, Type: e.Type, Section: e.Section}
				}
				mu.Unlock()

				return
			}
		}

		fail("RFC Editor errata", "errata", "", err)
	})

	for file, only := range cfg.IANA {
		wg.Go(func() {
			raw, err := get(fmt.Sprintf("%s/assignments/%s/%s.xml", ep.IANA, file, file))
			if err == nil {
				var regs map[string]map[string]Record
				if regs, err = parseIANA(raw, only); err == nil {
					mu.Lock()
					for id, recs := range regs {
						snap.Registries[file+"/"+id] = recs
					}
					mu.Unlock()

					return
				}
			}

			fail("IANA "+file, "iana", file, err)
		})
	}

	for _, name := range cfg.Drafts {
		wg.Go(func() {
			raw, err := get(fmt.Sprintf("%s/doc/%s/doc.json", ep.Datatracker, name))
			if err == nil {
				var d Draft
				if d, err = parseDraft(raw); err == nil {
					mu.Lock()
					snap.Drafts[name] = d
					mu.Unlock()

					return
				}
			}

			fail("Datatracker "+name, "draft", name, err)
		})
	}

	for name, url := range cfg.Pages {
		wg.Go(func() {
			raw, err := get(url)
			if err == nil {
				mu.Lock()
				snap.Pages[name] = hashPage(raw)
				mu.Unlock()

				return
			}

			fail(name, "page", name, err)
		})
	}

	wg.Wait()
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })

	return snap, errs
}

// fetch GETs url with a size cap, retrying transient failures twice.
func fetch(ctx context.Context, client *http.Client, url string, maxBytes int64, retryDelay time.Duration) ([]byte, error) {
	var lastErr error

	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay * time.Duration(attempt)):
			}
		}

		body, retry, err := fetchOnce(ctx, client, url, maxBytes)
		if err == nil || !retry {
			return body, err
		}

		lastErr = err
	}

	return nil, lastErr
}

func fetchOnce(ctx context.Context, client *http.Client, url string, maxBytes int64) (body []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("User-Agent", "NyeKo-ItL-jwt-standards-watch (+https://github.com/NyeKo-ItL/jwt)")

	resp, err := client.Do(req) //nolint:gosec // URLs come from the committed tracked.json and fixed endpoints
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests, fmt.Errorf("GET %s: status %s", url, resp.Status)
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, true, err
	}

	if int64(len(body)) > maxBytes {
		return nil, false, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxBytes)
	}

	return body, false, nil
}

type ianaRegistry struct {
	ID       string         `xml:"id,attr"`
	Records  []ianaRecord   `xml:"record"`
	Children []ianaRegistry `xml:"registry"`
}

type ianaRecord struct {
	Value        string    `xml:"value"`
	Name         string    `xml:"name"`
	Description  string    `xml:"description"`
	Usage        string    `xml:"usage"`
	Requirements string    `xml:"requirements"`
	Xrefs        []ianaRef `xml:"xref"`
	Reference    string    `xml:"reference"`
}

type ianaRef struct {
	Type    string `xml:"type,attr"`
	Data    string `xml:"data,attr"`
	Section string `xml:"section,attr"`
}

// parseIANA normalizes an IANA registry file into sub-registry -> key ->
// record. Records sharing a value are keyed "value|usage".
func parseIANA(raw []byte, only []string) (map[string]map[string]Record, error) {
	var root ianaRegistry
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}

	if len(root.Children) == 0 {
		return nil, errors.New("no sub-registries found")
	}

	out := map[string]map[string]Record{}

	for _, reg := range root.Children {
		if len(only) > 0 && !slices.Contains(only, reg.ID) {
			continue
		}

		count := map[string]int{}
		for _, r := range reg.Records {
			count[recordValue(r)]++
		}

		recs := map[string]Record{}

		for _, r := range reg.Records {
			key := recordValue(r)
			if count[key] > 1 {
				key += "|" + strings.TrimSpace(r.Usage)
			}

			for n, base := 2, key; ; n++ {
				if _, dup := recs[key]; !dup {
					break
				}

				key = fmt.Sprintf("%s#%d", base, n)
			}

			refs := []string{}

			for _, x := range r.Xrefs {
				if x.Type == "person" {
					continue
				}

				ref := x.Data
				if x.Section != "" {
					ref += "#" + x.Section
				}

				refs = append(refs, ref)
			}

			if t := collapse(r.Reference); t != "" {
				refs = append(refs, t)
			}

			recs[key] = Record{
				Description:  collapse(r.Description),
				Usage:        collapse(r.Usage),
				Requirements: collapse(r.Requirements),
				References:   sorted(refs),
			}
		}

		out[reg.ID] = recs
	}

	return out, nil
}

func recordValue(r ianaRecord) string {
	if v := collapse(r.Value); v != "" {
		return v
	}

	return collapse(r.Name)
}

func parseDraft(raw []byte) (Draft, error) {
	var doc struct {
		Title          string          `json:"title"`
		Rev            string          `json:"rev"`
		State          string          `json:"state"`
		IESGState      string          `json:"iesg_state"`
		RFCEditorState *string         `json:"rfceditor_state"`
		StdLevel       *string         `json:"std_level"`
		RFC            json.RawMessage `json:"rfc"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Draft{}, err
	}

	if doc.Rev == "" {
		return Draft{}, errors.New("document has no rev")
	}

	d := Draft{Title: doc.Title, Rev: doc.Rev, State: doc.State, IESGState: doc.IESGState}
	if doc.RFCEditorState != nil {
		d.RFCEditorState = *doc.RFCEditorState
	}

	if doc.StdLevel != nil {
		d.StdLevel = *doc.StdLevel
	}

	if rfc := strings.Trim(string(doc.RFC), `" `); rfc != "" && rfc != "null" {
		if !strings.HasPrefix(rfc, "RFC") {
			rfc = "RFC" + rfc
		}

		d.RFC = rfc
	}

	return d, nil
}

var spaces = regexp.MustCompile(`\s+`)

func collapse(s string) string { return strings.TrimSpace(spaces.ReplaceAllString(s, " ")) }

// hashPage fingerprints a page, ignoring whitespace-only differences.
func hashPage(raw []byte) string {
	sum := sha256.Sum256([]byte(collapse(string(raw))))
	return hex.EncodeToString(sum[:])
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)

	return out
}

// KeepFrom copies the baseline value of every source that failed, so a fetch
// failure is reported as such and never as a removal.
func (s *Snapshot) KeepFrom(base Snapshot, errs []error) {
	for _, err := range errs {
		var se *SourceError
		if !errors.As(err, &se) {
			continue
		}

		switch se.kind {
		case "rfc":
			if v, ok := base.RFCs[se.key]; ok {
				s.RFCs[se.key] = v
			}
		case "errata":
			maps.Copy(s.Errata, base.Errata)
		case "iana":
			for id, recs := range base.Registries {
				if strings.HasPrefix(id, se.key+"/") {
					s.Registries[id] = recs
				}
			}
		case "draft":
			if v, ok := base.Drafts[se.key]; ok {
				s.Drafts[se.key] = v
			}
		case "page":
			if v, ok := base.Pages[se.key]; ok {
				s.Pages[se.key] = v
			}
		}
	}
}
