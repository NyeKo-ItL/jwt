// Command standardswatch compares the current state of the standards this
// library implements — RFC status and errata, IANA JOSE/JWT registries,
// IETF drafts and OpenID specification pages — with a committed baseline and
// writes a Markdown report of the differences. The scheduled
// standards-watch workflow turns that report into a GitHub issue.
//
// Usage (from .github/standards):
//
//	go run .                 # check: write report.md, set changed=true|false in $GITHUB_OUTPUT
//	go run . -accept         # triage done: store the current state as baseline.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"
)

type runOptions struct {
	config, baseline, report, snapshot, githubOutput string
	accept                                           bool
	endpoints                                        Endpoints
	client                                           *http.Client
	date                                             string
}

func main() {
	opts := runOptions{
		endpoints:    DefaultEndpoints(),
		client:       &http.Client{Timeout: 90 * time.Second},
		githubOutput: os.Getenv("GITHUB_OUTPUT"),
		date:         time.Now().UTC().Format(time.DateOnly),
	}

	flag.StringVar(&opts.config, "config", "tracked.json", "what to watch")
	flag.StringVar(&opts.baseline, "baseline", "baseline.json", "last accepted state")
	flag.StringVar(&opts.report, "report", "report.md", "Markdown report to write")
	flag.StringVar(&opts.snapshot, "snapshot", "", "optionally write the current state here")
	flag.BoolVar(&opts.accept, "accept", false, "store the current state as the baseline")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "standardswatch:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts runOptions) error {
	cfg, err := LoadConfig(opts.config)
	if err != nil {
		return err
	}

	base := newSnapshot()

	if raw, err := os.ReadFile(opts.baseline); err == nil {
		if err := json.Unmarshal(raw, &base); err != nil {
			return fmt.Errorf("%s: %w", opts.baseline, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	cur, errs := Collect(ctx, opts.client, cfg, opts.endpoints)
	cur.KeepFrom(base, errs)

	for _, e := range errs {
		fmt.Printf("::warning title=standards watch::%s\n", e)
	}

	if opts.snapshot != "" {
		if err := writeJSON(opts.snapshot, cur); err != nil {
			return err
		}
	}

	if opts.accept {
		if len(errs) > 0 {
			return fmt.Errorf("refusing to accept a partial snapshot (%d sources failed)", len(errs))
		}

		fmt.Println("baseline updated:", opts.baseline)

		return writeJSON(opts.baseline, cur)
	}

	changes := Diff(base, cur, cfg)
	fmt.Printf("%d change(s), %d fetch failure(s)\n", len(changes), len(errs))

	if err := os.WriteFile(opts.report, []byte(Report(changes, errs, opts.date)), 0o600); err != nil {
		return err
	}

	if opts.githubOutput != "" {
		f, err := os.OpenFile(opts.githubOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(f, "changed=%t\n", len(changes) > 0)
		if cerr := f.Close(); err == nil {
			err = cerr
		}

		return err
	}

	return nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
