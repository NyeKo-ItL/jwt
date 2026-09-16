package main

import (
	"fmt"
	"slices"
	"strings"
)

// Section headings, in report order.
const (
	sectionRFC      = "RFC status"
	sectionErrata   = "Errata"
	sectionRegistry = "IANA registries"
	sectionDrafts   = "Drafts"
	sectionPages    = "Pages"
)

var sectionOrder = []string{sectionRFC, sectionErrata, sectionRegistry, sectionDrafts, sectionPages}

// Change is one difference between the baseline and the current snapshot.
type Change struct {
	Section string
	Summary string
	Link    string
	Impact  string
}

// Diff lists every difference from base to cur, in a stable order.
func Diff(base, cur Snapshot, cfg Config) []Change {
	var out []Change

	add := func(section, subject, summary, link string) {
		out = append(out, Change{Section: section, Summary: summary, Link: link, Impact: impactFor(cfg, subject)})
	}

	for _, id := range unionKeys(base.RFCs, cur.RFCs) {
		b, inBase := base.RFCs[id]
		c, inCur := cur.RFCs[id]
		link := "https://www.rfc-editor.org/info/" + strings.ToLower(id)

		switch {
		case !inCur:
			add(sectionRFC, id, id+": no longer tracked", link)
		case !inBase:
			add(sectionRFC, id, fmt.Sprintf("%s: added to tracking (%s)", id, c.Status), link)
		default:
			if b.Status != c.Status {
				add(sectionRFC, id, fmt.Sprintf("%s status %s → %s", id, b.Status, c.Status), link)
			}

			for _, n := range added(b.UpdatedBy, c.UpdatedBy) {
				add(sectionRFC, id, fmt.Sprintf("%s is updated by %s", id, n), link)
			}

			for _, n := range added(b.ObsoletedBy, c.ObsoletedBy) {
				add(sectionRFC, id, fmt.Sprintf("%s is obsoleted by %s", id, n), link)
			}
		}
	}

	for _, doc := range unionKeys(base.Errata, cur.Errata) {
		b, c := base.Errata[doc], cur.Errata[doc]
		for _, eid := range unionKeys(b, c) {
			be, inBase := b[eid]
			ce, inCur := c[eid]
			link := "https://www.rfc-editor.org/errata/eid" + eid

			switch {
			case !inCur:
				add(sectionErrata, doc, fmt.Sprintf("%s erratum %s: removed", doc, eid), link)
			case !inBase:
				add(sectionErrata, doc, fmt.Sprintf("%s erratum %s (%s, §%s): new, %s", doc, eid, ce.Type, ce.Section, ce.Status), link)
			case be.Status != ce.Status:
				add(sectionErrata, doc, fmt.Sprintf("%s erratum %s: %s → %s", doc, eid, be.Status, ce.Status), link)
			}
		}
	}

	for _, reg := range unionKeys(base.Registries, cur.Registries) {
		b, c := base.Registries[reg], cur.Registries[reg]
		file, id, _ := strings.Cut(reg, "/")
		link := fmt.Sprintf("https://www.iana.org/assignments/%s/%s.xhtml#%s", file, file, id)

		for _, key := range unionKeys(b, c) {
			br, inBase := b[key]
			cr, inCur := c[key]

			switch {
			case !inCur:
				add(sectionRegistry, reg, fmt.Sprintf("%s %s: removed", reg, key), link)
			case !inBase:
				add(sectionRegistry, reg, fmt.Sprintf("%s %s: registered", reg, key), link)
			default:
				var parts []string

				parts = appendIfChanged(parts, "requirements", br.Requirements, cr.Requirements)
				parts = appendIfChanged(parts, "usage", br.Usage, cr.Usage)
				parts = appendIfChanged(parts, "description", br.Description, cr.Description)
				parts = appendIfChanged(parts, "references", strings.Join(br.References, " "), strings.Join(cr.References, " "))

				if len(parts) > 0 {
					add(sectionRegistry, reg, fmt.Sprintf("%s %s: %s", reg, key, strings.Join(parts, "; ")), link)
				}
			}
		}
	}

	for _, name := range unionKeys(base.Drafts, cur.Drafts) {
		b, inBase := base.Drafts[name]
		c, inCur := cur.Drafts[name]
		link := "https://datatracker.ietf.org/doc/" + name + "/"

		switch {
		case !inCur:
			add(sectionDrafts, name, name+": no longer tracked", link)
		case !inBase:
			add(sectionDrafts, name, fmt.Sprintf("%s: added to tracking (rev %s, %s)", name, c.Rev, orDash(c.IESGState)), link)
		default:
			var parts []string

			parts = appendIfChanged(parts, "rev", b.Rev, c.Rev)
			parts = appendIfChanged(parts, "state", b.State, c.State)
			parts = appendIfChanged(parts, "IESG", b.IESGState, c.IESGState)
			parts = appendIfChanged(parts, "RFC Editor", b.RFCEditorState, c.RFCEditorState)
			parts = appendIfChanged(parts, "level", b.StdLevel, c.StdLevel)

			if c.RFC != "" && c.RFC != b.RFC {
				parts = append(parts, "published as "+c.RFC)
			}

			if len(parts) > 0 {
				add(sectionDrafts, name, name+": "+strings.Join(parts, "; "), link)
			}
		}
	}

	for _, name := range unionKeys(base.Pages, cur.Pages) {
		b, inBase := base.Pages[name]
		c, inCur := cur.Pages[name]
		link := cfg.Pages[name]

		switch {
		case !inCur:
			add(sectionPages, name, name+": no longer tracked", link)
		case !inBase:
			add(sectionPages, name, name+": added to tracking", link)
		case b != c:
			add(sectionPages, name, name+": content changed", link)
		}
	}

	return out
}

// impactFor returns the hint of the longest configured prefix of subject.
func impactFor(cfg Config, subject string) string {
	best := ""

	for prefix := range cfg.Impact {
		if strings.HasPrefix(subject, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}

	return cfg.Impact[best]
}

func appendIfChanged(parts []string, label, before, after string) []string {
	if before == after {
		return parts
	}

	return append(parts, fmt.Sprintf("%s %s → %s", label, orDash(before), orDash(after)))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}

	return s
}

func added(before, after []string) []string {
	var out []string

	for _, v := range after {
		if !slices.Contains(before, v) {
			out = append(out, v)
		}
	}

	return out
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}

	var out []string

	for _, m := range []map[string]V{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}

	slices.Sort(out)

	return out
}

// Report renders the issue body.
func Report(changes []Change, fetchErrs []error, date string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Standards changes to review\n\n")
	fmt.Fprintf(&b, "Weekly standards watch, run on **%s**, compared with `.github/standards/baseline.json`.\n\n", date)

	if len(changes) == 0 {
		b.WriteString("No changes since the baseline.\n")
	}

	for _, section := range sectionOrder {
		var items []Change

		for _, c := range changes {
			if c.Section == section {
				items = append(items, c)
			}
		}

		if len(items) == 0 {
			continue
		}

		fmt.Fprintf(&b, "## %s\n\n", section)

		for _, c := range items {
			line := "- " + c.Summary
			if c.Link != "" {
				line += " — [source](" + c.Link + ")"
			}

			if c.Impact != "" {
				line += " · likely impact: `" + c.Impact + "`"
			}

			b.WriteString(line + "\n")
		}

		b.WriteString("\n")
	}

	if len(fetchErrs) > 0 {
		b.WriteString("## Fetch failures\n\nThese sources could not be checked; their baseline values were kept.\n\n")

		for _, err := range fetchErrs {
			b.WriteString("- " + err.Error() + "\n")
		}

		b.WriteString("\n")
	}

	if len(changes) > 0 {
		b.WriteString(`## Triage

1. For each item, decide whether the library, ` + "`COMPLIANCE.md`" + ` or ` + "`SECURITY.md`" + ` needs a change, and open a PR (tests first) or note why not.
2. Accept the new state so the next run starts from it:

   ` + "```sh" + `
   cd .github/standards && go run . -accept
   ` + "```" + `

3. Commit the updated ` + "`baseline.json`" + ` in a PR that closes this issue.
`)
	}

	return b.String()
}
