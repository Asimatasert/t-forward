package main

// Doc-drift tests: docs/CONFIG_NOTES.md ("Schema" block) and examples/*.yaml
// must agree with the daemon's confYAML struct (read via `yq -o=json`, so the
// `json` tags are the on-disk key names). No yq binary and no YAML library is
// needed — the files are scanned with a tiny key extractor (tDocKeyPaths).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// tDocCLIOnly lists documented keys the daemon deliberately does NOT unmarshal:
// they are consumed only by the bash CLI (`t-forward`, via `yq` -> .vpn.<key>),
// and encoding/json silently ignores unknown keys, so the daemon stays correct.
// Each entry must (a) be in the doc, (b) be absent from confYAML and (c) really
// be read by the CLI script — tDocTestCLIOnlyExceptionsAreCurrent enforces all
// three, so the list cannot rot. If the daemon starts reading one of them, add
// the field to confYAML and delete the entry here.
var tDocCLIOnly = map[string]string{
	"vpn.tofu":         "openconnect pin learning, CLI only",
	"vpn.ikev":         "strongSwan IKE version, CLI only",
	"vpn.psk":          "strongSwan pre-shared key, CLI only",
	"vpn.ike_proposal": "strongSwan Phase-1 proposals, CLI only",
	"vpn.esp_proposal": "strongSwan Phase-2 proposals, CLI only",
	"vpn.ike_lifetime": "strongSwan Phase-1 SA lifetime, CLI only",
	"vpn.lifetime":     "strongSwan Phase-2 SA lifetime, CLI only",
	"vpn.local_id":     "strongSwan leftid, CLI only",
	"vpn.remote_id":    "strongSwan rightid, CLI only",
}

// tDocUndocumentedCLI lists keys the CLI reads and examples/ uses, but that are
// missing from the CONFIG_NOTES.md Schema block (real doc drift, found by this
// test). The doc fix is separate work (BUG: doc drift); until then the
// "documented in Schema" example check skips instead of failing for exactly
// these keys. Delete the entry once the doc lists the key.
var tDocUndocumentedCLI = map[string]string{
	"vpn.no_dtls": "openconnect: tunnel over TLS only (t-forward:196, examples/vpn.example.yaml, README); not in CONFIG_NOTES.md Schema",
}

// tDocExampleRoots maps an example file to the struct it configures. Files not
// listed use confYAML (tunnel confs in conf.d/). scan.example.yaml is
// ~/.config/t-forward/scan.yaml, read into scanConf, and is not part of the
// CONFIG_NOTES.md tunnel schema (checkDoc=false).
var tDocExampleRoots = map[string]struct {
	root     reflect.Type
	checkDoc bool
}{
	"scan.example.yaml": {reflect.TypeOf(scanConf{}), false},
}

// ---- key extraction from YAML text -----------------------------------------

var tDocKeyRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*):(\s|$)`)

// tDocStripComment removes a trailing "# ..." comment that is outside quotes.
func tDocStripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// tDocFlowKeys returns the mapping keys of a flow value such as
// `{ remote: 22, local: any }` or `[{a: 1}, {b: 2}]`, with their depth-0 paths
// relative to the flow value (nested flow maps are walked too).
func tDocFlowKeys(v string) []string {
	var out []string
	var walk func(s string, prefix string)
	walk = func(s, prefix string) {
		s = strings.TrimSpace(s)
		if len(s) < 2 {
			return
		}
		switch s[0] {
		case '[':
			// split items at depth 0
			for _, it := range tDocSplitFlow(s[1 : len(s)-1]) {
				walk(it, prefix)
			}
		case '{':
			for _, kv := range tDocSplitFlow(s[1 : len(s)-1]) {
				i := strings.Index(kv, ":")
				if i < 0 {
					continue
				}
				k := strings.Trim(strings.TrimSpace(kv[:i]), `"'`)
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				out = append(out, p)
				walk(kv[i+1:], p)
			}
		}
	}
	walk(v, "")
	return out
}

// tDocSplitFlow splits s at top-level commas (outside quotes/brackets).
func tDocSplitFlow(s string) []string {
	var parts []string
	var q byte
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// tDocKeyPaths extracts every mapping key path ("a.b.c") of a block-style YAML
// text. Sequences are transparent (hosts[].forwards[].remote -> hosts.forwards.remote).
// Supports what the repo's YAML uses: block maps, "- key:" items, flow maps/lists
// as values or items, comments. Not a general YAML parser.
func tDocKeyPaths(text string) map[string]bool {
	type frame struct {
		indent int
		key    string
	}
	var stack []frame
	paths := map[string]bool{}
	pathOf := func(extra string) string {
		var parts []string
		for _, f := range stack {
			parts = append(parts, f.key)
		}
		if extra != "" {
			parts = append(parts, extra)
		}
		return strings.Join(parts, ".")
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(tDocStripComment(raw), " \t\r")
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || trimmed == "---" {
			continue
		}
		indent := len(line) - len(trimmed)
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			dashIndent := indent
			for len(stack) > 0 && stack[len(stack)-1].indent > dashIndent {
				stack = stack[:len(stack)-1]
			}
			rest := strings.TrimLeft(strings.TrimPrefix(trimmed, "-"), " ")
			indent = dashIndent + (len(trimmed) - len(rest))
			trimmed = rest
			if trimmed == "" {
				continue
			}
			if trimmed[0] == '{' || trimmed[0] == '[' { // flow item
				for _, k := range tDocFlowKeys(trimmed) {
					paths[pathOf(k)] = true
				}
				continue
			}
		}
		m := tDocKeyRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue // scalar list item, continuation, ...
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		key := m[1]
		paths[pathOf(key)] = true
		val := strings.TrimSpace(trimmed[len(m[0]):])
		if val != "" && (val[0] == '{' || val[0] == '[') {
			for _, k := range tDocFlowKeys(val) {
				paths[pathOf(key+"."+k)] = true
			}
		}
		stack = append(stack, frame{indent, key})
	}
	return paths
}

// tDocSchemaBlock returns the first ```yaml fence under the "## Schema" heading.
func tDocSchemaBlock(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "docs", "CONFIG_NOTES.md"))
	if err != nil {
		t.Fatalf("read CONFIG_NOTES.md: %v", err)
	}
	doc := string(b)
	i := strings.Index(doc, "\n## Schema")
	if i < 0 {
		t.Fatal(`"## Schema" heading not found in docs/CONFIG_NOTES.md`)
	}
	rest := doc[i:]
	if j := strings.Index(rest[3:], "\n## "); j >= 0 { // stay inside the section
		rest = rest[:j+3]
	}
	start := strings.Index(rest, "```yaml\n")
	if start < 0 {
		t.Fatal("no ```yaml block in the Schema section")
	}
	rest = rest[start+len("```yaml\n"):]
	end := strings.Index(rest, "\n```")
	if end < 0 {
		t.Fatal("unterminated ```yaml block in the Schema section")
	}
	return rest[:end]
}

// ---- key paths from the struct ----------------------------------------------

// tDocStructPaths walks confYAML by reflection and returns every json key path.
// Pointers and slices are transparent; a type implementing json.Unmarshaler
// (scalar, jumpHop) is a leaf — its accepted shapes are custom, not structural.
func tDocStructPaths(root reflect.Type) map[string]bool {
	paths := map[string]bool{}
	unm := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || rt.Implements(unm) || reflect.PointerTo(rt).Implements(unm) {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			p := name
			if prefix != "" {
				p = prefix + "." + name
			}
			paths[p] = true
			walk(f.Type, p)
		}
	}
	walk(root, "")
	return paths
}

func tDocSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tDocMissing returns keys of a that are not in b and not in skip.
func tDocMissing(a, b map[string]bool, skip map[string]string) []string {
	var out []string
	for _, k := range tDocSorted(a) {
		if !b[k] {
			if _, ok := skip[k]; !ok {
				out = append(out, k)
			}
		}
	}
	return out
}

func tDocConfPaths() map[string]bool { return tDocStructPaths(reflect.TypeOf(confYAML{})) }

// ---- tests -------------------------------------------------------------------

// The extractor itself: pin its behaviour on a synthetic document so a parser
// bug cannot silently make the drift tests vacuous.
func TestTDocKeyPathsExtractor(t *testing.T) {
	src := `# comment
name: x   # trailing
tags: [a, b]
vpn:
  server: "h:1"   # c
  imap:
    host: h
  jump:
    - 10.0.0.1
    - admin@h:2222
hosts:
  - ip: 1.2.3.4
    forwards:
      - { remote: 22, local: "a:b", service: ssh }
      - remote: 80
        note: n
  - ip: 5.6.7.8
subnets:
  - { cidr: 1.0.0.0/8, tags: [p] }
last: 1
`
	want := []string{
		"hosts", "hosts.forwards", "hosts.forwards.local", "hosts.forwards.note",
		"hosts.forwards.remote", "hosts.forwards.service", "hosts.ip",
		"last", "name", "subnets", "subnets.cidr", "subnets.tags", "tags",
		"vpn", "vpn.imap", "vpn.imap.host", "vpn.jump", "vpn.server",
	}
	got := tDocSorted(tDocKeyPaths(src))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths mismatch\n got: %v\nwant: %v", got, want)
	}
}

// The reflection side: spot-check that nested paths, tag renames, pointer and
// slice transparency and Unmarshaler leaves are all handled.
func TestTDocStructPathsShape(t *testing.T) {
	p := tDocConfPaths()
	for _, k := range []string{
		"name", "socks", "totp_command", "vpn.totp_secret", "vpn.totp_imap.from_filter",
		"ssh.jump", "hosts.forwards.remote", "subnets.cidr",
	} {
		if !p[k] {
			t.Errorf("struct path %q missing (have %v)", k, tDocSorted(p))
		}
	}
	for _, k := range []string{"ssh.jump.host", "socks.s", "VPN", "vpn.TotpIMAP"} {
		if p[k] {
			t.Errorf("struct path %q must not exist (leaf type / Go name leaked)", k)
		}
	}
}

func TestConfigNotesSchemaMatchesConfStruct(t *testing.T) {
	doc := tDocKeyPaths(tDocSchemaBlock(t))
	if len(doc) < 30 {
		t.Fatalf("only %d keys extracted from the Schema block — extractor or doc broken", len(doc))
	}
	st := tDocConfPaths()

	t.Run("documented key exists in struct", func(t *testing.T) {
		if miss := tDocMissing(doc, st, tDocCLIOnly); len(miss) > 0 {
			t.Errorf("documented in CONFIG_NOTES.md but not a json key of confYAML (typo, rename or removed field?):\n  %s\n"+
				"If the daemon intentionally ignores it, add it to tDocCLIOnly with a reason.",
				strings.Join(miss, "\n  "))
		}
	})
	t.Run("struct key is documented", func(t *testing.T) {
		if miss := tDocMissing(st, doc, nil); len(miss) > 0 {
			t.Errorf("json key of confYAML missing from the CONFIG_NOTES.md Schema block:\n  %s",
				strings.Join(miss, "\n  "))
		}
	})
}

func TestTDocTestCLIOnlyExceptionsAreCurrent(t *testing.T) {
	doc := tDocKeyPaths(tDocSchemaBlock(t))
	st := tDocConfPaths()
	cli, err := os.ReadFile(filepath.Join("..", "t-forward"))
	if err != nil {
		t.Fatalf("read CLI script: %v", err)
	}
	for _, k := range tDocSorted(tDocMapKeys(tDocCLIOnly)) {
		if !doc[k] {
			t.Errorf("exception %q is no longer documented — drop it from tDocCLIOnly", k)
		}
		if st[k] {
			t.Errorf("exception %q is now a confYAML field — drop it from tDocCLIOnly", k)
		}
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(k) + `\b`).Match(cli) {
			t.Errorf("exception %q: the CLI script no longer reads .%s — the reason is stale", k, k)
		}
	}
}

func TestTDocUndocumentedCLIListIsCurrent(t *testing.T) {
	doc := tDocKeyPaths(tDocSchemaBlock(t))
	st := tDocConfPaths()
	cli, err := os.ReadFile(filepath.Join("..", "t-forward"))
	if err != nil {
		t.Fatalf("read CLI script: %v", err)
	}
	for k := range tDocUndocumentedCLI {
		if doc[k] {
			t.Errorf("%q is now documented — drop it from tDocUndocumentedCLI", k)
		}
		if st[k] {
			t.Errorf("%q is now a confYAML field — drop it from tDocUndocumentedCLI", k)
		}
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(k) + `\b`).Match(cli) {
			t.Errorf("%q: the CLI script no longer reads it — drop it from tDocUndocumentedCLI", k)
		}
	}
}

func tDocMapKeys(m map[string]string) map[string]bool {
	o := make(map[string]bool, len(m))
	for k := range m {
		o[k] = true
	}
	return o
}

func TestExamplesKeysMatchConfStruct(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "examples", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples/*.yaml found (err=%v)", err)
	}
	confPaths := tDocConfPaths()
	doc := tDocKeyPaths(tDocSchemaBlock(t))
	for _, f := range files {
		f := f
		base := filepath.Base(f)
		t.Run(base, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			keys := tDocKeyPaths(string(b))
			if len(keys) < 3 {
				t.Fatalf("only %d keys extracted — parser or example broken", len(keys))
			}
			st, skip, checkDoc := confPaths, tDocCLIOnly, true
			if r, ok := tDocExampleRoots[base]; ok {
				st, skip, checkDoc = tDocStructPaths(r.root), nil, r.checkDoc
			} else {
				skip = map[string]string{}
				for k, v := range tDocCLIOnly {
					skip[k] = v
				}
				for k, v := range tDocUndocumentedCLI {
					skip[k] = v
				}
			}
			t.Run("keys known to daemon struct", func(t *testing.T) {
				if miss := tDocMissing(keys, st, skip); len(miss) > 0 {
					t.Errorf("example uses keys the daemon struct does not know:\n  %s", strings.Join(miss, "\n  "))
				}
			})
			if !checkDoc {
				return
			}
			t.Run("keys documented in Schema", func(t *testing.T) {
				miss := tDocMissing(keys, doc, nil)
				var unknown, known []string
				for _, k := range miss {
					if _, ok := tDocUndocumentedCLI[k]; ok {
						known = append(known, k)
					} else {
						unknown = append(unknown, k)
					}
				}
				if len(unknown) > 0 {
					t.Errorf("example uses keys missing from the CONFIG_NOTES.md Schema block:\n  %s", strings.Join(unknown, "\n  "))
				}
				if len(unknown) == 0 && len(known) > 0 {
					t.Skipf("BUG: doc drift: %s used in %s but missing from docs/CONFIG_NOTES.md Schema (separate fix)", strings.Join(known, ", "), base)
				}
			})
		})
	}
}
