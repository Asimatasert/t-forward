package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

func strsp(s ...string) *[]string { return &s }

func TestValidateEditOK(t *testing.T) {
	cases := []struct {
		name string
		e    confEdit
	}{
		{"empty edit", confEdit{}},
		{"name", confEdit{Name: strp("Office VPN")}},
		{"empty name", confEdit{Name: strp("")}},
		{"tags", confEdit{Tags: strsp("db", "prod", "eu-1")}},
		{"empty tag list", confEdit{Tags: strsp()}},
		{"host note and tags", confEdit{Hosts: map[string]hostEdit{"10.0.0.5": {Note: strp("Production DB"), Tags: strsp("db")}}}},
		{"forward note", confEdit{Forwards: map[string]string{"10.0.0.5:5432": "primary"}}},
		{"forward with empty note", confEdit{Forwards: map[string]string{"10.0.0.5:22": ""}}},
		{"subnet", confEdit{Subnets: map[string]hostEdit{"10.0.0.0/16": {Note: strp("office LAN"), Tags: strsp("dmz")}}}},
		{"everything", confEdit{
			Name:     strp("n"),
			Tags:     strsp("a"),
			Hosts:    map[string]hostEdit{"1.2.3.4": {Note: strp("h")}},
			Forwards: map[string]string{"1.2.3.4:80": "x"},
			Subnets:  map[string]hostEdit{"192.168.0.0/24": {Tags: strsp("lan")}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := validateEdit(c.e); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateEditRejects(t *testing.T) {
	cases := []struct {
		name    string
		e       confEdit
		wantErr string
	}{
		{"name LF", confEdit{Name: strp("a\nb")}, "name must be one line"},
		{"name CR", confEdit{Name: strp("a\rb")}, "name must be one line"},
		{"tag with space", confEdit{Tags: strsp("ok", "not ok")}, "tag has an illegal character"},
		{"tag with tab", confEdit{Tags: strsp("a\tb")}, "tag has an illegal character"},
		{"tag with newline", confEdit{Tags: strsp("a\nb")}, "tag has an illegal character"},
		{"host note LF", confEdit{Hosts: map[string]hostEdit{"1.2.3.4": {Note: strp("a\nb")}}}, "host note must be one line"},
		{"host tag with space", confEdit{Hosts: map[string]hostEdit{"1.2.3.4": {Tags: strsp("a b")}}}, "host tag has an illegal character"},
		{"forward key without colon", confEdit{Forwards: map[string]string{"10.0.0.5": "x"}}, "forward key must be ip:port"},
		{"forward key without ip", confEdit{Forwards: map[string]string{":80": "x"}}, "forward key must be ip:port"},
		{"forward key without port", confEdit{Forwards: map[string]string{"10.0.0.5:": "x"}}, "forward key must be ip:port"},
		{"forward key with text port", confEdit{Forwards: map[string]string{"10.0.0.5:http": "x"}}, "forward key must be ip:port"},
		{"forward key with extra colon", confEdit{Forwards: map[string]string{"10.0.0.5:80:90": "x"}}, "forward key must be ip:port"},
		{"forward key with port expression", confEdit{Forwards: map[string]string{"10.0.0.5:80;id": "x"}}, "forward key must be ip:port"},
		{"forward note LF", confEdit{Forwards: map[string]string{"10.0.0.5:80": "a\nb"}}, "forward note must be one line"},
		{"subnet not a CIDR", confEdit{Subnets: map[string]hostEdit{"office": {}}}, "subnet key is not a CIDR"},
		{"subnet key with command substitution", confEdit{Subnets: map[string]hostEdit{"$(id)/8": {}}}, "subnet key is not a CIDR"},
		{"subnet label LF", confEdit{Subnets: map[string]hostEdit{"10.0.0.0/8": {Note: strp("a\nb")}}}, "subnet label must be one line"},
		{"subnet tag with space", confEdit{Subnets: map[string]hostEdit{"10.0.0.0/8": {Tags: strsp("a b")}}}, "subnet tag has an illegal character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateEdit(c.e)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if err.Error() != c.wantErr {
				t.Fatalf("error = %q, want %q", err, c.wantErr)
			}
		})
	}
}

// Free text is deliberately NOT filtered for shell/yq metacharacters: values
// reach yq only through strenv(), so they are inert. This pins that contract —
// if someone starts building yq expressions from these values, review again.
func TestValidateEditAllowsMetacharactersInFreeText(t *testing.T) {
	nasty := `$(id); rm -rf / ../../etc "quoted" 'single' | .a = 1 `
	e := confEdit{
		Name:     strp(nasty),
		Hosts:    map[string]hostEdit{"10.0.0.5": {Note: strp(nasty)}},
		Forwards: map[string]string{"10.0.0.5:80": nasty},
		Subnets:  map[string]hostEdit{"10.0.0.0/8": {Note: strp(nasty)}},
		Tags:     strsp("a;b", "$(x)", "../x"),
	}
	if err := validateEdit(e); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The JSON pointer semantics are what decides whether a field is edited at all:
// absent/null = leave alone, [] = clear.
func TestConfEditJSONDecode(t *testing.T) {
	var e confEdit
	body := `{"name":"n","tags":[],"hosts":{"10.0.0.5":{"note":"x","tags":["a"]}},` +
		`"forwards":{"10.0.0.5:22":"ssh"},"subnets":{"10.0.0.0/8":{"note":"lan"}}}`
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatal(err)
	}
	if e.Name == nil || *e.Name != "n" {
		t.Fatalf("name = %v", e.Name)
	}
	if e.Tags == nil || len(*e.Tags) != 0 {
		t.Fatalf("tags: [] must decode to a non-nil empty list, got %v", e.Tags)
	}
	if h := e.Hosts["10.0.0.5"]; h.Note == nil || *h.Note != "x" || h.Tags == nil || (*h.Tags)[0] != "a" {
		t.Fatalf("host = %+v", h)
	}
	if e.Forwards["10.0.0.5:22"] != "ssh" {
		t.Fatalf("forwards = %v", e.Forwards)
	}
	if s := e.Subnets["10.0.0.0/8"]; s.Note == nil || *s.Note != "lan" || s.Tags != nil {
		t.Fatalf("subnet = %+v", s)
	}
	if err := validateEdit(e); err != nil {
		t.Fatalf("decoded edit should validate: %v", err)
	}

	var none confEdit
	if err := json.Unmarshal([]byte(`{"name":null,"tags":null}`), &none); err != nil {
		t.Fatal(err)
	}
	if none.Name != nil || none.Tags != nil {
		t.Fatalf("null must stay nil (no edit), got %v / %v", none.Name, none.Tags)
	}
}

func TestIsNumeric(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0", true},
		{"80", true},
		{"65535", true},
		{"007", true},
		{"-1", false},
		{"+80", false},
		{"", false},
		{" 1", false},
		{"1 ", false},
		{"1.5", false},
		{"1e3", false},
		{"abc", false},
		{"80;id", false},
		{"8 0", false},
		{"0x50", false},
		{"٣", false},                    // Arabic-Indic digit
		{"99999999999999999999", false}, // overflows int
		{"1\n", false},
	}
	for _, c := range cases {
		if got := isNumeric(c.in); got != c.want {
			t.Errorf("isNumeric(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A forward key is "ip:port"; a signed port is not a port.
func TestForwardKeyRejectsSignedPort(t *testing.T) {
	for _, port := range []string{"-1", "+80"} {
		e := confEdit{Forwards: map[string]string{"10.0.0.5:" + port: "x"}}
		if err := validateEdit(e); err == nil {
			t.Errorf("forward key with port %q was accepted", port)
		}
	}
}

func TestValidPort(t *testing.T) {
	for _, s := range []string{"1", "22", "80", "5432", "65535"} {
		if !validPort(s) {
			t.Errorf("validPort(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "0", "65536", "99999", "-1", "+80", "080", "007", " 80", "80 ", "8.0", "1e3", "٣", "99999999999999999999"} {
		if validPort(s) {
			t.Errorf("validPort(%q) = true, want false", s)
		}
	}
}

func TestValidCIDRKey(t *testing.T) {
	good := []string{"10.0.0.0/16", "192.168.1.0/24", "0.0.0.0/0", "10.8.0.5/32", "172.16.0.0/12"}
	for _, s := range good {
		if !validCIDRKey(s) {
			t.Errorf("validCIDRKey(%q) = false, want true", s)
		}
	}

	bad := []string{
		"",
		"10.0.0.0",       // no slash
		"10.0.0.0//16",   // two slashes
		"10.0.0.0/16/8",  // two slashes
		"10.0.0.0/16 ",   // trailing space
		" 10.0.0.0/16",   // leading space
		"10.0.0.0 /16",   // inner space
		"10.0.0.0/16\n",  // newline
		"10.0.0.0/16\r",  // CR
		"10.0.0.0/16\t",  // tab
		"10.0.0.0/16;id", // command separator
		"10.0.0.0/16&&id",
		"10.0.0.0/16|id",
		"$(id)/8",
		"`id`/8",
		"${HOME}/8",
		"10.0.0.0/16$(id)",
		"::1/128",         // IPv6 is out of scope (digits and dots only)
		"fe80::/10",       // ditto
		"10.0.0.0/16\x00", // NUL
		"１０.0.0.0/16",     // fullwidth digits
		"10.0.0.0/１６",
		"a.b.c.d/8",
		"-1.0.0.0/8",
		"10.0.0.0/-1",
		"10.0.0.0/8\"",
		"10.0.0.0/8'",
		"~/8",
		"*/8",
	}
	for _, s := range bad {
		if validCIDRKey(s) {
			t.Errorf("validCIDRKey(%q) = true, want false", s)
		}
	}
}

// Everything below is "CIDR-shaped" (digits, dots, one slash) but is not an
// IPv4 CIDR, so validCIDRKey must reject it.
func TestValidCIDRKeyRequiresRealCIDR(t *testing.T) {
	for _, s := range []string{"/", "../", "..", "./.", "1/2", "10.0.0.0/", "/16", "...../", "999.1.1.1/8", "10.0.0.0/33", "1.2.3/8", "10.0.0.0/099"} {
		if _, ipn, err := net.ParseCIDR(s); err == nil && ipn.IP.To4() != nil {
			t.Fatalf("test table error: %q is a valid IPv4 CIDR", s)
		}
		if validCIDRKey(s) {
			t.Errorf("validCIDRKey(%q) = true, but it is not an IPv4 CIDR", s)
		}
	}
}

func TestJSONArr(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"nil", nil, "[]"},
		{"empty", []string{}, "[]"},
		{"one", []string{"a"}, `["a"]`},
		{"several keep order", []string{"b", "a", "c"}, `["b","a","c"]`},
		{"quote escaped", []string{`a"b`}, `["a\"b"]`},
		{"backslash escaped", []string{`a\b`}, `["a\\b"]`},
		{"newline escaped", []string{"a\nb"}, `["a\nb"]`},
		{"empty string element", []string{""}, `[""]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := jsonArr(c.in); got != c.want {
				t.Fatalf("jsonArr(%q) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

// jsonArr output is fed to yq's fromjson, so it must always be valid JSON that
// decodes back to exactly the input, whatever the strings contain.
func TestJSONArrRoundTrip(t *testing.T) {
	in := []string{
		"plain", "", "with space", "$(id)", "`id`", "a;b", "../../etc/passwd",
		`quo"te`, `back\slash`, "new\nline", "tab\t", "ünïcode ✓", "<script>&", "\x00nul",
		strings.Repeat("x", 4096),
	}
	var out []string
	if err := json.Unmarshal([]byte(jsonArr(in)), &out); err != nil {
		t.Fatalf("jsonArr produced invalid JSON: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the value:\n in: %q\nout: %q", in, out)
	}
}

// ------------------------------------------------------------------ handleConf
//
// The reject paths and the "unknown fields are ignored" check need no yq: they
// stop before any `yq -i` runs. The edit tests further down skip without yq.

// sampleConf is a trimmed vpn.example.yaml with recognisable secrets, so the
// tests can prove the secrets survive every edit untouched.
const sampleConf = `name: Example VPN
type: vpn
tags: [example]

vpn:
  server: vpn.example.com:10443
  protocol: fortinet
  user: username1
  password: pw-secret-1
  psk: psk-secret-2
  servercert: pin-sha256:abc123
  totp_secret: JBSWY3DPEHPK3PXP

socks: 1080

hosts:
  - ip: 10.0.0.20
    name: app server
    tags: [db, web]
    forwards:
      - { remote: 22,   local: any,  service: ssh, user: root, note: admin access }
      - { remote: 80,   local: any }
      - { remote: 5432, local: any,  service: postgres, user: postgres }
  - ip: 10.0.0.21
    name: bastion
    forwards:
      - { remote: 22, local: 2205, service: ssh, user: username1 }

subnets:
  - { cidr: 10.0.0.0/16, label: office LAN, tags: [dmz] }
`

// secretLines are the sensitive conf lines that no edit may ever change.
var secretLines = []string{
	"  password: pw-secret-1\n",
	"  psk: psk-secret-2\n",
	"  servercert: pin-sha256:abc123\n",
	"  totp_secret: JBSWY3DPEHPK3PXP\n",
}

// newConfActions returns Actions over a real Docker (fake `docker` on PATH, see
// stubDocker) with one conf, "lab", holding content. handleConf ends in
// broadcastState, so a bare &Docker{} would panic on its nil hub.
func newConfActions(t *testing.T, content string) (a *Actions, confFile string) {
	t.Helper()
	stubDocker(t)
	d, root := newTestDocker(t)
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	confFile = filepath.Join(root, "conf.d", "lab.yaml")
	if err := os.WriteFile(confFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Actions{docker: d}, confFile
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func confReq(a *Actions, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	a.handleConf(rec, req)
	return rec
}

func errOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON: %q", rec.Body.String())
	}
	s, _ := m["error"].(string)
	return s
}

func TestHandleConfRejectsNonPOST(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		rec := confReq(a, m, "/conf/lab", `{"name":"x"}`)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, rec.Code)
		}
	}
	// the method check comes first: even an unknown conf is 405, not 404
	if rec := confReq(a, http.MethodGet, "/conf/nope", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unknown conf: status = %d, want 405", rec.Code)
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("conf changed by a rejected request:\n%s", got)
	}
}

func TestHandleConfRejectsBadName(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	for _, p := range []string{
		"/conf/",          // empty
		"/conf/../x",      // traversal
		"/conf/..",        // traversal
		"/conf/a..b",      // embedded ".."
		"/conf/a/b",       // path separator
		"/conf/-x",        // leading '-' would parse as a CLI flag
		"/conf/.hidden",   // leading dot
		"/conf/a%20b",     // space (raw, the handler does not unescape)
		"/conf/lab.yaml/", // trailing slash
		"/conf/a;id",
	} {
		rec := confReq(a, http.MethodPost, p, `{"name":"x"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", p, rec.Code)
			continue
		}
		if e := errOf(t, rec); e != "bad name" {
			t.Errorf("%s: error = %q, want \"bad name\"", p, e)
		}
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("conf changed by a rejected request:\n%s", got)
	}
}

func TestHandleConfUnknownConf404(t *testing.T) {
	a, _ := newConfActions(t, sampleConf)
	rec := confReq(a, http.MethodPost, "/conf/nope", `{"name":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if e := errOf(t, rec); e != "no such tunnel" {
		t.Errorf("error = %q", e)
	}
	// 404 must not create the file
	if _, err := os.Stat(confPath(a.docker.confDir, "nope")); err == nil {
		t.Error("handler created a conf for an unknown tunnel")
	}
}

func TestHandleConfBadJSON(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	for name, body := range map[string]string{
		"empty body":       "",
		"not json":         "name=x",
		"truncated":        `{"name":"x"`,
		"array":            `["name"]`,
		"wrong type name":  `{"name":5}`,
		"wrong type tags":  `{"tags":"a"}`,
		"wrong type hosts": `{"hosts":["10.0.0.20"]}`,
		"tag is not text":  `{"tags":[1]}`,
	} {
		rec := confReq(a, http.MethodPost, "/conf/lab", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, rec.Code, rec.Body.String())
			continue
		}
		if e := errOf(t, rec); e != "bad json" {
			t.Errorf("%s: error = %q, want \"bad json\"", name, e)
		}
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("conf changed by a rejected request:\n%s", got)
	}
}

// The body is read through a 64 KiB LimitReader, so an oversize document is cut
// mid-value and fails to decode: rejected as bad json, nothing written.
func TestHandleConfBodyOver64KiB(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	big := `{"name":"` + strings.Repeat("a", 64*1024+10) + `"}`
	rec := confReq(a, http.MethodPost, "/conf/lab", big)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := errOf(t, rec); e != "bad json" {
		t.Errorf("error = %q, want \"bad json\"", e)
	}
	// content hidden after the limit is never parsed
	big2 := `{"name":"` + strings.Repeat("b", 64*1024) + `","tags":["late"]}`
	_ = confReq(a, http.MethodPost, "/conf/lab", big2)
	if got := readFile(t, file); strings.Contains(got, "late") || got != sampleConf {
		t.Errorf("conf changed by an oversize request:\n%s", got)
	}
}

func TestHandleConfValidateRejects(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	cases := []struct {
		name, body, wantErr string
	}{
		{"name newline", `{"name":"a\nb"}`, "name must be one line"},
		{"name CR", `{"name":"a\rb"}`, "name must be one line"},
		{"tag space", `{"tags":["a b"]}`, "tag has an illegal character"},
		{"host note newline", `{"hosts":{"10.0.0.20":{"note":"a\nb"}}}`, "host note must be one line"},
		{"host tag space", `{"hosts":{"10.0.0.20":{"tags":["a b"]}}}`, "host tag has an illegal character"},
		{"forward key", `{"forwards":{"10.0.0.20":"x"}}`, "forward key must be ip:port"},
		{"forward port expr", `{"forwards":{"10.0.0.20:22;id":"x"}}`, "forward key must be ip:port"},
		{"forward note newline", `{"forwards":{"10.0.0.20:22":"a\nb"}}`, "forward note must be one line"},
		{"subnet key", `{"subnets":{"$(id)/8":{"note":"x"}}}`, "subnet key is not a CIDR"},
		{"subnet label newline", `{"subnets":{"10.0.0.0/8":{"note":"a\nb"}}}`, "subnet label must be one line"},
		{"subnet tag space", `{"subnets":{"10.0.0.0/8":{"tags":["a b"]}}}`, "subnet tag has an illegal character"},
		// one bad field vetoes the whole request: the good name must not land
		{"valid name plus bad tag", `{"name":"renamed","tags":["a b"]}`, "tag has an illegal character"},
	}
	for _, c := range cases {
		rec := confReq(a, http.MethodPost, "/conf/lab", c.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", c.name, rec.Code, rec.Body.String())
			continue
		}
		if e := errOf(t, rec); e != c.wantErr {
			t.Errorf("%s: error = %q, want %q", c.name, e, c.wantErr)
		}
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("conf changed by a rejected request:\n%s", got)
	}
}

// Only the confEdit whitelist is decoded. Sensitive keys (and anything else)
// sent in the JSON are ignored, so with no whitelisted field present no yq call
// happens and the conf stays byte-identical.
func TestHandleConfIgnoresNonWhitelistedKeys(t *testing.T) {
	a, file := newConfActions(t, sampleConf)
	body := `{
		"password": "pwned", "psk": "pwned", "totp_secret": "pwned", "servercert": "pwned",
		"vpn": {"password": "pwned", "psk": "pwned", "server": "evil.example.com:443"},
		"ssh": {"key": "pwned"}, "socks": 1, "type": "ssh", "restart": true,
		"hosts": {"10.0.0.20": {"password": "pwned", "ip": "6.6.6.6", "forwards": []}},
		"subnets": {"10.0.0.0/16": {"password": "pwned", "cidr": "6.6.6.0/24"}}
	}`
	rec := confReq(a, http.MethodPost, "/conf/lab", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("non-whitelisted JSON keys changed the conf:\n%s", got)
	}
	// and an empty object is a harmless no-op too
	if rec := confReq(a, http.MethodPost, "/conf/lab", `{}`); rec.Code != http.StatusOK {
		t.Errorf("empty edit: status = %d", rec.Code)
	}
	if got := readFile(t, file); got != sampleConf {
		t.Errorf("empty edit changed the conf:\n%s", got)
	}
}

// -------------------------------------------- yq-backed edits (skip without yq)

// yqJSON reads expr from the conf as compact JSON via yq.
func yqJSON(t *testing.T, file, expr string) string {
	t.Helper()
	out, err := exec.Command("yq", "-o=json", "-I=0", expr, file).CombinedOutput()
	if err != nil {
		t.Fatalf("yq %s: %v: %s", expr, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeConf(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lab.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertSecretsIntact(t *testing.T, file string) {
	t.Helper()
	got := readFile(t, file)
	for _, l := range secretLines {
		if !strings.Contains(got, "\n"+l) {
			t.Errorf("secret line %q missing or changed:\n%s", strings.TrimSpace(l), got)
		}
	}
	orig := writeConf(t, sampleConf)
	for _, key := range []string{".vpn", ".type", ".socks"} {
		if want, have := yqJSON(t, orig, key), yqJSON(t, file, key); want != have {
			t.Errorf("%s changed: %s -> %s", key, want, have)
		}
	}
}

func TestYqEditSetsAndFails(t *testing.T) {
	requireYq(t)
	f := writeConf(t, sampleConf)
	if err := yqEdit(f, `.name = strenv(VAL)`, env{"VAL": "Renamed"}); err != nil {
		t.Fatal(err)
	}
	if got := yqJSON(t, f, ".name"); got != `"Renamed"` {
		t.Errorf(".name = %s", got)
	}

	// a bad expression is reported with the "yq:" prefix and leaves the file alone
	before := readFile(t, f)
	err := yqEdit(f, `.name = (`, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "yq: ") {
		t.Errorf("bad expr: err = %v, want a \"yq: ...\" error", err)
	}
	if readFile(t, f) != before {
		t.Error("failed yq call modified the file")
	}

	// a missing file is an error, not a created file
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	if err := yqEdit(missing, `.a = 1`, nil); err == nil {
		t.Error("yqEdit on a missing file: expected an error")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("yqEdit created a missing file")
	}
}

func TestApplyEditsAllFields(t *testing.T) {
	requireYq(t)
	f := writeConf(t, sampleConf)
	err := applyEdits(f, confEdit{
		Name: strp("Prod VPN"),
		Tags: strsp("prod", "eu-1"),
		Hosts: map[string]hostEdit{
			"10.0.0.20": {Note: strp("db primary"), Tags: strsp("db")},
			"10.0.0.21": {Tags: strsp()}, // [] clears
		},
		Forwards: map[string]string{
			"10.0.0.20:22":   "ops access", // existing note replaced
			"10.0.0.20:80":   "web ui",     // note added to a forward without one
			"10.0.0.21:22":   "jump",
			"10.0.0.99:22":   "no such host", // unknown host: no-op
			"10.0.0.20:9999": "no such port", // unknown port: no-op
		},
		Subnets: map[string]hostEdit{
			"10.0.0.0/16":    {Note: strp("HQ")},                       // update label, keep tags
			"192.168.5.0/24": {Note: strp("lab"), Tags: strsp("test")}, // create
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for expr, want := range map[string]string{
		".name": `"Prod VPN"`,
		".tags": `["prod","eu-1"]`,
		`.hosts[] | select(.ip == "10.0.0.20") | .name`:                    `"db primary"`,
		`.hosts[] | select(.ip == "10.0.0.20") | .tags`:                    `["db"]`,
		`.hosts[] | select(.ip == "10.0.0.21") | .tags`:                    `[]`,
		`.hosts[] | select(.ip == "10.0.0.21") | .name`:                    `"bastion"`,
		`.hosts[0].forwards[] | select(.remote == 22) | .note`:             `"ops access"`,
		`.hosts[0].forwards[] | select(.remote == 22) | .service`:          `"ssh"`,
		`.hosts[0].forwards[] | select(.remote == 80) | .note`:             `"web ui"`,
		`.hosts[0].forwards[] | select(.remote == 5432) | has("note")`:     `false`,
		`.hosts[1].forwards[0].note`:                                       `"jump"`,
		`.subnets[] | select(.cidr == "10.0.0.0/16") | .label`:             `"HQ"`,
		`.subnets[] | select(.cidr == "10.0.0.0/16") | .tags`:              `["dmz"]`,
		`.subnets[] | select(.cidr == "192.168.5.0/24") | [.label, .tags]`: `["lab",["test"]]`,
		`.subnets | length`: `2`,
		`.hosts | length`:   `2`,
	} {
		if got := yqJSON(t, f, expr); got != want {
			t.Errorf("%s = %s, want %s", expr, got, want)
		}
	}
	assertSecretsIntact(t, f)
}

func TestApplyEditsEmptyEditLeavesFileAlone(t *testing.T) {
	requireYq(t)
	f := writeConf(t, sampleConf)
	if err := applyEdits(f, confEdit{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, f); got != sampleConf {
		t.Errorf("empty edit rewrote the file:\n%s", got)
	}
}

func TestApplyEditsStopsAtFirstError(t *testing.T) {
	requireYq(t)
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	if err := applyEdits(missing, confEdit{Name: strp("x"), Tags: strsp("a")}); err == nil ||
		!strings.HasPrefix(err.Error(), "yq: ") {
		t.Errorf("err = %v, want a yq error", err)
	}
}

func TestSubnetUpsert(t *testing.T) {
	requireYq(t)

	t.Run("update keeps the entry's other fields", func(t *testing.T) {
		f := writeConf(t, sampleConf)
		if err := subnetUpsert(f, "10.0.0.0/16", `"label": strenv(VAL)`, env{"C": "10.0.0.0/16", "VAL": "HQ"}); err != nil {
			t.Fatal(err)
		}
		if got := yqJSON(t, f, ".subnets"); got != `[{"cidr":"10.0.0.0/16","label":"HQ","tags":["dmz"]}]` {
			t.Errorf(".subnets = %s", got)
		}
	})

	t.Run("tags update keeps the label", func(t *testing.T) {
		f := writeConf(t, sampleConf)
		if err := subnetUpsert(f, "10.0.0.0/16", `"tags": (strenv(J)|fromjson)`, env{"C": "10.0.0.0/16", "J": `["a","b"]`}); err != nil {
			t.Fatal(err)
		}
		if got := yqJSON(t, f, ".subnets"); got != `[{"cidr":"10.0.0.0/16","label":"office LAN","tags":["a","b"]}]` {
			t.Errorf(".subnets = %s", got)
		}
	})

	t.Run("absent cidr is appended, others untouched", func(t *testing.T) {
		f := writeConf(t, sampleConf)
		if err := subnetUpsert(f, "172.16.0.0/12", `"label": strenv(VAL)`, env{"C": "172.16.0.0/12", "VAL": "dc"}); err != nil {
			t.Fatal(err)
		}
		want := `[{"cidr":"10.0.0.0/16","label":"office LAN","tags":["dmz"]},{"cidr":"172.16.0.0/12","label":"dc"}]`
		if got := yqJSON(t, f, ".subnets"); got != want {
			t.Errorf(".subnets = %s, want %s", got, want)
		}
	})

	t.Run("conf without a subnets key gets one", func(t *testing.T) {
		f := writeConf(t, "name: bare\ntype: local\n")
		if err := subnetUpsert(f, "10.9.0.0/16", `"label": strenv(VAL)`, env{"C": "10.9.0.0/16", "VAL": "x"}); err != nil {
			t.Fatal(err)
		}
		if got := yqJSON(t, f, ".subnets"); got != `[{"cidr":"10.9.0.0/16","label":"x"}]` {
			t.Errorf(".subnets = %s", got)
		}
		if got := yqJSON(t, f, ".name"); got != `"bare"` {
			t.Errorf(".name = %s", got)
		}
	})

	t.Run("repeated upsert does not duplicate", func(t *testing.T) {
		f := writeConf(t, sampleConf)
		for i := 0; i < 3; i++ {
			if err := subnetUpsert(f, "10.0.0.0/16", `"label": strenv(VAL)`, env{"C": "10.0.0.0/16", "VAL": "again"}); err != nil {
				t.Fatal(err)
			}
		}
		if got := yqJSON(t, f, ".subnets | length"); got != "1" {
			t.Errorf("subnets length = %s, want 1", got)
		}
	})
}

// The handler's claim: values reach yq through strenv()/fromjson, so no value
// can inject yq syntax. Each payload is written as a note/label/tag and must
// land in the file as that exact string, with every other key unchanged.
func TestApplyEditsValuesCannotInjectYq(t *testing.T) {
	requireYq(t)
	payloads := []string{
		`"; .password = "x"`,
		`"; .vpn.password = "x" | .name = "`,
		`$(id)`,
		"`id`",
		`| del(.)`,
		`) | del(.hosts) | (.name = "`,
		`\"; .vpn.psk = \"x`,
		`${HOME}`,
		`strenv(VAL)`,
		`'; touch /tmp/pwned #`,
		`# comment: x`,
		`- {a: b}`,
		`*anchor`,
		`{{ .x }}`,
		`é ü 🔥`,
		`true`,
		`null`,
		`0x10`,
		``,
	}
	// tags forbid whitespace, so give them the whitespace-free vectors only
	tagPayloads := []string{`$(id)`, `"|del(.)`, `"];.vpn.password="x`, `strenv(J)`, `!!str`, `true`, `null`}

	origOther := yqJSON(t, writeConf(t, sampleConf), `del(.name, .tags, .hosts, .subnets)`)
	origHost1 := yqJSON(t, writeConf(t, sampleConf), `.hosts[1]`)
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }

	for i, p := range payloads {
		f := writeConf(t, sampleConf)
		tag := tagPayloads[i%len(tagPayloads)]
		e := confEdit{
			Name:     strp(p),
			Tags:     strsp(tag),
			Hosts:    map[string]hostEdit{"10.0.0.20": {Note: strp(p), Tags: strsp(tag)}},
			Forwards: map[string]string{"10.0.0.20:22": p},
			Subnets:  map[string]hostEdit{"10.0.0.0/16": {Note: strp(p), Tags: strsp(tag)}},
		}
		if err := validateEdit(e); err != nil {
			t.Fatalf("payload %q rejected by validateEdit: %v", p, err)
		}
		if err := applyEdits(f, e); err != nil {
			t.Fatalf("payload %q: applyEdits: %v", p, err)
		}
		for expr, exp := range map[string]string{
			".name": quote(p),
			".tags": "[" + quote(tag) + "]",
			`.hosts[] | select(.ip == "10.0.0.20") | .name`:        quote(p),
			`.hosts[] | select(.ip == "10.0.0.20") | .tags`:        "[" + quote(tag) + "]",
			`.hosts[0].forwards[] | select(.remote == 22) | .note`: quote(p),
			`.subnets[] | select(.cidr == "10.0.0.0/16") | .label`: quote(p),
			`.subnets[] | select(.cidr == "10.0.0.0/16") | .tags`:  "[" + quote(tag) + "]",
		} {
			if got := yqJSON(t, f, expr); got != exp {
				t.Errorf("payload %q: %s = %s, want %s", p, expr, got, exp)
			}
		}
		if got := yqJSON(t, f, `del(.name, .tags, .hosts, .subnets)`); got != origOther {
			t.Errorf("payload %q changed other keys:\n got  %s\n want %s", p, got, origOther)
		}
		if got := yqJSON(t, f, `[.hosts[].ip]`); got != `["10.0.0.20","10.0.0.21"]` {
			t.Errorf("payload %q changed host ips: %s", p, got)
		}
		if got := yqJSON(t, f, `.hosts[1]`); got != origHost1 {
			t.Errorf("payload %q changed the other host: %s", p, got)
		}
		if got := yqJSON(t, f, `.subnets | length`); got != "1" {
			t.Errorf("payload %q changed the subnet count: %s", p, got)
		}
		assertSecretsIntact(t, f)
	}
}

// Keys are values too: an IP or remote-port key carrying yq syntax must match
// nothing (or fail to parse) instead of widening the selection.
func TestApplyEditsKeysCannotInjectYq(t *testing.T) {
	requireYq(t)

	t.Run("host ip is compared as a string", func(t *testing.T) {
		for _, ip := range []string{
			`10.0.0.20" or true or .ip == "`,
			`x") | .name = "pwned" | (.name`,
			`.`,
			``,
			`10.0.0.2`, // prefix of a real ip must not match
		} {
			f := writeConf(t, sampleConf)
			err := applyEdits(f, confEdit{
				Hosts:    map[string]hostEdit{ip: {Note: strp("pwned"), Tags: strsp("pwned")}},
				Forwards: map[string]string{ip + ":22": "pwned"},
			})
			if err != nil {
				t.Fatalf("ip %q: %v", ip, err)
			}
			if got := readFile(t, f); got != sampleConf {
				t.Errorf("ip %q modified the conf:\n%s", ip, got)
			}
		}
	})

	t.Run("forward port goes through fromjson, not into the expression", func(t *testing.T) {
		for _, rp := range []string{`22 or true`, `22; .vpn.password = "x"`, `"22"`, `null`, `[22]`, `abc`} {
			f := writeConf(t, sampleConf)
			// validateEdit would reject these keys; applyEdits is called
			// directly to prove the second line of defence. Some inputs parse
			// as JSON (null, "22") and some do not: either way nothing may be
			// written.
			_ = applyEdits(f, confEdit{Forwards: map[string]string{"10.0.0.20:" + rp: "pwned"}})
			if got := readFile(t, f); strings.Contains(got, "pwned") {
				t.Errorf("port %q wrote a note:\n%s", rp, got)
			}
			assertSecretsIntact(t, f)
		}
	})

	t.Run("subnet cidr is compared as a string", func(t *testing.T) {
		f := writeConf(t, sampleConf)
		cidr := `10.0.0.0/16" or true or .cidr == "`
		if err := applyEdits(f, confEdit{Subnets: map[string]hostEdit{cidr: {Note: strp("L")}}}); err != nil {
			t.Fatal(err)
		}
		// the existing real subnet is untouched; the odd key is only a new entry
		if got := yqJSON(t, f, `.subnets[] | select(.cidr == "10.0.0.0/16")`); got != `{"cidr":"10.0.0.0/16","label":"office LAN","tags":["dmz"]}` {
			t.Errorf("real subnet changed: %s", got)
		}
		assertSecretsIntact(t, f)
	})
}

// ---- end to end through the HTTP handler (yq required)

func TestHandleConfAppliesEdits(t *testing.T) {
	requireYq(t)
	a, file := newConfActions(t, sampleConf)
	body := `{
		"name": "Renamed",
		"tags": ["prod"],
		"hosts": {"10.0.0.20": {"note": "db", "tags": ["x"]}},
		"forwards": {"10.0.0.20:22": "ops"},
		"subnets": {"10.0.0.0/16": {"note": "HQ"}},
		"password": "pwned", "vpn": {"psk": "pwned"}
	}`
	rec := confReq(a, http.MethodPost, "/conf/lab", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok":true`)) {
		t.Errorf("body = %s", rec.Body.String())
	}
	if got := yqJSON(t, file, ".name"); got != `"Renamed"` {
		t.Errorf(".name = %s", got)
	}
	if got := yqJSON(t, file, `.hosts[0].forwards[0].note`); got != `"ops"` {
		t.Errorf("forward note = %s", got)
	}
	if got := yqJSON(t, file, `.subnets[0].label`); got != `"HQ"` {
		t.Errorf("subnet label = %s", got)
	}
	if got := readFile(t, file); strings.Contains(got, "pwned") {
		t.Errorf("non-whitelisted keys reached the conf:\n%s", got)
	}
	assertSecretsIntact(t, file)
}

// yq failing is a 500 with the yq message, not a panic or a 200.
func TestHandleConfYqFailureIs500(t *testing.T) {
	requireYq(t)
	a, file := newConfActions(t, "name: [unclosed\n")
	rec := confReq(a, http.MethodPost, "/conf/lab", `{"name":"x"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
	if e := errOf(t, rec); !strings.HasPrefix(e, "yq: ") {
		t.Errorf("error = %q, want a yq error", e)
	}
	if got := readFile(t, file); got != "name: [unclosed\n" {
		t.Errorf("broken conf was rewritten: %q", got)
	}
}
