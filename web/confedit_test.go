package main

import (
	"encoding/json"
	"net"
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

// A forward key is "ip:port"; a signed port is not a port. isNumeric uses
// strconv.Atoi, which accepts a sign.
func TestForwardKeyRejectsSignedPort(t *testing.T) {
	for _, port := range []string{"-1", "+80"} {
		e := confEdit{Forwards: map[string]string{"10.0.0.5:" + port: "x"}}
		if err := validateEdit(e); err == nil {
			t.Errorf("forward key with port %q was accepted", port)
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

// validCIDRKey only checks the characters (digits, dots, one slash), not that
// the key parses as a CIDR. Everything below is "CIDR-shaped" by that rule but
// is not an IPv4 CIDR.
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
