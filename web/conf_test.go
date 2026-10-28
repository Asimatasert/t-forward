package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScalarUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"number", `8080`, "8080"},
		{"quoted string", `"any"`, "any"},
		{"quoted number stays text", `"8080"`, "8080"},
		{"bind:port string", `"0.0.0.0:8080"`, "0.0.0.0:8080"},
		{"null", `null`, ""},
		{"surrounding whitespace", "  8080\n", "8080"},
		{"bool as written", `true`, "true"},
		{"float as written", `1.5`, "1.5"},
		{"escaped string", `"a\"b"`, `a"b`},
		{"empty string", `""`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := scalar{s: "stale"} // must be overwritten, not appended to
			if err := v.UnmarshalJSON([]byte(c.in)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := v.String(); got != c.want {
				t.Fatalf("scalar(%s) = %q, want %q", c.in, got, c.want)
			}
		})
	}

	t.Run("empty input resets", func(t *testing.T) {
		v := scalar{s: "stale"}
		if err := v.UnmarshalJSON(nil); err != nil || v.String() != "" {
			t.Fatalf("got %q, %v; want empty, nil", v.String(), err)
		}
	})
	t.Run("unterminated string is an error", func(t *testing.T) {
		var v scalar
		if err := v.UnmarshalJSON([]byte(`"abc`)); err == nil {
			t.Fatal("expected error for unterminated string")
		}
	})
}

func TestScalarInStruct(t *testing.T) {
	var doc struct {
		A scalar `json:"a"`
		B scalar `json:"b"`
		C scalar `json:"c"`
		D scalar `json:"d"`
	}
	if err := json.Unmarshal([]byte(`{"a": 5432, "b": "any", "c": null}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.A.String() != "5432" || doc.B.String() != "any" || doc.C.String() != "" || doc.D.String() != "" {
		t.Fatalf("got a=%q b=%q c=%q d=%q", doc.A, doc.B, doc.C, doc.D)
	}
}

func TestJumpHopUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name, in string
		want     jumpHop
	}{
		{"bare host", `"10.0.0.10"`, jumpHop{Host: "10.0.0.10"}},
		{"bare user@host:port stays in Host", `"admin@10.0.0.20:2222"`, jumpHop{Host: "admin@10.0.0.20:2222"}},
		{"object", `{"host":"bastion","user":"ops","port":2222}`, jumpHop{Host: "bastion", User: "ops", Port: 2222}},
		{"object host only", `{"host":"bastion"}`, jumpHop{Host: "bastion"}},
		{"object with whitespace", "  {\"host\":\"h\"}\n", jumpHop{Host: "h"}},
		{"empty object", `{}`, jumpHop{}},
		{"null is a no-op", `null`, jumpHop{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h jumpHop
			if err := json.Unmarshal([]byte(c.in), &h); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h != c.want {
				t.Fatalf("got %+v, want %+v", h, c.want)
			}
		})
	}

	for _, bad := range []string{`5`, `[1]`, `{"port":"x"}`, `true`} {
		t.Run("rejects "+bad, func(t *testing.T) {
			var h jumpHop
			if err := json.Unmarshal([]byte(bad), &h); err == nil {
				t.Fatalf("expected an error for %s, got %+v", bad, h)
			}
		})
	}

	t.Run("mixed list keeps order", func(t *testing.T) {
		var hops []jumpHop
		in := `["10.0.0.10", {"host":"10.0.0.20","user":"admin","port":2222}]`
		if err := json.Unmarshal([]byte(in), &hops); err != nil {
			t.Fatal(err)
		}
		want := []jumpHop{{Host: "10.0.0.10"}, {Host: "10.0.0.20", User: "admin", Port: 2222}}
		if !reflect.DeepEqual(hops, want) {
			t.Fatalf("got %+v, want %+v", hops, want)
		}
	})
}

func TestJumpHopToken(t *testing.T) {
	cases := []struct {
		hop  jumpHop
		want string
	}{
		{jumpHop{Host: "h"}, "h"},
		{jumpHop{Host: "h", User: "u"}, "u@h"},
		{jumpHop{Host: "h", Port: 2222}, "h:2222"},
		{jumpHop{Host: "h", User: "u", Port: 2222}, "u@h:2222"},
		{jumpHop{Host: "h", Port: 22}, "h"}, // default port is omitted
		{jumpHop{Host: "h", Port: 0}, "h"},
		{jumpHop{Host: "h", User: "u", Port: 22}, "u@h"},
		{jumpHop{}, ""},
	}
	for _, c := range cases {
		if got := c.hop.token(); got != c.want {
			t.Errorf("%+v.token() = %q, want %q", c.hop, got, c.want)
		}
	}
}

func TestConfPath(t *testing.T) {
	cases := []struct{ dir, name, want string }{
		{"/etc/tf/conf.d", "office", "/etc/tf/conf.d/office.yaml"},
		{"/etc/tf/conf.d/", "office", "/etc/tf/conf.d/office.yaml"}, // trailing slash cleaned
		{"conf.d", "scan-en0-10-0-0-5-22", "conf.d/scan-en0-10-0-0-5-22.yaml"},
		{"/c", "a.b", "/c/a.b.yaml"},
	}
	for _, c := range cases {
		if got := confPath(c.dir, c.name); got != c.want {
			t.Errorf("confPath(%q, %q) = %q, want %q", c.dir, c.name, got, c.want)
		}
	}
}

// requireYq skips the test when the yq binary (needed by readConfYAML) is
// missing. CI's ubuntu-latest runner ships yq; a bare golang image does not.
func requireYq(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("yq"); err != nil {
		t.Skip("yq not installed")
	}
}

func readExample(t *testing.T, name string) *confYAML {
	t.Helper()
	c, err := readConfYAML(filepath.Join("..", "examples", name))
	if err != nil {
		t.Fatalf("readConfYAML(%s): %v", name, err)
	}
	return c
}

func TestReadConfYAMLSSHJumpExample(t *testing.T) {
	requireYq(t)
	c := readExample(t, "ssh-jump.example.yaml")

	if c.Name != "DB via bastion" || c.Type != "ssh" {
		t.Fatalf("name/type = %q/%q", c.Name, c.Type)
	}
	if !reflect.DeepEqual(c.Tags, []string{"ssh", "example"}) {
		t.Fatalf("tags = %v", c.Tags)
	}
	if c.Socks.String() != "1080" {
		t.Fatalf("socks = %q, want 1080", c.Socks.String())
	}
	if c.SSH == nil {
		t.Fatal("ssh block missing")
	}
	if c.SSH.Host != "10.0.0.30" || c.SSH.User != "username1" || c.SSH.Port != 22 {
		t.Fatalf("ssh = %+v", c.SSH)
	}
	var toks []string
	for _, h := range c.SSH.Jump {
		toks = append(toks, h.token())
	}
	if !reflect.DeepEqual(toks, []string{"10.0.0.10", "admin@10.0.0.20:2222"}) {
		t.Fatalf("jump tokens = %v", toks)
	}
	if len(c.Hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(c.Hosts))
	}
	h0 := c.Hosts[0]
	if h0.IP != "10.0.0.40" || h0.Name != "deep db" || len(h0.Forwards) != 1 {
		t.Fatalf("host0 = %+v", h0)
	}
	f := h0.Forwards[0]
	if f.Remote.String() != "5432" || f.Local.String() != "5433" || f.Service != "postgres" {
		t.Fatalf("forward = %+v", f)
	}
	if got := c.Hosts[1].Forwards[0].Local.String(); got != "any" {
		t.Fatalf("host1 local = %q, want any", got)
	}
}

func TestReadConfYAMLVPNExample(t *testing.T) {
	requireYq(t)
	c := readExample(t, "vpn.example.yaml")

	if c.Type != "vpn" || c.VPN == nil {
		t.Fatalf("type/vpn = %q/%v", c.Type, c.VPN)
	}
	if c.VPN.Server != "vpn.example.com:10443" || c.VPN.Protocol != "fortinet" || c.VPN.User != "username1" {
		t.Fatalf("vpn = %+v", c.VPN)
	}
	if c.VPN.Totp {
		t.Fatal("totp should be false in the example")
	}
	if c.Restart {
		t.Fatal("restart is commented out in the example")
	}
	if c.Socks.String() != "1080" {
		t.Fatalf("socks = %q", c.Socks.String())
	}
	if len(c.Hosts) != 2 || len(c.Hosts[0].Forwards) != 4 {
		t.Fatalf("hosts/forwards shape wrong: %+v", c.Hosts)
	}
	lan := c.Hosts[0].Forwards[3]
	if lan.Remote.String() != "8080" || lan.Local.String() != "0.0.0.0:8080" {
		t.Fatalf("lan-bind forward = %+v", lan)
	}
	if len(c.Subnets) != 1 || c.Subnets[0].CIDR != "10.0.0.0/16" || c.Subnets[0].Label != "office LAN" ||
		!reflect.DeepEqual(c.Subnets[0].Tags, []string{"dmz"}) {
		t.Fatalf("subnets = %+v", c.Subnets)
	}
}

func TestReadConfYAMLIMAPExample(t *testing.T) {
	requireYq(t)
	c := readExample(t, "vpn-imap.example.yaml")
	if c.VPN == nil || !c.VPN.Totp || c.VPN.TotpIMAP == nil {
		t.Fatalf("vpn/totp_imap missing: %+v", c.VPN)
	}
	im := c.VPN.TotpIMAP
	if im.Host != "imap.example.com" || im.User != "inbox@example.com" {
		t.Fatalf("imap = %+v", im)
	}
}

func TestReadConfYAMLAllExamplesParse(t *testing.T) {
	requireYq(t)
	files, err := filepath.Glob(filepath.Join("..", "examples", "*.example.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no example files found (err=%v)", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			if _, err := readConfYAML(f); err != nil {
				t.Fatalf("readConfYAML: %v", err)
			}
		})
	}
}

func TestReadConfYAMLTempFile(t *testing.T) {
	requireYq(t)
	dir := t.TempDir()
	path := confPath(dir, "tmp")
	body := `name: Temp
restart: true
socks: any
ssh:
  host: h.example.com
  jump:
    - { host: j1, user: u, port: 2200 }
    - j2
hosts:
  - ip: 192.0.2.5
    forwards:
      - { remote: "443", local: 8443 }
      - { remote: 22 }
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Restart || c.Socks.String() != "any" || c.Type != "" {
		t.Fatalf("restart/socks/type = %v/%q/%q", c.Restart, c.Socks.String(), c.Type)
	}
	if c.SSH == nil || len(c.SSH.Jump) != 2 || c.SSH.Jump[0].token() != "u@j1:2200" || c.SSH.Jump[1].token() != "j2" {
		t.Fatalf("ssh = %+v", c.SSH)
	}
	fw := c.Hosts[0].Forwards
	if fw[0].Remote.String() != "443" || fw[0].Local.String() != "8443" ||
		fw[1].Remote.String() != "22" || fw[1].Local.String() != "" {
		t.Fatalf("forwards = %+v", fw)
	}
}

func TestReadConfYAMLErrors(t *testing.T) {
	requireYq(t)
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if c, err := readConfYAML(filepath.Join(dir, "nope.yaml")); err == nil {
			t.Fatalf("expected error, got %+v", c)
		}
	})
	t.Run("broken yaml", func(t *testing.T) {
		p := filepath.Join(dir, "broken.yaml")
		if err := os.WriteFile(p, []byte("name: [unterminated\n  : : :\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if c, err := readConfYAML(p); err == nil {
			t.Fatalf("expected error, got %+v", c)
		}
	})
	t.Run("wrong shape", func(t *testing.T) {
		p := filepath.Join(dir, "shape.yaml")
		if err := os.WriteFile(p, []byte("hosts: not-a-list\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if c, err := readConfYAML(p); err == nil {
			t.Fatalf("expected a JSON unmarshal error, got %+v", c)
		}
	})
}

func TestCloneForwardsIsDeep(t *testing.T) {
	orig := Tunnel{ID: "t", Forwards: []Forward{
		{Local: "127.0.0.1:auto", Remote: "10.0.0.1:22", Service: "ssh"},
		{Local: "127.0.0.1:auto", Remote: "10.0.0.1:80", Service: "http"},
	}}
	cp := cloneForwards(orig)

	if !reflect.DeepEqual(cp, orig) {
		t.Fatalf("clone differs from original: %+v vs %+v", cp, orig)
	}
	// callers overwrite forward fields with the real published port
	cp.Forwards[0].Local = "127.0.0.1:41000"
	cp.Forwards = append(cp.Forwards, Forward{Remote: "x"})
	if orig.Forwards[0].Local != "127.0.0.1:auto" {
		t.Fatalf("mutating the clone changed the original: %+v", orig.Forwards[0])
	}
	if len(orig.Forwards) != 2 {
		t.Fatalf("original length changed to %d", len(orig.Forwards))
	}
}

func TestCloneForwardsNil(t *testing.T) {
	cp := cloneForwards(Tunnel{ID: "t"})
	if cp.Forwards != nil {
		t.Fatalf("nil Forwards should stay nil, got %#v", cp.Forwards)
	}
	if cp.ID != "t" {
		t.Fatalf("other fields must be preserved, got %+v", cp)
	}
}

// tunnelFromConf seeds Forwards with an empty non-nil slice and its error path
// returns [], so the clone should keep it non-nil: /state would otherwise serve
// "forwards":null for a conf without forwards (inconsistent API contract). The
// panel normalizes via applyState (`forwards: s.forwards || []`), so there is
// no visible error today.
func TestCloneForwardsKeepsEmptySliceNonNil(t *testing.T) {
	cp := cloneForwards(Tunnel{Forwards: []Forward{}})
	b, _ := json.Marshal(cp)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["forwards"]) != "[]" {
		t.Fatalf(`"forwards" marshalled as %s, want []`, m["forwards"])
	}
}

// withPublishBind swaps the package-level bind address (read from
// T_FORWARD_BIND at start-up) for the duration of a test.
func withPublishBind(t *testing.T, bind string) {
	t.Helper()
	old := publishBind
	publishBind = bind
	t.Cleanup(func() { publishBind = old })
}

func TestLocalSpec(t *testing.T) {
	withPublishBind(t, "127.0.0.1")
	cases := []struct{ in, want string }{
		{"", "127.0.0.1:auto"},
		{"any", "127.0.0.1:auto"},
		{"8080", "127.0.0.1:8080"},
		{"0.0.0.0:8080", "0.0.0.0:8080"},
		{"192.168.1.5:9100", "192.168.1.5:9100"},
		{"[::1]:80", "[::1]:80"},
		{"127.0.0.1:auto", "127.0.0.1:auto"},
	}
	for _, c := range cases {
		if got := localSpec(c.in); got != c.want {
			t.Errorf("localSpec(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLocalSpecFollowsPublishBind(t *testing.T) {
	withPublishBind(t, "0.0.0.0")
	if got := localSpec("any"); got != "0.0.0.0:auto" {
		t.Errorf("any -> %q", got)
	}
	if got := localSpec("2205"); got != "0.0.0.0:2205" {
		t.Errorf("2205 -> %q", got)
	}
	// an explicit bind:port is never rewritten
	if got := localSpec("127.0.0.1:2205"); got != "127.0.0.1:2205" {
		t.Errorf("explicit bind -> %q", got)
	}
}

func TestOrEmpty(t *testing.T) {
	if got := orEmpty(nil); got == nil || len(got) != 0 {
		t.Fatalf("orEmpty(nil) = %#v, want empty non-nil slice", got)
	}
	b, _ := json.Marshal(orEmpty(nil))
	if string(b) != "[]" {
		t.Fatalf("nil marshals as %s, want []", b)
	}
	in := []string{"a", "b"}
	if got := orEmpty(in); !reflect.DeepEqual(got, in) {
		t.Fatalf("orEmpty(%v) = %v", in, got)
	}
	if got := orEmpty([]string{}); got == nil || len(got) != 0 {
		t.Fatalf("empty non-nil slice must stay non-nil, got %#v", got)
	}
}
