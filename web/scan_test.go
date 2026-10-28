package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Sample `nmap -oG -` output. IPs are RFC 5737 documentation addresses so the
// host's ARP cache never knows them (parseNmapGreppable fills MAC from `arp`).
const nmapSample = "# Nmap 7.94 scan initiated Mon Oct 26 12:00:00 2026 as: nmap -sT -n --open -p 22,80,443,445,8080 -T4 --host-timeout 90s -oG - 192.0.2.0/24\n" +
	"Host: 192.0.2.1 (router.lan)\tStatus: Up\n" +
	"Host: 192.0.2.1 (router.lan)\tPorts: 80/open/tcp//http///, 443/open/tcp//https///\tIgnored State: closed (3)\n" +
	"Host: 192.0.2.7 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu/\n" +
	"Host: 192.0.2.9 ()\tPorts: 22/closed/tcp//ssh///, 8080/open/tcp//http-proxy///\n" +
	"Host: 192.0.2.20 ()\tStatus: Up\n" +
	"Host: 192.0.2.21 ()\tPorts: 22/closed/tcp//ssh///, 80/filtered/tcp//http///\n" +
	"Host: 192.0.2.30 (nas.lan)\tPorts: 445/open/tcp//microsoft-ds///\n" +
	"# Nmap done at Mon Oct 26 12:00:09 2026 -- 256 IP addresses (6 hosts up) scanned in 9.00 seconds\n"

// portsOf flattens devices to ip -> "port/service" strings for compact asserts.
func portsOf(devs []scanDevice) map[string][]string {
	m := map[string][]string{}
	for _, d := range devs {
		for _, p := range d.Ports {
			m[d.IP] = append(m[d.IP], itoa(p.Port)+"/"+p.Service)
		}
	}
	return m
}

func itoa(n int) string { return joinInts([]int{n}) }

func TestParseNmapGreppable(t *testing.T) {
	devs := parseNmapGreppable(nmapSample)

	var ips []string
	for _, d := range devs {
		ips = append(ips, d.IP)
	}
	// 192.0.2.20 (Status line only) and 192.0.2.21 (no open ports) are dropped
	if want := []string{"192.0.2.1", "192.0.2.7", "192.0.2.9", "192.0.2.30"}; !reflect.DeepEqual(ips, want) {
		t.Fatalf("devices = %v, want %v", ips, want)
	}

	hosts := map[string]string{}
	for _, d := range devs {
		hosts[d.IP] = d.Host
	}
	if hosts["192.0.2.1"] != "router.lan" || hosts["192.0.2.30"] != "nas.lan" || hosts["192.0.2.7"] != "" {
		t.Fatalf("hostnames = %v", hosts)
	}

	want := map[string][]string{
		"192.0.2.1":  {"80/http", "443/https"},
		"192.0.2.7":  {"22/ssh"},          // version text after the service is ignored
		"192.0.2.9":  {"8080/http-proxy"}, // the closed 22 is skipped
		"192.0.2.30": {"445/microsoft-ds"},
	}
	if got := portsOf(devs); !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestParseNmapGreppableEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string][]string
	}{
		{"empty input", "", map[string][]string{}},
		{"comments only", "# Nmap done\n", map[string][]string{}},
		{"crlf line endings", "Host: 192.0.2.5 ()\tPorts: 80/open/tcp//http///\r\n", map[string][]string{"192.0.2.5": {"80/http"}}},
		{"no trailing newline", "Host: 192.0.2.5 ()\tPorts: 80/open/tcp//http///", map[string][]string{"192.0.2.5": {"80/http"}}},
		{"unknown service is empty", "Host: 192.0.2.5 ()\tPorts: 9999/open/tcp//unknown///", map[string][]string{"192.0.2.5": {"9999/unknown"}}},
		{"empty service name", "Host: 192.0.2.5 ()\tPorts: 9999/open/tcp////", map[string][]string{"192.0.2.5": {"9999/"}}},
		{"non-numeric port skipped", "Host: 192.0.2.5 ()\tPorts: x/open/tcp//http///, 81/open/tcp//http///", map[string][]string{"192.0.2.5": {"81/http"}}},
		{"short entry skipped", "Host: 192.0.2.5 ()\tPorts: 80/open/tcp, 81/open/tcp//http///", map[string][]string{"192.0.2.5": {"81/http"}}},
		{"only closed", "Host: 192.0.2.5 ()\tPorts: 80/closed/tcp//http///", map[string][]string{}},
		{"line without Host prefix ignored", "  Host: 192.0.2.5 ()\tPorts: 80/open/tcp//http///\n", map[string][]string{}},
		{"ipv6 host", "Host: 2001:db8::1 ()\tPorts: 22/open/tcp//ssh///", map[string][]string{"2001:db8::1": {"22/ssh"}}},
		{"hostname without port list gap", "Host: 192.0.2.5 (a.b.c)\tPorts: 22/open/tcp//ssh///\tIgnored State: closed (1)", map[string][]string{"192.0.2.5": {"22/ssh"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := portsOf(parseNmapGreppable(c.in))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ports = %v, want %v", got, c.want)
			}
		})
	}

	t.Run("hostname parsed", func(t *testing.T) {
		devs := parseNmapGreppable("Host: 192.0.2.5 (a.b.c)\tPorts: 22/open/tcp//ssh///\n")
		if len(devs) != 1 || devs[0].Host != "a.b.c" {
			t.Fatalf("devs = %+v", devs)
		}
	})
	t.Run("ports never nil for a returned device", func(t *testing.T) {
		for _, d := range parseNmapGreppable(nmapSample) {
			if len(d.Ports) == 0 {
				t.Fatalf("%s returned with no ports", d.IP)
			}
		}
	})
}

func TestDeviceID(t *testing.T) {
	cases := []struct{ mac, ip, want string }{
		{"AA:BB:CC:DD:EE:FF", "192.0.2.1", "aa:bb:cc:dd:ee:ff"}, // lowercased
		{"aa:bb:cc:dd:ee:ff", "192.0.2.1", "aa:bb:cc:dd:ee:ff"},
		{"", "192.0.2.1", "ip:192.0.2.1"},
		{"", "", "ip:"},
	}
	for _, c := range cases {
		if got := deviceID(c.mac, c.ip); got != c.want {
			t.Errorf("deviceID(%q, %q) = %q, want %q", c.mac, c.ip, got, c.want)
		}
	}
}

func TestDeviceIDIsAcceptedByValidDeviceID(t *testing.T) {
	for _, id := range []string{
		deviceID("AA:BB:CC:DD:EE:FF", "192.0.2.1"),
		deviceID("", "192.0.2.1"),
	} {
		if !validDeviceID(id) {
			t.Errorf("generated id %q is rejected by validDeviceID", id)
		}
	}
}

func TestWidenHostCIDR(t *testing.T) {
	cases := []struct{ name, ip, cidr, want string }{
		{"/32 becomes the /24 around the ip", "10.8.0.5", "10.8.0.5/32", "10.8.0.0/24"},
		{"/32 uses the interface ip", "100.64.12.77", "100.64.12.77/32", "100.64.12.0/24"},
		{"/24 passes through", "192.168.1.20", "192.168.1.0/24", "192.168.1.0/24"},
		{"/16 passes through", "10.1.2.3", "10.1.0.0/16", "10.1.0.0/16"},
		{"/31 passes through", "10.1.2.3", "10.1.2.2/31", "10.1.2.2/31"},
		{"empty cidr stays empty", "10.1.2.3", "", ""},
		{"/32 with empty ip gives up", "", "10.8.0.5/32", ""},
		{"/32 with garbage ip gives up", "not-an-ip", "10.8.0.5/32", ""},
		{"/32 with ipv6 ip gives up", "2001:db8::1", "2001:db8::1/32", ""},
		{"ipv4-mapped ipv6 text is accepted", "::ffff:10.8.0.5", "10.8.0.5/32", "10.8.0.0/24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := widenHostCIDR(c.ip, c.cidr); got != c.want {
				t.Fatalf("widenHostCIDR(%q, %q) = %q, want %q", c.ip, c.cidr, got, c.want)
			}
		})
	}
}

func TestRedisHostPort(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"localhost:6379", "localhost", "6379"},
		{"redis.internal:6380", "redis.internal", "6380"},
		{"10.0.0.5:6379", "10.0.0.5", "6379"},
		{"redis", "redis", "6379"}, // default port
		{"10.0.0.5", "10.0.0.5", "6379"},
		{"[::1]:6379", "::1", "6379"}, // redis-cli -h wants the unbracketed host
		{"[::1]:6380", "::1", "6380"},
		{"[::1]", "::1", "6379"},
		{"2001:db8::5", "2001:db8::5", "6379"},
		{"  redis:6380 ", "redis", "6380"},
	}
	for _, c := range cases {
		h, p := redisHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("redisHostPort(%q) = (%q, %q), want (%q, %q)", c.in, h, p, c.host, c.port)
		}
	}
}

// redis-cli gets `-p <port>`: an empty port (trailing colon) or a bare IPv6
// literal being split at its last colon yields a broken command line.
func TestRedisHostPortMalformed(t *testing.T) {
	if h, p := redisHostPort("redis:"); h != "redis" || p != "6379" {
		t.Errorf(`redisHostPort("redis:") = (%q, %q), want ("redis", "6379")`, h, p)
	}
	if h, p := redisHostPort("::1"); h != "::1" || p != "6379" {
		t.Errorf(`redisHostPort("::1") = (%q, %q), want ("::1", "6379")`, h, p)
	}
}

func TestValidIfaceName(t *testing.T) {
	good := []string{
		"en0", "eth0", "wlan0", "tailscale0", "utun3", "br-1a2b3c", "docker0",
		"eth0.100", "eth0:1", "my_if", "A", strings.Repeat("a", 24),
	}
	for _, s := range good {
		if !validIfaceName(s) {
			t.Errorf("validIfaceName(%q) = false, want true", s)
		}
	}

	bad := []string{
		"",
		strings.Repeat("a", 25), // too long
		"en 0",                  // space
		" en0",
		"en0 ",
		"en0\n",
		"en0\r",
		"en0\t",
		"en0;id",
		"en0&&id",
		"en0|id",
		"$(id)",
		"`id`",
		"${HOME}",
		"en0$(id)",
		"../etc",
		"..\\etc",
		"a/b",
		"/etc/passwd",
		"en0\x00",
		"en\"0",
		"en'0",
		"en0>x",
		"en0<x",
		"en0*",
		"en0?",
		"é0",  // non-ASCII letter
		"ｅｎ０", // fullwidth
		"en0%",
		"en0=1",
		"en0,eth1",
	}
	for _, s := range bad {
		if validIfaceName(s) {
			t.Errorf("validIfaceName(%q) = true, want false", s)
		}
	}
}

func TestValidDeviceID(t *testing.T) {
	good := []string{
		"aa:bb:cc:dd:ee:ff",
		"00:11:22:33:44:55",
		"ip:192.0.2.1",
		"ip:10.0.0.255",
		"AA:BB:CC:DD:EE:FF", // existing records may be upper case; handler lowercases anyway
		"aA:0b:Cc:1d:eE:f2",
	}
	for _, s := range good {
		if !validDeviceID(s) {
			t.Errorf("validDeviceID(%q) = false, want true", s)
		}
	}

	bad := []string{
		"",
		strings.Repeat("a", 65), // too long
		"aa:bb:cc:dd:ee:ff ",
		" aa:bb",
		"aa bb",
		"aa:bb\n",
		"aa:bb\r",
		"aa:bb\t",
		"aa:bb;id",
		"aa:bb&id",
		"aa:bb|id",
		"$(id)",
		"`id`",
		"${HOME}",
		"ip:$(id)",
		"ip:10.0.0.1;id",
		"../etc/passwd",
		"ip:../x",
		"a/b",
		"aa:bb\x00",
		"aa:bb\"",
		"aa:bb'",
		strings.Repeat("a", 64), // right charset, wrong shape
		"aa:bb:cc:dd:ee",        // too short
		"aa:bb:cc:dd:ee:ff:00",  // too long
		"aabb:cc:dd:ee:ff:00",
		"aa:bb:cc:dd:ee:fg",
		"ip:",
		"ip:999.1.1.1",
		"ip:10.0.0",
		"ip:::ffff:10.0.0.1",
		"ip:2001:db8::1",
		"ip:010.0.0.1",
		"ip:10.0.0.1/24",
		"aa-bb-cc-dd-ee-ff",
		"ip=10.0.0.1",
		"é",
	}
	for _, s := range bad {
		if validDeviceID(s) {
			t.Errorf("validDeviceID(%q) = true, want false", s)
		}
	}
}

// The doc comment promises "a MAC or ip:<ipv4> shape (hex, dots, colons, the
// ip: prefix)". The check accepts any a-z letters, so non-hex words pass.
func TestValidDeviceIDRequiresMACOrIPShape(t *testing.T) {
	for _, s := range []string{"zz:zz:zz:zz:zz:zz", "hello", "ip:ip:ip", "::", "..", ":", "."} {
		if validDeviceID(s) {
			t.Errorf("validDeviceID(%q) = true, but it is neither a MAC nor ip:<ipv4>", s)
		}
	}
}

func TestJoinInts(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{}, ""},
		{[]int{80}, "80"},
		{[]int{22, 80, 443}, "22,80,443"},
		{[]int{3, 1, 2}, "3,1,2"}, // order preserved, not sorted
		{[]int{0, -1}, "0,-1"},
		{[]int{65535}, "65535"},
	}
	for _, c := range cases {
		if got := joinInts(c.in); got != c.want {
			t.Errorf("joinInts(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := joinInts(defaultScanPorts); !strings.HasPrefix(got, "21,22,23,") || strings.Contains(got, " ") {
		t.Errorf("joinInts(defaultScanPorts) = %q", got)
	}
}

func sampleSnapshot() scanSnapshot {
	return scanSnapshot{
		At:       1790000000,
		Scanning: true,
		Interfaces: []scanIfaceResult{
			{Name: "en0", IP: "192.0.2.10", CIDR: "192.0.2.0/24", Devices: []scanDevice{
				{IP: "192.0.2.1", MAC: "aa:bb:cc:dd:ee:01", Ports: []scanPort{{Port: 80, Service: "http"}}},
				{IP: "192.0.2.2", Ports: []scanPort{{Port: 22, Service: "ssh"}}},
			}},
			{Name: "utun3", IP: "10.8.0.5", CIDR: "10.8.0.0/24", Devices: nil},
		},
	}
}

func TestCloneSnapshotIsIndependent(t *testing.T) {
	orig := sampleSnapshot()
	cp := cloneSnapshot(orig)

	if !reflect.DeepEqual(cp, orig) {
		t.Fatalf("clone differs from original:\n%+v\n%+v", cp, orig)
	}

	// mutate everything annotate() or a publisher could touch on the copy
	cp.At = 1
	cp.Scanning = false
	cp.Interfaces[0].Name = "changed"
	cp.Interfaces[0].Devices[0].Name = "label"
	cp.Interfaces[0].Devices[1].Tags = []string{"t"}
	cp.Interfaces[0].Devices = append(cp.Interfaces[0].Devices, scanDevice{IP: "192.0.2.99"})
	cp.Interfaces = append(cp.Interfaces, scanIfaceResult{Name: "extra"})

	want := sampleSnapshot()
	if !reflect.DeepEqual(orig, want) {
		t.Fatalf("mutating the clone changed the original:\n%+v\nwant\n%+v", orig, want)
	}
}

func TestCloneSnapshotEmpty(t *testing.T) {
	cp := cloneSnapshot(scanSnapshot{})
	if cp.Interfaces == nil || len(cp.Interfaces) != 0 {
		t.Fatalf("Interfaces = %#v, want empty non-nil (JSON [])", cp.Interfaces)
	}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"interfaces":[]`) {
		t.Fatalf("empty snapshot marshals as %s", b)
	}
}

func TestAnnotate(t *testing.T) {
	annos := map[string]deviceAnno{
		"aa:bb:cc:dd:ee:01": {Name: "Router", Tags: []string{"infra"}},
		"ip:192.0.2.2":      {Name: "NAS", Tags: []string{"storage", "lan"}},
		"ip:192.0.2.3":      {Name: "stale ip label"}, // device has a MAC: the MAC key is checked first
	}
	snap := scanSnapshot{Interfaces: []scanIfaceResult{
		{Name: "en0", Devices: []scanDevice{
			{IP: "192.0.2.1", MAC: "AA:BB:CC:DD:EE:01"}, // mixed-case MAC matches the lowercase key
			{IP: "192.0.2.2"}, // no MAC -> "ip:" key
			{IP: "192.0.2.3", MAC: "aa:bb:cc:dd:ee:03"}, // MAC without an entry falls back to "ip:" key
			{IP: "192.0.2.4"}, // not annotated
		}},
		{Name: "utun3", Devices: []scanDevice{
			{IP: "192.0.2.2"}, // same ip on another interface also gets it
		}},
	}}
	annotate(&snap, annos)

	d := snap.Interfaces[0].Devices
	if d[0].Name != "Router" || !reflect.DeepEqual(d[0].Tags, []string{"infra"}) {
		t.Errorf("by MAC: %+v", d[0])
	}
	if d[1].Name != "NAS" || !reflect.DeepEqual(d[1].Tags, []string{"storage", "lan"}) {
		t.Errorf("by ip: %+v", d[1])
	}
	if d[2].Name != "stale ip label" {
		t.Errorf("MAC without entry should fall back to the ip key: %+v", d[2])
	}
	if d[3].Name != "" || d[3].Tags != nil {
		t.Errorf("unknown device must stay untouched: %+v", d[3])
	}
	if got := snap.Interfaces[1].Devices[0].Name; got != "NAS" {
		t.Errorf("second interface: %q", got)
	}
}

func TestAnnotateMACKeyWinsOverIPKey(t *testing.T) {
	annos := map[string]deviceAnno{
		"aa:bb:cc:dd:ee:01": {Name: "by mac"},
		"ip:192.0.2.1":      {Name: "by ip"},
	}
	snap := scanSnapshot{Interfaces: []scanIfaceResult{{Devices: []scanDevice{{IP: "192.0.2.1", MAC: "aa:bb:cc:dd:ee:01"}}}}}
	annotate(&snap, annos)
	if got := snap.Interfaces[0].Devices[0].Name; got != "by mac" {
		t.Fatalf("name = %q, want the MAC entry to win", got)
	}
}

func TestAnnotateNoAnnosIsNoop(t *testing.T) {
	for _, annos := range []map[string]deviceAnno{nil, {}} {
		snap := sampleSnapshot()
		annotate(&snap, annos)
		if !reflect.DeepEqual(snap, sampleSnapshot()) {
			t.Fatalf("annotate with %v changed the snapshot", annos)
		}
	}
}

func TestAnnotateOnCloneLeavesOriginalAlone(t *testing.T) {
	orig := sampleSnapshot()
	cp := cloneSnapshot(orig)
	annotate(&cp, map[string]deviceAnno{
		"aa:bb:cc:dd:ee:01": {Name: "Router", Tags: []string{"infra"}},
		"ip:192.0.2.2":      {Name: "NAS"},
	})
	if cp.Interfaces[0].Devices[0].Name != "Router" || cp.Interfaces[0].Devices[1].Name != "NAS" {
		t.Fatalf("clone was not annotated: %+v", cp.Interfaces[0].Devices)
	}
	if !reflect.DeepEqual(orig, sampleSnapshot()) {
		t.Fatalf("annotating the clone changed the original: %+v", orig.Interfaces[0].Devices)
	}
}
