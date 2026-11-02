package main

import (
	"net"
	"testing"
)

func TestPortOf(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"127.0.0.1:8023", 8023},
		{"0.0.0.0:8080", 8080},
		{"[::1]:22", 22},
		{"[::]:5432", 5432},
		{":80", 80},
		{"127.0.0.1:65535", 65535},
		{"127.0.0.1:auto", 0}, // dynamic port: skipped
		{"127.0.0.1:", 0},
		{"8023", 0}, // no colon, no port
		{"", 0},
		{"localhost", 0},
		{"127.0.0.1:abc", 0},
		{"127.0.0.1:80x", 0},
		{"127.0.0.1:99999999999999999999", 0}, // overflows int
		{"a:b:c", 0},
		{"1.2.3.4:80:90", 90}, // the last colon wins
	}
	for _, c := range cases {
		if got := portOf(c.in); got != c.want {
			t.Errorf("portOf(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"10.0.0.5:22", "10.0.0.5", 22},
		{"127.0.0.1:8023", "127.0.0.1", 8023},
		{"[::1]:22", "[::1]", 22}, // brackets are kept
		{"[fe80::1]:443", "[fe80::1]", 443},
		{"*:80", "*", 80},
		{":80", "", 80},
		{"10.0.0.5", "10.0.0.5", 0}, // no port
		{"10.0.0.5:", "10.0.0.5", 0},
		{"10.0.0.5:http", "10.0.0.5", 0}, // non-numeric port
		{"", "", 0},
		{":", "", 0},
		{"a:b:7", "a:b", 7},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %d), want (%q, %d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestSubnetOf(t *testing.T) {
	// deliberately not sorted by specificity: the most specific must still win
	nets := mustNets(t, "10.1.0.0/16", "10.0.0.0/8", "10.1.2.0/24", "192.168.0.0/16", "fd00::/8")
	cases := []struct {
		name, ip, want string
	}{
		{"most specific /24", "10.1.2.3", "10.1.2.0/24"},
		{"middle /16", "10.1.9.9", "10.1.0.0/16"},
		{"outer /8", "10.200.0.1", "10.0.0.0/8"},
		{"other net", "192.168.7.7", "192.168.0.0/16"},
		{"network address", "10.1.2.0", "10.1.2.0/24"},
		{"broadcast address", "10.1.2.255", "10.1.2.0/24"},
		{"IPv4-mapped IPv6", "::ffff:10.1.2.3", "10.1.2.0/24"},
		{"IPv6 in fd00::/8", "fd00::5", "fd00::/8"},
		{"outside every net", "8.8.8.8", ""},
		{"IPv6 outside", "::1", ""},
		{"not an IP", "not-an-ip", ""},
		{"IP with port", "10.1.2.3:22", ""},
		{"CIDR string", "10.1.2.0/24", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := subnetOf(c.ip, nets); got != c.want {
			t.Errorf("%s: subnetOf(%q) = %q, want %q", c.name, c.ip, got, c.want)
		}
	}
	if got := subnetOf("10.1.2.3", nil); got != "" {
		t.Errorf("nil nets: got %q", got)
	}
	if got := subnetOf("10.1.2.3", []*net.IPNet{}); got != "" {
		t.Errorf("empty nets: got %q", got)
	}
	// a /0 net contains everything but loses to anything more specific
	wide := mustNets(t, "0.0.0.0/0", "10.0.0.0/8")
	if got := subnetOf("10.9.9.9", wide); got != "10.0.0.0/8" {
		t.Errorf("/0 vs /8: got %q", got)
	}
	if got := subnetOf("8.8.8.8", wide); got != "0.0.0.0/0" {
		t.Errorf("/0 fallback: got %q", got)
	}
}

func TestIsProxyProc(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"OrbStack", true},
		{"OrbStack Helper", true},
		{"com.docker.backend", true},
		{"com.docker.vpnkit", true},
		{"docker-proxy", true},
		{"docker-pr", true}, // the kernel truncates comm to 15 chars
		{"vpnkit-bridge", true},
		{"Docker", true},
		{"Docker Desktop", true},
		{"", false},
		{"ssh", false},
		{"sshd", false},
		{"dockerd", false},  // the daemon is not the accept-side proxy
		{"docker", false},   // the CLI
		{"orbstack", false}, // matching is case-sensitive
		{"xdocker-proxy", false},
		{"/usr/bin/docker-proxy", false}, // prefix match: comm only, not a path
		{" OrbStack", false},
	}
	for _, c := range cases {
		if got := isProxyProc(c.cmd); got != c.want {
			t.Errorf("isProxyProc(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}
