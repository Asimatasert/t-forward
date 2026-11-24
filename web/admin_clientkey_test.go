package main

import (
	"net/http/httptest"
	"strconv"
	"testing"
)

const testClient = "192.0.2.1"

func TestClientKey(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.1:5000":              "192.0.2.1",
		"[::ffff:192.0.2.1]:5000":     "192.0.2.1",
		"[2001:db8:1:2:3:4:5:6]:5000": "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::9]:80":   "2001:db8:1:2::/64",
		"[fe80::1%eth0]:80":           "fe80::/64",
		"@":                           "@", // not host:port: used verbatim
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		req.Header.Set("X-Real-IP", "203.0.113.51")
		if got := clientKey(req); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", addr, got, want)
		}
	}
}

// A client at its own limit does not move the shared ceiling much, but many
// clients together reach it and then everyone waits.
func TestGlobalCeilingLocksEveryoneOut(t *testing.T) {
	a, _ := newTestActions(t)
	g := &a.gate
	for i := 0; i < globalLockAfterFail-1; i++ {
		g.recordFailure("198.51.100." + strconv.Itoa(i%250))
	}
	if d := g.retryAfter("203.0.113.1"); d != 0 {
		t.Fatalf("a bystander is locked at %d failures: %v", globalLockAfterFail-1, d)
	}
	g.recordFailure("198.51.100.250")
	if d := g.retryAfter("203.0.113.1"); d <= 0 {
		t.Fatal("the global ceiling did not engage")
	}
	g.recordSuccess("203.0.113.1")
	if d := g.retryAfter("203.0.113.1"); d != 0 {
		t.Errorf("a success should clear the global lockout, got %v", d)
	}
}

func TestClientTableIsBounded(t *testing.T) {
	a, _ := newTestActions(t)
	g := &a.gate
	for i := 0; i < 3*maxTrackedClients; i++ {
		g.recordFailure("client-" + strconv.Itoa(i))
		if len(g.clients) > maxTrackedClients {
			t.Fatalf("table grew to %d", len(g.clients))
		}
	}
}
