package main

// Extra coverage for the port-less bracketed IPv6 Host header fix in hostOnly.
// The core regression is TestHostOnlyBareBracketedIPv6 in main_test.go; these
// tests pin the edges and, above all, that nothing becomes *more* accepted:
// only a bracketed IPv6 loopback literal loses its brackets.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTHostOnlyIPv6Forms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"[::1]", "::1"}, // the fix
		{"[::ffff:127.0.0.1]", "::ffff:127.0.0.1"}, // v4-mapped loopback
		{"[::1]:8080", "::1"},                      // with port: unchanged
		{"[::1]:80", "::1"},                        //
		{"127.0.0.1:8080", "127.0.0.1"},            // host:port unchanged
		{"localhost", "localhost"},                 // plain name unchanged
		{"::1", "::1"},                             // already bare
		{"[2001:db8::1]", "[2001:db8::1]"},         // non-loopback: brackets kept
		{"[::]", "[::]"},                           // unspecified is not loopback
		{"[fe80::1%lo]", "[fe80::1%lo]"},           // zone: not parsed, kept
		{"[localhost]", "[localhost]"},             // bracketed name is not an IPv6 literal
		{"[127.0.0.1]", "[127.0.0.1]"},             // IPv4 never goes in brackets
		{"[]", "[]"},                               //
		{"[", "["},                                 //
		{"[::1", "[::1"},                           // unbalanced
		{"::1]", "::1]"},                           //
		{"[[::1]]", "[[::1]]"},                     // nested
		{"[::1] ", "[::1] "},                       // trailing space is not stripped
	}
	for _, c := range cases {
		if got := hostOnly(c.in); got != c.want {
			t.Errorf("hostOnly(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// bindIsLoopback shares hostOnly. A listen address always carries a port, so
// the bracketed-no-port branch is never hit by a real flag value; the result
// for "[::1]:port" is unchanged.
func TestTHostBindIsLoopbackUnchanged(t *testing.T) {
	yes := []string{"[::1]:8787", "127.0.0.1:8787", "localhost:8787"}
	no := []string{"[::]:8787", ":8787", "0.0.0.0:8787", "[2001:db8::1]:8787", "example.com:8787"}
	for _, a := range yes {
		if !bindIsLoopback(a) {
			t.Errorf("bindIsLoopback(%q) = false, want true", a)
		}
	}
	for _, a := range no {
		if bindIsLoopback(a) {
			t.Errorf("bindIsLoopback(%q) = true, want false", a)
		}
	}
}

// The listen address handed to guardMiddleware as the bind host
// (hostOnly(*addr)) is the same for "[::1]:port" as before the fix.
func TestTHostListenAddrToBindHost(t *testing.T) {
	for in, want := range map[string]string{
		"[::1]:8787":       "::1",
		"[::]:8787":        "::",
		"[2001:db8::1]:80": "2001:db8::1",
		"127.0.0.1:8787":   "127.0.0.1",
		":8787":            "",
	} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

// End to end through guardMiddleware: the port-less loopback Host is accepted,
// and no Host that was rejected before the fix is accepted now.
func TestTHostGuardBareBracketedIPv6(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	cases := []struct {
		name  string
		bind  string
		extra []string
		host  string
		want  int
	}{
		{"bare loopback now accepted", "127.0.0.1", nil, "[::1]", 418},
		{"bare v4-mapped loopback accepted", "127.0.0.1", nil, "[::ffff:127.0.0.1]", 418},
		{"loopback with port still accepted", "127.0.0.1", nil, "[::1]:8787", 418},
		// no loosening: these were rejected before and still are
		{"bare non-loopback IPv6 rejected", "127.0.0.1", nil, "[2001:db8::1]", 403},
		{"bare unspecified IPv6 rejected", "127.0.0.1", nil, "[::]", 403},
		{"bare bracketed name rejected", "127.0.0.1", nil, "[evil.example.com]", 403},
		{"bare bracketed localhost-lookalike rejected", "127.0.0.1", nil, "[localhost]", 403},
		{"bare bracketed IPv4 rejected", "127.0.0.1", nil, "[192.168.1.9]", 403},
		{"unbalanced bracket rejected", "127.0.0.1", nil, "[::1", 403},
		{"non-loopback IPv6 bind host does not admit the bare form", "[2001:db8::1]:8787", nil, "[2001:db8::1]", 403},
		{"allow-list entry without brackets does not admit the bare form", "127.0.0.1", []string{"2001:db8::1"}, "[2001:db8::1]", 403},
		// operator can still allow the exact bracketed string explicitly
		{"explicitly allow-listed bracketed literal", "127.0.0.1", []string{"[2001:db8::1]"}, "[2001:db8::1]", 418},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bind := hostOnly(c.bind)
			h := guardMiddleware(bind, c.extra, ok)
			req := httptest.NewRequest("GET", "/state", nil)
			req.Host = c.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("Host %q: status = %d, want %d", c.host, rec.Code, c.want)
			}
		})
	}
}
