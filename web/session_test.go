package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A cookie is scoped by host, not by port: whatever cookies the daemon sets are
// also sent to every forwarded service the panel opens on the same hostname.
// These tests replay exactly that — the cookies and nothing else — and require
// the daemon to refuse them.

// cookieJar renders the Cookie header a browser would send after resp.
func cookieJar(rs ...result) string {
	var parts []string
	for _, r := range rs {
		for _, c := range r.resp.Cookies() {
			if c.MaxAge < 0 {
				continue // an expired cookie is dropped, not sent
			}
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}

var sessionKeyRe = regexp.MustCompile(`<meta name="tf-session-key" content="([0-9a-f]+)">`)

// pageSessionKey extracts the origin-scoped key the panel page carries.
func pageSessionKey(body string) string {
	if m := sessionKeyRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// bodyAdminKey extracts the admin session's origin-scoped key from a JSON body.
func bodyAdminKey(body string) string {
	var m struct {
		AdminKey string `json:"adminKey"`
	}
	_ = json.Unmarshal([]byte(body), &m)
	return m.AdminKey
}

// eventsStatus opens /events with the given headers and returns the status and,
// for a 200, the first SSE line.
func eventsStatus(t *testing.T, d *daemon, hdr map[string]string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", d.base+"/events", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return resp.StatusCode, ""
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return 200, line
}

func TestCookiesReplayedFromAnotherPortDoNotAuthenticate(t *testing.T) {
	const tok = "leak-token-0123456789"
	d := startDaemon(t, startOpts{token: tok, cfgDir: t.TempDir()})
	noBearer := func(extra map[string]string) map[string]string {
		h := map[string]string{"Authorization": "-"}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	// the operator opens the panel through the printed link
	first := d.req("GET", "/?token="+tok, "", noBearer(nil))
	if first.code != 200 {
		t.Fatalf("GET /?token= = %d", first.code)
	}
	jar := cookieJar(first)
	if jar == "" {
		t.Fatal("the panel load set no cookie")
	}
	if strings.Contains(jar, tok) {
		t.Errorf("a cookie carries the raw token: %q", jar)
	}

	// token-gated routes: the cookies alone are refused
	for _, p := range []string{"/state", "/version", "/settings", "/scan", "/layout", "/evlog", "/nope"} {
		if r := d.req("GET", p, "", noBearer(map[string]string{"Cookie": jar})); r.code != 401 {
			t.Errorf("cookie-only GET %s = %d, want 401", p, r.code)
		}
	}
	for _, p := range []string{"/up", "/down", "/layout", "/settings", "/conf/x", "/scan/forward"} {
		if r := d.req("POST", p, `{}`, noBearer(map[string]string{"Cookie": jar})); r.code != 401 {
			t.Errorf("cookie-only POST %s = %d, want 401", p, r.code)
		}
	}
	if code, _ := eventsStatus(t, d, map[string]string{"Cookie": jar}); code != 401 {
		t.Errorf("cookie-only /events = %d, want 401", code)
	}

	// privileged routes: set a PIN, then replay the admin cookie. The request
	// carries the daemon token so that only the admin gate is under test (this is
	// what a forwarded service faces under -no-auth, or once it knows the token).
	set := d.req("POST", "/settings", `{"adminPin":"123456"}`, nil)
	if set.code != 200 {
		t.Fatalf("setting the PIN: %d %s", set.code, set.body)
	}
	adminJar := cookieJar(set)
	if adminJar == "" {
		t.Fatal("setting the PIN set no cookie")
	}
	for _, c := range []struct{ path, body string }{
		{"/conf/nosuch", `{}`},
		{"/scan/forward", `{"ip":"192.0.2.1","port":"80"}`},
		{"/scan/device", `{"id":"aa:bb:cc:dd:ee:ff"}`},
		{"/notify/test", `{}`},
		{"/settings", `{"claudeApiKey":"k"}`},
	} {
		r := d.req("POST", c.path, c.body, map[string]string{"Cookie": adminJar})
		if r.code != 403 || !strings.Contains(r.body, `"needPin":true`) {
			t.Errorf("admin-cookie-only POST %s = %d %q, want 403 needPin", c.path, r.code, r.body)
		}
	}
	// the cookie value replayed as the API header is no session either
	val := adminJar[strings.IndexByte(adminJar, '=')+1:]
	if r := d.req("POST", "/conf/nosuch", `{}`, map[string]string{"X-Admin-Token": val}); r.code != 403 {
		t.Errorf("admin cookie value as X-Admin-Token = %d, want 403", r.code)
	}
	// both cookies together, as the browser really sends them
	if r := d.req("POST", "/conf/nosuch", `{}`, noBearer(map[string]string{"Cookie": jar + "; " + adminJar})); r.code != 401 {
		t.Errorf("both cookies, no origin secret: POST /conf/nosuch = %d, want 401", r.code)
	}
}

func TestBrowserSessionNeedsCookieAndOriginKey(t *testing.T) {
	const tok = "session-token-0123456789"
	d := startDaemon(t, startOpts{token: tok, cfgDir: t.TempDir()})
	bare := func(extra map[string]string) map[string]string {
		h := map[string]string{"Authorization": "-"}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	first := d.req("GET", "/?token="+tok, "", bare(nil))
	ck := first.cookie("tf_session")
	if ck == nil {
		t.Fatalf("no tf_session cookie (code %d)", first.code)
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Errorf("cookie = %+v, want HttpOnly SameSite=Strict Path=/", ck)
	}
	key := pageSessionKey(first.body)
	if key == "" {
		t.Fatal("the token-authenticated page carries no session key")
	}
	if strings.Contains(ck.Value, key) || strings.Contains(first.body, tok) || strings.Contains(ck.Value, tok) {
		t.Error("cookie and key must be distinct, and neither may be the token")
	}
	if old := first.cookie("tf_token"); old != nil {
		t.Errorf("a browser without the legacy cookie was sent one: %+v", old)
	}
	jar := "tf_session=" + ck.Value
	sess := bare(map[string]string{"Cookie": jar, "X-Session-Key": key})

	// cookie + origin key authenticates reads, writes and the stream
	if r := d.req("GET", "/state", "", sess); r.code != 200 {
		t.Errorf("cookie+key GET /state = %d", r.code)
	}
	if r := d.req("POST", "/up", `{"name":"bad name!"}`, sess); r.code == 401 {
		t.Errorf("cookie+key POST /up = 401: %s", r.body)
	}
	if code, line := eventsStatus(t, d, map[string]string{"Cookie": jar, "X-Session-Key": key}); code != 200 || line != "event: state\n" {
		t.Errorf("cookie+key /events = %d %q, want the state snapshot", code, line)
	}

	// every incomplete or mismatched combination is refused
	second := d.req("GET", "/?token="+tok, "", bare(nil))
	otherKey, otherCk := pageSessionKey(second.body), second.cookie("tf_session")
	if otherCk == nil || otherKey == "" || otherKey == key || otherCk.Value == ck.Value {
		t.Fatalf("a second visit without a cookie must get its own session")
	}
	id, _, _ := strings.Cut(ck.Value, ".")
	for name, h := range map[string]map[string]string{
		"key without cookie":           {"X-Session-Key": key},
		"cookie with wrong key":        {"Cookie": jar, "X-Session-Key": strings.Repeat("0", len(key))},
		"cookie with empty key":        {"Cookie": jar, "X-Session-Key": ""},
		"key of another session":       {"Cookie": jar, "X-Session-Key": otherKey},
		"cookie value as key":          {"Cookie": jar, "X-Session-Key": ck.Value},
		"forged cookie, real key":      {"Cookie": "tf_session=" + id + "." + strings.Repeat("0", 64), "X-Session-Key": key},
		"id only, real key":            {"Cookie": "tf_session=" + id, "X-Session-Key": key},
		"legacy token cookie":          {"Cookie": "tf_token=" + tok},
		"wrong token is never rescued": {"Cookie": jar, "X-Session-Key": key, "X-Token": "wrong"},
	} {
		if r := d.req("GET", "/state", "", bare(h)); r.code != 401 {
			t.Errorf("%s: GET /state = %d, want 401", name, r.code)
		}
	}

	// a reload sends the cookie only: the static panel is served again, but
	// without a key and without a new cookie — it is useless to a replayer
	reload := d.req("GET", "/", "", bare(map[string]string{"Cookie": jar}))
	if reload.code != 200 || pageSessionKey(reload.body) != "" || reload.cookie("tf_session") != nil {
		t.Errorf("cookie-only reload: code=%d key=%q cookie=%v", reload.code, pageSessionKey(reload.body), reload.cookie("tf_session"))
	}
	if !strings.Contains(reload.body, `<meta name="tf-session-key" content="">`) {
		t.Error("cookie-only reload must serve the panel with the empty key placeholder")
	}
	if r := d.req("GET", "/", "", bare(map[string]string{"Cookie": "tf_session=" + id + "." + strings.Repeat("0", 64)})); r.code != 401 {
		t.Errorf("forged cookie GET / = %d, want 401", r.code)
	}
	if r := d.req("POST", "/", `{}`, bare(map[string]string{"Cookie": jar})); r.code != 401 {
		t.Errorf("cookie-only POST / = %d, want 401", r.code)
	}

	// re-opening the link in a browser that already has the cookie keeps the
	// session (other tabs stay signed in) and hands out the same key
	again := d.req("GET", "/?token="+tok, "", bare(map[string]string{"Cookie": jar}))
	if c := again.cookie("tf_session"); c == nil || c.Value != ck.Value || pageSessionKey(again.body) != key {
		t.Errorf("re-open changed the session: cookie=%v key=%q", c, pageSessionKey(again.body))
	}

	// API clients are unaffected
	for name, h := range map[string]map[string]string{
		"bearer":  {"Authorization": "Bearer " + tok},
		"X-Token": {"Authorization": "-", "X-Token": tok},
		// a stale cookie (e.g. from before a token change) must not block the link
		"query beats stale cookie": {"Authorization": "-", "Cookie": "tf_session=stale.stale"},
	} {
		path := "/state"
		if name == "query beats stale cookie" {
			path = "/state?token=" + tok
		}
		if r := d.req("GET", path, "", h); r.code != 200 {
			t.Errorf("%s: GET %s = %d, want 200", name, path, r.code)
		}
	}
}

// Under -no-auth there is no token and no tf_session; the admin session is the
// only credential, and its cookie leaks to other ports just the same.
func TestAdminSessionNeedsCookieAndOriginKey(t *testing.T) {
	d := startDaemon(t, startOpts{args: []string{"-no-auth"}, cfgDir: t.TempDir()})

	if r := d.req("GET", "/", "", nil); r.code != 200 || len(r.resp.Cookies()) != 0 || pageSessionKey(r.body) != "" {
		t.Errorf("/ under -no-auth: code=%d cookies=%v key=%q", r.code, r.resp.Cookies(), pageSessionKey(r.body))
	}

	set := d.req("POST", "/settings", `{"adminPin":"123456"}`, nil)
	if set.code != 200 || set.cookie("tf_admin") == nil || bodyAdminKey(set.body) == "" {
		t.Fatalf("setting the PIN: %d %s cookie=%v", set.code, set.body, set.cookie("tf_admin"))
	}
	u := d.req("POST", "/admin/unlock", `{"pin":"123456"}`, nil)
	ck, key := u.cookie("tf_admin"), bodyAdminKey(u.body)
	if u.code != 200 || ck == nil || key == "" {
		t.Fatalf("unlock = %d %s cookie=%v", u.code, u.body, ck)
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("tf_admin = %+v, want HttpOnly SameSite=Strict", ck)
	}
	if key == ck.Value || strings.Contains(ck.Value, key) {
		t.Error("admin key must not be derivable from the cookie")
	}
	jar := "tf_admin=" + ck.Value

	refused := map[string]map[string]string{
		"cookie only":                {"Cookie": jar},
		"cookie with wrong key":      {"Cookie": jar, "X-Admin-Key": strings.Repeat("0", len(key))},
		"key only":                   {"X-Admin-Key": key},
		"cookie value as key":        {"Cookie": jar, "X-Admin-Key": ck.Value},
		"cookie value as API header": {"X-Admin-Token": ck.Value},
		"key as API header":          {"X-Admin-Token": key},
		"key of another session":     {"Cookie": jar, "X-Admin-Key": bodyAdminKey(set.body)},
	}
	for name, h := range refused {
		r := d.req("POST", "/conf/nosuch", `{}`, h)
		if r.code != 403 || !strings.Contains(r.body, `"needPin":true`) {
			t.Errorf("%s: POST /conf/nosuch = %d %q, want 403 needPin", name, r.code, r.body)
		}
	}
	// cookie + origin key reaches the handler (404: no such tunnel)
	if r := d.req("POST", "/conf/nosuch", `{}`, map[string]string{"Cookie": jar, "X-Admin-Key": key}); r.code != 404 {
		t.Errorf("cookie+key POST /conf/nosuch = %d %s, want 404 from the handler", r.code, r.body)
	}
	// so does the PIN in the API header
	if r := d.req("POST", "/conf/nosuch", `{}`, map[string]string{"X-Admin-Token": "123456"}); r.code != 404 {
		t.Errorf("PIN in X-Admin-Token: POST /conf/nosuch = %d %s, want 404", r.code, r.body)
	}
}

// ------------------------------------------------------ unit: browserSessions

func TestBrowserSessionsSecretPersistsAndFollowsToken(t *testing.T) {
	dir := t.TempDir()
	a := newBrowserSessions(dir, "tok-A")
	id := a.newID()
	cookie, key := a.cookieValue(id), a.key(id)
	if len(key) != 64 || strings.Contains(cookie, key) {
		t.Fatalf("cookie %q / key %q", cookie, key)
	}

	fi, err := os.Stat(filepath.Join(dir, "web-session.key"))
	if err != nil {
		t.Fatalf("secret not persisted: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("secret mode = %v, want 0600", fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("stray files beside the secret: %v", ents)
	}

	accepts := func(s *browserSessions) bool {
		req := httptest.NewRequest(http.MethodGet, "/state", nil)
		req.AddCookie(&http.Cookie{Name: "tf_session", Value: cookie})
		got, ok := s.cookieID(req)
		return ok && got == id && s.keyValid(id, key)
	}
	if !accepts(a) {
		t.Fatal("a session is not accepted by the instance that minted it")
	}
	// a restarted daemon (same config dir, same token) still accepts it
	if !accepts(newBrowserSessions(dir, "tok-A")) {
		t.Error("session lost across a restart")
	}
	// rotating the token revokes it
	if accepts(newBrowserSessions(dir, "tok-B")) {
		t.Error("session survived a token change")
	}
	// another installation (different secret) with the same token rejects it,
	// i.e. the cookie is not a function of the token alone
	if accepts(newBrowserSessions(t.TempDir(), "tok-A")) {
		t.Error("session accepted by a daemon with a different secret")
	}

	// an unusable config dir degrades to an in-memory secret, never to a fixed one
	missing := filepath.Join(dir, "absent", "deeper")
	m1, m2 := newBrowserSessions(missing, "tok-A"), newBrowserSessions(missing, "tok-A")
	if m1.key(id) == m2.key(id) || m1.key(id) == key {
		t.Error("in-memory fallback secret is not random")
	}
	// a truncated secret file is replaced rather than trusted
	short := t.TempDir()
	if err := os.WriteFile(filepath.Join(short, "web-session.key"), []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s1 := newBrowserSessions(short, "tok-A")
	if s2 := newBrowserSessions(short, "tok-A"); s1.key(id) != s2.key(id) {
		t.Error("a replaced secret must persist")
	}
	if b, _ := os.ReadFile(filepath.Join(short, "web-session.key")); len(strings.TrimSpace(string(b))) != 64 {
		t.Errorf("weak secret kept: %q", b)
	}
}

func TestBrowserSessionsRejectMalformedCookies(t *testing.T) {
	s := newBrowserSessions(t.TempDir(), "tok")
	id := s.newID()
	good := s.cookieValue(id)
	for _, v := range []string{"", ".", id, id + ".", "." + macHex(s.cookieKey, ""), good + "0", good[1:], strings.ToUpper(good), s.key(id), id + "." + s.key(id)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "tf_session", Value: v})
		if _, ok := s.cookieID(req); ok && v != good {
			t.Errorf("cookie %q accepted", v)
		}
	}
	if s.keyValid(id, "") || s.keyValid("", "") || s.keyValid(id, s.cookieValue(id)) || !s.keyValid(id, s.key(id)) {
		t.Error("keyValid misjudged a key")
	}
}

// Releases up to v0.8.0 kept the raw token in the tf_token cookie. A browser
// that still holds it sends the token to every forwarded port, so the daemon
// must make the browser drop it on whatever it answers — an upgraded browser
// has no session yet and gets nothing but 401 until the link is opened again —
// and must never accept it as a credential.
func TestLegacyTokenCookieIsExpiredOnEveryResponse(t *testing.T) {
	const tok = "legacy-token-0123456789"
	expired := func(t *testing.T, what string, cs []*http.Cookie) {
		t.Helper()
		n := 0
		for _, c := range cs {
			if c.Name != "tf_token" {
				continue
			}
			n++
			if c.MaxAge >= 0 || c.Value != "" || c.Path != "/" {
				t.Errorf("%s: tf_token = %+v, want an expiry for Path=/", what, c)
			}
		}
		if n != 1 {
			t.Errorf("%s: %d tf_token Set-Cookie headers, want 1", what, n)
		}
	}
	legacy := "tf_token=" + tok

	t.Run("token mode", func(t *testing.T) {
		d := startDaemon(t, startOpts{token: tok, cfgDir: t.TempDir()})
		bare := func(extra map[string]string) map[string]string {
			h := map[string]string{"Authorization": "-"}
			for k, v := range extra {
				h[k] = v
			}
			return h
		}
		for _, c := range []struct {
			what, method, path, body string
			hdr                      map[string]string
			want                     int
		}{
			{"refused read", "GET", "/state", "", bare(map[string]string{"Cookie": legacy}), 401},
			{"refused panel load", "GET", "/", "", bare(map[string]string{"Cookie": legacy}), 401},
			{"refused write", "POST", "/up", `{"name":"x"}`, bare(map[string]string{"Cookie": legacy}), 401},
			{"refused stream", "GET", "/events", "", bare(map[string]string{"Cookie": legacy}), 401},
			{"unknown path", "GET", "/nope", "", bare(map[string]string{"Cookie": legacy}), 401},
			{"wrong token", "GET", "/state", "", bare(map[string]string{"Cookie": legacy, "X-Token": "wrong"}), 401},
			{"rejected by the guard", "GET", "/state", "", bare(map[string]string{"Cookie": legacy, "Sec-Fetch-Site": "cross-site"}), 403},
			{"unauthenticated liveness probe", "GET", "/healthz", "", bare(map[string]string{"Cookie": legacy}), 200},
			{"API client", "GET", "/state", "", map[string]string{"Cookie": legacy}, 200},
			{"panel link", "GET", "/?token=" + tok, "", bare(map[string]string{"Cookie": legacy}), 200},
		} {
			r := d.req(c.method, c.path, c.body, c.hdr)
			if r.code != c.want {
				t.Errorf("%s: %s %s = %d, want %d", c.what, c.method, c.path, r.code, c.want)
			}
			expired(t, c.what, r.resp.Cookies())
		}

		// with a real session next to it: still expired, and still no credential
		first := d.req("GET", "/?token="+tok, "", bare(nil))
		ck, key := first.cookie("tf_session"), pageSessionKey(first.body)
		if ck == nil || key == "" {
			t.Fatalf("no session: code %d", first.code)
		}
		jar := "tf_session=" + ck.Value + "; " + legacy
		r := d.req("GET", "/state", "", bare(map[string]string{"Cookie": jar, "X-Session-Key": key}))
		if r.code != 200 {
			t.Errorf("session + legacy cookie: GET /state = %d, want 200", r.code)
		}
		expired(t, "session + legacy cookie", r.resp.Cookies())
		r = d.req("GET", "/state", "", bare(map[string]string{"Cookie": jar}))
		if r.code != 401 {
			t.Errorf("session cookie + legacy cookie, no key: GET /state = %d, want 401", r.code)
		}
		expired(t, "session cookie + legacy cookie, no key", r.resp.Cookies())

		// a request without the legacy cookie is not sent one
		for _, h := range []map[string]string{bare(nil), nil, bare(map[string]string{"Cookie": "tf_session=" + ck.Value, "X-Session-Key": key})} {
			if r := d.req("GET", "/state", "", h); r.cookie("tf_token") != nil {
				t.Errorf("unprompted tf_token Set-Cookie (code %d)", r.code)
			}
		}
	})

	// the cookie outlives a switch to -no-auth as well
	t.Run("no-auth", func(t *testing.T) {
		d := startDaemon(t, startOpts{args: []string{"-no-auth"}, cfgDir: t.TempDir()})
		r := d.req("GET", "/state", "", map[string]string{"Cookie": legacy})
		if r.code != 200 {
			t.Errorf("GET /state = %d, want 200", r.code)
		}
		expired(t, "no-auth", r.resp.Cookies())
		if r := d.req("GET", "/state", "", nil); r.cookie("tf_token") != nil {
			t.Error("unprompted tf_token Set-Cookie under -no-auth")
		}
	})
}

// A secret file left group/world readable (restored backup, loose umask) is
// kept, but its mode is tightened.
func TestBrowserSessionsTightenExistingSecretMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web-session.key")
	a := newBrowserSessions(dir, "tok")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	b := newBrowserSessions(dir, "tok")
	id := a.newID()
	if a.key(id) != b.key(id) {
		t.Error("the existing secret was replaced instead of kept")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode after load = %v, want 0600", fi.Mode().Perm())
	}
}
