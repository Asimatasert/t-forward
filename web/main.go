package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed panel/index.html
var panelFS embed.FS

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:8787", "listen address (127.0.0.1 only)")
		tokenFile    = flag.String("token-file", "", "path to a file containing the auth token (preferred over argv; default: TF_WEB_TOKEN env or random)")
		tfPath       = flag.String("tf", "t-forward", "path to the t-forward CLI")
		configDir    = flag.String("config-dir", defaultConfigDir(), "t-forward config directory")
		noAuth       = flag.Bool("no-auth", false, "disable the token check entirely — ONLY safe when bound to a trusted private address (e.g. a tailnet IP), since anyone who can reach it gets full control")
		expose       = flag.Bool("expose", false, "permit -no-auth on a non-loopback bind (DANGEROUS: full control to anyone who can reach the address)")
		allowedHosts = flag.String("allowed-hosts", "", "extra comma-separated Host header values to accept, besides loopback / the bind host / IP literals (DNS-rebinding guard)")
		allowTotpCmd = flag.Bool("allow-totp-command", envBool("TF_ALLOW_TOTP_COMMAND"), "permit a tunnel's totp_command to be auto-executed (sh -c) to fetch a code; OFF by default because it is arbitrary command execution as the daemon user")
	)
	flag.Parse()

	// -no-auth serves full control to anyone who can reach the socket. On a
	// non-loopback bind that is the whole network, so require an explicit -expose
	// acknowledgement rather than let a stray flag silently expose the host.
	if *noAuth && !isLoopbackHost(hostOnly(*addr)) && !*expose {
		log.Fatalf("-no-auth on a non-loopback address (%s) exposes full control to the network; re-run with -expose to confirm you intend this", *addr)
	}

	// Load the token WITHOUT ever accepting it as a literal flag value: a flag
	// value is world-readable on Linux via /proc/<pid>/cmdline and `ps -ww`, so
	// the sole auth secret would leak to any local user. Prefer TF_WEB_TOKEN,
	// then a file whose contents (not path) hold the secret, then a random one.
	tok := os.Getenv("TF_WEB_TOKEN")
	if tok == "" && *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil && !*noAuth {
			log.Fatalf("read token-file: %v", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	generated := false
	if tok == "" && !*noAuth {
		tok = randomToken()
		generated = true
	}

	panel, err := panelFS.ReadFile("panel/index.html")
	if err != nil {
		log.Fatalf("embed panel: %v", err)
	}

	hub := NewHub()
	dock := NewDocker(hub, *configDir, *tfPath)
	dock.allowTotpCmd = *allowTotpCmd
	scanner := NewScanner(hub, *configDir)
	hub.SnapshotFn = func() (string, any) { return "state", dock.State() }
	acts := NewActions(hub, dock, scanner, *tfPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Never leak the ?token= query string via the Referer header when the
		// panel navigates or loads subresources.
		w.Header().Set("Referrer-Policy", "no-referrer")
		// The panel is rebuilt with the daemon; never let the browser serve a
		// stale cached copy after an upgrade.
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		// The panel is reached once through /?token=<tok>; hand the secret off to a
		// SameSite=Strict, HttpOnly cookie so every SUBSEQUENT request (SSE, polling,
		// actions) authenticates via the cookie instead of a ?token= query string.
		// That keeps the token out of per-request URLs (browser history, proxy logs)
		// and — being SameSite=Strict — is never attached to a cross-site request.
		if !*noAuth {
			http.SetCookie(w, &http.Cookie{
				Name:     "tf_token",
				Value:    tok,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		_, _ = w.Write(panel)
	})
	mux.HandleFunc("/events", hub.ServeHTTP)
	mux.HandleFunc("/evlog", hub.ServeEvLog)
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, dock.State())
	})
	mux.HandleFunc("/up", acts.handleUp)
	mux.HandleFunc("/down", acts.handleDown)
	mux.HandleFunc("/code", acts.handleCode)
	mux.HandleFunc("/totp/", acts.handleTotp)
	mux.HandleFunc("/conf/", acts.handleConf)
	mux.HandleFunc("/scan", acts.handleScan)
	mux.HandleFunc("/scan/rescan", acts.handleScanRescan)
	mux.HandleFunc("/scan/forward", acts.handleScanForward)
	mux.HandleFunc("/scan/device", acts.handleScanDevice)

	var handler http.Handler = mux
	if !*noAuth {
		handler = tokenMiddleware(tok, mux)
	}
	// Outermost guard (runs even under -no-auth): reject DNS-rebinding Host values
	// and browser-reported cross-site requests, so a malicious web page the operator
	// visits cannot drive this loopback daemon.
	handler = guardMiddleware(hostOnly(*addr), splitComma(*allowedHosts), handler)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// background live readers
	go dock.StatsLoop(ctx)
	go dock.EventsLoop(ctx)
	go dock.WaitingLoop(ctx)
	go dock.StateLoop(ctx)
	go dock.ClientsLoop(ctx)
	go dock.HostPingLoop(ctx)
	go scanner.Loop(ctx)

	srv := &http.Server{Addr: *addr, Handler: handler}

	// startup banner
	if *noAuth {
		fmt.Printf("t-forward web daemon on http://%s (NO AUTH — anyone who can reach this address has full control)\n", *addr)
	} else if generated {
		if stdoutIsTTY() {
			fmt.Printf("t-forward web daemon on http://%s\n", *addr)
			fmt.Printf("open: http://%s/?token=%s\n", *addr, tok)
		} else {
			// Not a terminal (e.g. under systemd → journal, readable by the
			// systemd-journal/adm group). Never persist the secret to a log;
			// emit only a short fingerprint for correlation. Operators running
			// as a service should set TF_WEB_TOKEN or -token-file instead.
			fmt.Printf("t-forward web daemon on http://%s (auto-generated token fp=%s; not printed: stdout is not a TTY, set TF_WEB_TOKEN)\n", *addr, tokenFingerprint(tok))
		}
	} else {
		fmt.Printf("t-forward web daemon on http://%s (token set)\n", *addr)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	stop()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func defaultConfigDir() string {
	if v := os.Getenv("T_FORWARD_CONFIG_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".config/t-forward"
	}
	return filepath.Join(home, ".config", "t-forward")
}

// stdoutIsTTY reports whether stdout is an interactive terminal. Under a service
// manager (systemd, etc.) stdout is a pipe/file, so this is false and we avoid
// writing the secret token to a persisted journal.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// tokenFingerprint returns a short, non-reversible identifier for a token so it
// can be correlated in logs without exposing the secret itself.
func tokenFingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:4])
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// tokenMiddleware enforces a constant-time token check on every route. The
// token may arrive as an Authorization: Bearer header, an X-Token header, or
// ?token= as a fallback. Headers are preferred and should be used by API
// callers. The ?token= form is retained only because browsers (initial panel
// load) and EventSource/SSE cannot set request headers; because a query string
// can land in browser history and proxy access logs, the daemon must remain
// bound to 127.0.0.1 and must never be fronted by a logging reverse proxy.
func tokenMiddleware(want string, next http.Handler) http.Handler {
	wantB := []byte(want)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got string
		if h := r.Header.Get("Authorization"); h != "" {
			got = trimBearer(h)
		}
		if got == "" {
			got = r.Header.Get("X-Token")
		}
		// Cookie carries the token on every request after the initial panel load
		// (set by the / handler), so SSE/polling/actions need no ?token= in the URL.
		if got == "" {
			if ck, err := r.Cookie("tf_token"); err == nil {
				got = ck.Value
			}
		}
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), wantB) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guardMiddleware defends the loopback daemon against being driven by a web page
// the operator happens to visit. Two checks, both browser-supplied:
//
//   - Sec-Fetch-Site: modern browsers stamp cross-origin requests "cross-site";
//     rejecting those blocks a malicious site's scripted fetch/XHR even under
//     -no-auth. Only a top-level *GET/HEAD* navigation (Sec-Fetch-Mode: navigate)
//     is exempt, so the operator can still click the /?token= link from anywhere
//     (a chat app, the terminal); a cross-site navigation with an unsafe method
//     (a forged <form method=POST> submit) is NOT exempt — that is the CSRF
//     vector. Non-browser clients (curl) omit the header and pass through (they
//     still face the token check).
//   - Content-Type on state-changing methods: a browser <form> can only send
//     text/plain, urlencoded, or multipart — never application/json — so
//     requiring JSON on POST/PUT/DELETE blocks a forged cross-site form even on
//     older browsers that don't send Sec-Fetch headers. The panel always sends
//     application/json; curl callers must too.
//   - Host allowlist: a DNS-rebinding attack reaches 127.0.0.1 through a rogue
//     *hostname*, so the Host header is that hostname — never loopback nor an IP
//     literal. Accepting only loopback names, the configured bind host, IP-literal
//     Hosts, and any operator-listed names rejects the rebind.
func guardMiddleware(bindHost string, extra []string, next http.Handler) http.Handler {
	allow := map[string]bool{"localhost": true}
	if bindHost != "" && bindHost != "0.0.0.0" && bindHost != "::" {
		allow[strings.ToLower(bindHost)] = true
	}
	for _, h := range extra {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			allow[h] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		safeMethod := r.Method == http.MethodGet || r.Method == http.MethodHead
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			// exempt ONLY a safe-method top-level navigation (clicking the
			// /?token= link); a cross-site POST/etc — scripted or a forged
			// form submit — is always blocked.
			navOK := safeMethod && r.Header.Get("Sec-Fetch-Mode") == "navigate"
			if !navOK {
				http.Error(w, "cross-site request blocked", http.StatusForbidden)
				return
			}
		}
		// Defense in depth (covers browsers that omit Sec-Fetch): a state-changing
		// request must be application/json, which a cross-site <form> can never be.
		if !safeMethod && r.Method != http.MethodOptions {
			ct := r.Header.Get("Content-Type")
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
				http.Error(w, "unsupported media type: send application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		if !hostAllowed(strings.ToLower(hostOnly(r.Host)), allow) {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostAllowed(host string, allow map[string]bool) bool {
	if host == "" { // HTTP/1.0 / some non-browser clients omit Host
		return true
	}
	if allow[host] || isLoopbackHost(host) {
		return true
	}
	// An IP-literal Host cannot be the target of DNS rebinding (rebinding needs a
	// name that re-resolves), so it is safe to accept regardless of which IP.
	return net.ParseIP(host) != nil
}

// hostOnly strips an optional :port from a host[:port] string.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// isLoopbackHost reports whether h is localhost or a loopback IP literal.
func isLoopbackHost(h string) bool {
	if h == "" || strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func trimBearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && (h[:len(p)] == p || h[:len(p)] == "bearer ") {
		return h[len(p):]
	}
	return h
}
