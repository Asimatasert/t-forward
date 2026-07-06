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
		addr      = flag.String("addr", "127.0.0.1:8787", "listen address (127.0.0.1 only)")
		tokenFile = flag.String("token-file", "", "path to a file containing the auth token (preferred over argv; default: TF_WEB_TOKEN env or random)")
		tfPath    = flag.String("tf", "t-forward", "path to the t-forward CLI")
		configDir = flag.String("config-dir", defaultConfigDir(), "t-forward config directory")
		noAuth    = flag.Bool("no-auth", false, "disable the token check entirely — ONLY safe when bound to a trusted private address (e.g. a tailnet IP), since anyone who can reach it gets full control")
	)
	flag.Parse()

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

func trimBearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && (h[:len(p)] == p || h[:len(p)] == "bearer ") {
		return h[len(p):]
	}
	return h
}
