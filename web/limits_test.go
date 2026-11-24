package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveEventsCancelled opens /events with an already-cancelled request context
// so an accepted stream returns right after its first frame.
func serveEventsCancelled(h *Hub) *httptest.ResponseRecorder {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEventStreamsAreCapped(t *testing.T) {
	h := NewHub()
	h.SnapshotFn = func() (string, any) { return "state", map[string]any{} }

	// Far more registered streams than any cap could sensibly be.
	const flood = 1000
	h.mu.Lock()
	fake := make([]*client, 0, flood)
	for i := 0; i < flood; i++ {
		c := &client{lossy: make(chan []byte, 1), state: make(chan []byte, 1)}
		h.clients[c] = struct{}{}
		fake = append(fake, c)
	}
	h.mu.Unlock()

	rec := serveEventsCancelled(h)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with %d open streams = %d, want 503", flood, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 carries no Retry-After header")
	}
	if got := clientCount(h); got != flood {
		t.Errorf("refused stream changed the client count: %d, want %d", got, flood)
	}

	// Closing streams frees capacity again.
	h.mu.Lock()
	for _, c := range fake {
		delete(h.clients, c)
	}
	h.mu.Unlock()
	if rec := serveEventsCancelled(h); rec.Code != http.StatusOK {
		t.Fatalf("status after streams closed = %d, want 200", rec.Code)
	}
	if got := clientCount(h); got != 0 {
		t.Errorf("served stream left %d clients registered", got)
	}
}

func TestEventStreamsBelowCapAreAccepted(t *testing.T) {
	h := NewHub()
	h.SnapshotFn = func() (string, any) { return "state", map[string]any{} }
	h.mu.Lock()
	for i := 0; i < 16; i++ { // a busy operator: many tabs
		h.clients[&client{lossy: make(chan []byte, 1), state: make(chan []byte, 1)}] = struct{}{}
	}
	h.mu.Unlock()
	if rec := serveEventsCancelled(h); rec.Code != http.StatusOK {
		t.Fatalf("status with 16 open streams = %d, want 200", rec.Code)
	}
}

// A slow stub CLI that records each start, so the test can see how many CLI
// processes run at once.
func TestConcurrentCLIRunsAreBounded(t *testing.T) {
	e := newActEnv(t)
	logFile := filepath.Join(t.TempDir(), "starts.log")
	e.a.tfPath = writeStubCLI(t, fmt.Sprintf("echo \"$*\" >> %q\nsleep 2\n", logFile))

	const burst = 40
	codes := make([]int, burst)
	retry := make([]string, burst)
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := doReq(e.a.handleUp, http.MethodPost, "/up", fmt.Sprintf(`{"name":"t%d"}`, i))
			codes[i] = rec.Code
			retry[i] = rec.Header().Get("Retry-After")
		}(i)
	}
	// Let the accepted runs start while all of them are still sleeping.
	time.Sleep(1 * time.Second)
	started := len(calls(t, logFile))
	wg.Wait()

	if started > 16 { // the cap (8) is far below the burst
		t.Fatalf("%d CLI runs were in flight at once for a burst of %d", started, burst)
	}
	var ok, busy int
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			busy++
			if retry[i] == "" {
				t.Error("429 carries no Retry-After header")
			}
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if busy == 0 {
		t.Errorf("no request was refused out of a burst of %d (ok=%d)", burst, ok)
	}
	if ok == 0 {
		t.Error("every request was refused")
	}
	if ok != started {
		t.Errorf("accepted %d requests but %d CLI runs started", ok, started)
	}
}

func TestCLIRunSlotsAreReleased(t *testing.T) {
	const runBurst = 8 // the per-daemon cap
	e := newActEnv(t)
	logFile := e.useStubCLI(t, 0)
	// Far more sequential runs than slots: each must give its slot back.
	for i := 0; i < 3*runBurst; i++ {
		rec := doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("run %d: status %d, body %s", i, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	for i := 0; i < 3*runBurst; i++ {
		if rec := doReq(e.a.handleDown, http.MethodPost, "/down", `{"name":"prod"}`); rec.Code != http.StatusOK {
			t.Fatalf("down %d: status %d", i, rec.Code)
		}
		if rec := doReq(e.a.handleCode, http.MethodPost, "/code", `{"name":"prod","code":"123456"}`); rec.Code != http.StatusOK {
			t.Fatalf("code %d: status %d", i, rec.Code)
		}
	}
	if n := len(calls(t, logFile)); n != 9*runBurst {
		t.Errorf("CLI ran %d times, want %d", n, 9*runBurst)
	}
}
