package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// clientCount returns the number of registered clients under the hub lock.
func clientCount(h *Hub) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// waitClients polls until the hub has exactly n clients or the deadline hits.
func waitClients(t *testing.T, h *Hub, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if clientCount(h) == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("hub clients = %d, want %d", clientCount(h), n)
}

func TestFrame(t *testing.T) {
	tests := []struct {
		name    string
		typ     string
		payload any
		want    string
	}{
		{"map", "stat", map[string]int{"a": 1}, "event: stat\ndata: {\"a\":1}\n\n"},
		{"string", "event", "hi", "event: event\ndata: \"hi\"\n\n"},
		{"nil", "state", nil, "event: state\ndata: null\n\n"},
		{"slice", "state", []string{"x", "y"}, "event: state\ndata: [\"x\",\"y\"]\n\n"},
		// json.Marshal fails on a channel: the frame must degrade to null
		// instead of panicking or emitting a broken frame.
		{"unmarshalable", "stat", make(chan int), "event: stat\ndata: null\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(frame(tc.typ, tc.payload)); got != tc.want {
				t.Fatalf("frame = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushStateCoalescesLatest(t *testing.T) {
	ch := make(chan []byte, 1)
	pushState(ch, []byte("one"))
	pushState(ch, []byte("two"))
	pushState(ch, []byte("three"))
	if len(ch) != 1 {
		t.Fatalf("slot len = %d, want 1", len(ch))
	}
	if got := string(<-ch); got != "three" {
		t.Fatalf("slot = %q, want latest (three)", got)
	}
	// Empty slot accepts a frame again.
	pushState(ch, []byte("four"))
	if got := string(<-ch); got != "four" {
		t.Fatalf("slot = %q, want four", got)
	}
}

func TestHubRegisterUnregister(t *testing.T) {
	h := NewHub()
	if n := clientCount(h); n != 0 {
		t.Fatalf("new hub has %d clients", n)
	}
	a, b := h.register(), h.register()
	if a == b {
		t.Fatal("register returned the same client twice")
	}
	if cap(a.lossy) != 64 || cap(a.state) != 1 {
		t.Fatalf("client buffers = lossy %d state %d, want 64/1", cap(a.lossy), cap(a.state))
	}
	if n := clientCount(h); n != 2 {
		t.Fatalf("clients = %d, want 2", n)
	}
	h.unregister(a)
	if n := clientCount(h); n != 1 {
		t.Fatalf("clients after unregister = %d, want 1", n)
	}
	h.unregister(a) // idempotent
	h.unregister(b)
	if n := clientCount(h); n != 0 {
		t.Fatalf("clients after all unregistered = %d", n)
	}
	h.Broadcast("stat", 1) // no clients: must not panic or block
}

func TestBroadcastRouting(t *testing.T) {
	tests := []struct {
		name      string
		typ       string
		wantState bool // frame lands in the reliable state slot
		wantLossy bool // frame lands in the lossy buffer
	}{
		{"state is reliable only", "state", true, false},
		{"stat is lossy only", "stat", false, true},
		{"event is lossy only", "event", false, true},
		{"unknown type is lossy", "hosts", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHub()
			c := h.register()
			h.Broadcast(tc.typ, map[string]any{"k": "v"})
			if got := len(c.state) == 1; got != tc.wantState {
				t.Errorf("state slot filled = %v, want %v", got, tc.wantState)
			}
			if got := len(c.lossy) == 1; got != tc.wantLossy {
				t.Errorf("lossy filled = %v, want %v", got, tc.wantLossy)
			}
			var f []byte
			if tc.wantState {
				f = <-c.state
			} else {
				f = <-c.lossy
			}
			if want := "event: " + tc.typ + "\n"; !strings.HasPrefix(string(f), want) {
				t.Errorf("frame %q lacks prefix %q", f, want)
			}
		})
	}
}

func TestBroadcastFansOutToAllClients(t *testing.T) {
	h := NewHub()
	cs := []*client{h.register(), h.register(), h.register()}
	h.Broadcast("stat", "x")
	for i, c := range cs {
		select {
		case f := <-c.lossy:
			if string(f) != "event: stat\ndata: \"x\"\n\n" {
				t.Errorf("client %d got %q", i, f)
			}
		default:
			t.Errorf("client %d got nothing", i)
		}
	}
	// An unregistered client no longer receives frames.
	h.unregister(cs[0])
	h.Broadcast("stat", "y")
	if len(cs[0].lossy) != 0 {
		t.Error("unregistered client still received a frame")
	}
	if len(cs[1].lossy) != 1 || len(cs[2].lossy) != 1 {
		t.Error("remaining clients missed the frame")
	}
}

// A client that never reads must neither block Broadcast nor starve the other
// clients: lossy frames are dropped beyond the buffer, state frames coalesce.
func TestSlowClientDoesNotBlockOthers(t *testing.T) {
	h := NewHub()
	slow, fast := h.register(), h.register()

	const n = 500
	done := make(chan struct{})
	var got []string
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			h.Broadcast("stat", i)
			// drain the fast client synchronously after every frame
			select {
			case f := <-fast.lossy:
				got = append(got, string(f))
			default:
				t.Errorf("fast client missed frame %d", i)
				return
			}
		}
		for i := 0; i < 5; i++ {
			h.Broadcast("state", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Broadcast blocked on a slow client")
	}

	if len(got) != n {
		t.Fatalf("fast client received %d frames, want %d", len(got), n)
	}
	if want := "event: stat\ndata: 0\n\n"; got[0] != want {
		t.Errorf("first fast frame = %q, want %q", got[0], want)
	}
	if want := "event: stat\ndata: 499\n\n"; got[n-1] != want {
		t.Errorf("last fast frame = %q, want %q", got[n-1], want)
	}
	// slow client: buffer is full and holds the OLDEST frames (newer dropped)
	if len(slow.lossy) != cap(slow.lossy) {
		t.Errorf("slow lossy len = %d, want full (%d)", len(slow.lossy), cap(slow.lossy))
	}
	if first := string(<-slow.lossy); first != "event: stat\ndata: 0\n\n" {
		t.Errorf("slow client first frame = %q", first)
	}
	// slow client's state slot holds only the newest snapshot
	if len(slow.state) != 1 {
		t.Fatalf("slow state slot len = %d, want 1", len(slow.state))
	}
	if st := string(<-slow.state); st != "event: state\ndata: 4\n\n" {
		t.Errorf("slow client state = %q, want latest (4)", st)
	}
}

func TestEventRingAndEvLog(t *testing.T) {
	h := NewHub()
	for i := 1; i <= 3; i++ {
		h.Broadcast("event", map[string]any{"msg": i})
	}
	// non-event frames are never recorded
	h.Broadcast("stat", map[string]any{"msg": "stat"})
	h.Broadcast("state", map[string]any{"msg": "state"})

	type resp struct {
		Seq    int64 `json:"seq"`
		Events []struct {
			Seq int64          `json:"seq"`
			Ev  map[string]any `json:"ev"`
		} `json:"events"`
	}
	get := func(t *testing.T, query string) resp {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeEvLog(rec, httptest.NewRequest(http.MethodGet, "/evlog"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		var r resp
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		return r
	}

	tests := []struct {
		name     string
		query    string
		wantSeqs []int64
	}{
		{"no since returns all", "", []int64{1, 2, 3}},
		{"since 0", "?since=0", []int64{1, 2, 3}},
		{"since 1", "?since=1", []int64{2, 3}},
		{"since current returns none", "?since=3", nil},
		{"since beyond returns none", "?since=99", nil},
		{"garbage since falls back to 0", "?since=abc", []int64{1, 2, 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := get(t, tc.query)
			if r.Seq != 3 {
				t.Errorf("seq = %d, want 3", r.Seq)
			}
			var seqs []int64
			for _, e := range r.Events {
				seqs = append(seqs, e.Seq)
			}
			if len(seqs) != len(tc.wantSeqs) {
				t.Fatalf("seqs = %v, want %v", seqs, tc.wantSeqs)
			}
			for i := range seqs {
				if seqs[i] != tc.wantSeqs[i] {
					t.Fatalf("seqs = %v, want %v", seqs, tc.wantSeqs)
				}
			}
		})
	}

	// The seq is also stamped into the live SSE payload so a client can
	// advance its /evlog cursor and not re-render duplicates after fallback.
	c := h.register()
	h.Broadcast("event", map[string]any{"msg": "live"})
	f := string(<-c.lossy)
	if !strings.Contains(f, `"seq":4`) {
		t.Errorf("live event frame %q lacks seq 4", f)
	}

	// Empty log serialises events as [] (not null) so JS clients can iterate.
	empty := NewHub()
	rec := httptest.NewRecorder()
	empty.ServeEvLog(rec, httptest.NewRequest(http.MethodGet, "/evlog", nil))
	if !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Errorf("empty evlog = %q, want events:[]", rec.Body.String())
	}
}

func TestEventRingBounded(t *testing.T) {
	h := NewHub()
	total := evCap + 10
	for i := 0; i < total; i++ {
		h.Broadcast("event", map[string]any{"i": i})
	}
	h.evMu.Lock()
	defer h.evMu.Unlock()
	if len(h.evRing) != evCap {
		t.Fatalf("ring len = %d, want %d", len(h.evRing), evCap)
	}
	if h.evRing[0].Seq != int64(total-evCap+1) || h.evRing[len(h.evRing)-1].Seq != int64(total) {
		t.Fatalf("ring seq range = %d..%d, want %d..%d",
			h.evRing[0].Seq, h.evRing[len(h.evRing)-1].Seq, total-evCap+1, total)
	}
	if h.evSeq != int64(total) {
		t.Fatalf("evSeq = %d, want %d", h.evSeq, total)
	}
}

// A non-map event payload is still recorded, just without a stamped seq.
func TestEventNonMapPayload(t *testing.T) {
	h := NewHub()
	c := h.register()
	h.Broadcast("event", "plain text")
	if f := string(<-c.lossy); f != "event: event\ndata: \"plain text\"\n\n" {
		t.Fatalf("frame = %q", f)
	}
	if h.evSeq != 1 || len(h.evRing) != 1 {
		t.Fatalf("evSeq=%d ring=%d, want 1/1", h.evSeq, len(h.evRing))
	}
}

func TestBroadcastConcurrent(t *testing.T) {
	h := NewHub()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c := h.register()
				h.Broadcast("stat", j)
				h.unregister(c)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Broadcast("state", j)
				h.Broadcast("event", map[string]any{"j": j})
			}
		}()
	}
	wg.Wait()
	if n := clientCount(h); n != 0 {
		t.Fatalf("leaked %d clients", n)
	}
}

// readFrame reads one SSE frame ("event:" + "data:" lines) from r.
func readFrame(t *testing.T, r *bufio.Reader) (typ, data string) {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			return typ, data
		case strings.HasPrefix(line, "event: "):
			typ = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func TestServeHTTPStreamAndCleanup(t *testing.T) {
	h := NewHub()
	h.SnapshotFn = func() (string, any) { return "state", []string{"snap"} }
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"Connection":        "keep-alive",
		"X-Accel-Buffering": "no",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}

	br := bufio.NewReader(resp.Body)
	// 1) the connect-time snapshot
	if typ, data := readFrame(t, br); typ != "state" || data != `["snap"]` {
		t.Fatalf("snapshot = %q %q", typ, data)
	}
	// 2) live broadcasts reach the connected client
	waitClients(t, h, 1)
	h.Broadcast("stat", map[string]int{"rx": 7})
	if typ, data := readFrame(t, br); typ != "stat" || data != `{"rx":7}` {
		t.Fatalf("stat frame = %q %q", typ, data)
	}
	h.Broadcast("state", []string{"new"})
	if typ, data := readFrame(t, br); typ != "state" || data != `["new"]` {
		t.Fatalf("state frame = %q %q", typ, data)
	}

	// 3) closing the connection unregisters the client
	cancel()
	waitClients(t, h, 0)
}

func TestServeHTTPMultipleClientsCleanup(t *testing.T) {
	h := NewHub() // nil SnapshotFn: no snapshot frame
	srv := httptest.NewServer(h)
	defer srv.Close()

	const n = 3
	cancels := make([]context.CancelFunc, n)
	readers := make([]*bufio.Reader, n)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		readers[i] = bufio.NewReader(resp.Body)
	}
	waitClients(t, h, n)

	h.Broadcast("stat", "all")
	for i, r := range readers {
		if typ, data := readFrame(t, r); typ != "stat" || data != `"all"` {
			t.Fatalf("client %d got %q %q", i, typ, data)
		}
	}

	// Dropping one client leaves the others working.
	cancels[0]()
	waitClients(t, h, n-1)
	h.Broadcast("stat", "rest")
	for i := 1; i < n; i++ {
		if typ, data := readFrame(t, readers[i]); typ != "stat" || data != `"rest"` {
			t.Fatalf("client %d got %q %q", i, typ, data)
		}
	}
	cancels[1]()
	cancels[2]()
	waitClients(t, h, 0)
}

// noFlushWriter is a ResponseWriter that does not implement http.Flusher.
type noFlushWriter struct {
	hdr  http.Header
	code int
	buf  bytes.Buffer
}

func (w *noFlushWriter) Header() http.Header         { return w.hdr }
func (w *noFlushWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *noFlushWriter) WriteHeader(code int)        { w.code = code }

func TestServeHTTPRequiresFlusher(t *testing.T) {
	h := NewHub()
	w := &noFlushWriter{hdr: http.Header{}}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/events", nil))
	if w.code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.code)
	}
	if !strings.Contains(w.buf.String(), "streaming unsupported") {
		t.Fatalf("body = %q", w.buf.String())
	}
	if n := clientCount(h); n != 0 {
		t.Fatalf("client registered despite 500: %d", n)
	}
}

// gateWriter blocks inside its first body Write until released, so a test can
// queue frames behind a busy writer and observe the order they drain in.
type gateWriter struct {
	hdr     http.Header
	mu      sync.Mutex
	buf     bytes.Buffer
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (w *gateWriter) Header() http.Header { return w.hdr }
func (w *gateWriter) WriteHeader(int)     {}
func (w *gateWriter) Flush()              {}
func (w *gateWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.release
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
func (w *gateWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Pending 'state' frames are written before queued stat/event backlog, so a
// state transition is never masked by lossy traffic.
func TestServeHTTPPrioritisesState(t *testing.T) {
	h := NewHub()
	w := &gateWriter{hdr: http.Header{}, started: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, req)
	}()
	waitClients(t, h, 1)

	h.Broadcast("stat", "A") // taken by the loop; its Write blocks on the gate
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("writer never started")
	}
	h.Broadcast("stat", "B")
	h.Broadcast("stat", "C")
	h.Broadcast("state", "S")
	close(w.release)

	want := "event: stat\ndata: \"A\"\n\n" +
		"event: state\ndata: \"S\"\n\n" +
		"event: stat\ndata: \"B\"\n\n" +
		"event: stat\ndata: \"C\"\n\n"
	deadline := time.Now().Add(5 * time.Second)
	for w.String() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := w.String(); got != want {
		t.Fatalf("write order:\n got %q\nwant %q", got, want)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP did not return after context cancel")
	}
	if n := clientCount(h); n != 0 {
		t.Fatalf("client leaked after cancel: %d", n)
	}
}
