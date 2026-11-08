package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the background loops of Docker (StateLoop, StatsLoop, EventsLoop,
// WaitingLoop, ClientsLoop, HostPingLoop). They run the real loop against the
// POSIX-sh docker/lsof/arp/yq stubs from docker_parse_test.go (no docker, no
// network beyond loopback) and stop it by cancelling the context. The loops are
// driven by 1-3 s timers, so each test costs a few seconds of wall clock.

// dlRun starts fn(ctx) in a goroutine and returns a stop func that cancels the
// context and fails the test when the loop does not return promptly.
func dlRun(t *testing.T, fn func(ctx context.Context)) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(ctx)
	}()
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("loop did not return after its context was cancelled")
		}
	}
	t.Cleanup(stop)
	return stop
}

// dlFrames collects the frames of one SSE event type from a client's lossy
// channel as they arrive.
type dlFrames struct {
	c    *client
	head string
	got  []string
}

func newDLFrames(c *client, eventType string) *dlFrames {
	return &dlFrames{c: c, head: "event: " + eventType + "\ndata: "}
}

func (f *dlFrames) drain() []string {
	for {
		select {
		case b := <-f.c.lossy:
			if s := string(b); strings.HasPrefix(s, f.head) {
				f.got = append(f.got, strings.TrimSuffix(strings.TrimPrefix(s, f.head), "\n\n"))
			}
		default:
			return f.got
		}
	}
}

func (f *dlFrames) waitFor(t *testing.T, what string, cond func(all []string) bool) {
	t.Helper()
	dpWait(t, what, func() bool { return cond(f.drain()) })
}

func dlHas(all []string, parts ...string) bool {
next:
	for _, s := range all {
		for _, p := range parts {
			if !strings.Contains(s, p) {
				continue next
			}
		}
		return true
	}
	return false
}

func TestDLStateLoopBroadcastsOnTick(t *testing.T) {
	dpTools(t) // docker ps fails -> State() falls back to the confs; fine for a heartbeat
	d, _ := newTestDocker(t)
	dpConf(t, d, "alpha", `{"name":"Alpha"}`)
	cl := d.hub.register()
	stop := dlRun(t, d.StateLoop)

	select {
	case b := <-cl.state:
		if s := string(b); !strings.HasPrefix(s, "event: state\n") || !strings.Contains(s, `"id":"alpha"`) {
			t.Fatalf("heartbeat frame = %q", s)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no state heartbeat within 8s (tick is 5s)")
	}
	stop()
}

func TestDLStateLoopStopsOnCancelledContext(t *testing.T) {
	dpTools(t)
	d, _ := newTestDocker(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() { d.StateLoop(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StateLoop ignored a cancelled context")
	}
}

func TestDLStatsLoopSamplesRepeatedlyAndStops(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	dpOut(t, dir, "stats", dpStat("tf-alpha", "1kB / 2kB"), 0)
	stop := dlRun(t, d.StatsLoop)

	// the loop samples once a second: a second `docker stats` proves it iterates
	dpWait(t, "two samples", func() bool { return dpCount(dir, "docker stats") >= 2 })
	stop()
	n := dpCount(dir, "docker stats")
	time.Sleep(1200 * time.Millisecond)
	if got := dpCount(dir, "docker stats"); got != n {
		t.Errorf("StatsLoop kept sampling after cancel: %d -> %d", n, got)
	}

	// an already-cancelled context returns before the first sample
	before := dpCount(dir, "docker ps")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d.StatsLoop(ctx)
	if got := dpCount(dir, "docker ps"); got != before {
		t.Errorf("cancelled StatsLoop still sampled (%d -> %d docker ps calls)", before, got)
	}
}

func TestDLEventsLoopAttachesTailersAndReconnects(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	cl := d.hub.register()
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	dpOut(t, dir, "logs", "2026-11-07T10:00:00Z tunnel is up\n", 0)
	dpOut(t, dir, "events", dpEv("start", "tf-alpha", "alpha"), 0)
	stop := dlRun(t, d.EventsLoop)

	// connect: initial state broadcast, tailer attached to the running container
	dpWait(t, "tailer log line", func() bool { return hasMsg(d.hub, "tunnel is up") })
	dpWait(t, "docker events", func() bool { return dpCount(dir, "docker events") >= 1 })
	select {
	case <-cl.state:
	case <-time.After(5 * time.Second):
		t.Fatal("EventsLoop never broadcast the state")
	}
	// the stub's `docker events` exits at once: after the 2s back-off the loop reconnects
	dpWait(t, "reconnect after back-off", func() bool { return dpCount(dir, "docker events") >= 2 })
	stop()
}

func hasMsg(h *Hub, msg string) bool {
	for _, e := range dpEvents(h) {
		if e["msg"] == msg {
			return true
		}
	}
	return false
}

func TestDLEventsLoopCancelledContextReturns(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() { d.EventsLoop(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("EventsLoop ignored a cancelled context")
	}
	if n := dpCount(dir, "docker events"); n != 0 {
		t.Errorf("docker events started %d times for a cancelled context", n)
	}
}

func dlWaitDirs(t *testing.T, d *Docker, spec map[string][]string) {
	t.Helper()
	for dir, files := range spec {
		p := filepath.Join(d.stateDir, dir)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(p, f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDLWaitingLoopAnnouncesLiveWaitsOnly(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "alpha", `{"name":"Alpha"}`)
	dpConf(t, d, "stale", `{"name":"Stale"}`) // configured, container not running
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	cl := d.hub.register()
	waiting := newDLFrames(cl, "waiting")
	d.armed["old-tunnel"] = true // no longer waiting: its arming state must be forgotten

	// stateDir does not exist yet: the loop must survive the ReadDir error
	stop := dlRun(t, d.WaitingLoop)
	time.Sleep(1300 * time.Millisecond)
	if got := waiting.drain(); len(got) != 0 {
		t.Fatalf("announced a wait with no auth dirs: %v", got)
	}

	dlWaitDirs(t, d, map[string][]string{
		"auth-alpha":  {"awaiting_code"},          // live wait: container running + marker
		"auth-ghost":  {"awaiting_code"},          // stale marker, no such tunnel in state
		"auth-stale":  {"awaiting_code"},          // stale marker, tunnel known but its container is down
		"auth-done":   {"awaiting_code", "ready"}, // already answered
		"auth-nomark": nil,                        // auth dir without a marker
		"other-dir":   {"awaiting_code"},          // not an auth- dir
	})
	if err := os.WriteFile(filepath.Join(d.stateDir, "auth-afile"), nil, 0o600); err != nil { // a file, not a dir
		t.Fatal(err)
	}

	waiting.waitFor(t, "waiting frame for alpha", func(all []string) bool { return dlHas(all, `"tun":"alpha"`) })
	time.Sleep(1200 * time.Millisecond) // one more tick: still only alpha
	for _, f := range waiting.drain() {
		if !strings.Contains(f, `"tun":"alpha"`) {
			t.Errorf("announced a wait that is not live: %s", f)
		}
	}
	dpWait(t, "stale armed entry dropped", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		_, ok := d.armed["old-tunnel"]
		return !ok
	})
	stop()
}

func TestDLClientsLoopReportsPeersAndRelogsAfterReconnect(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "alpha", `{"name":"Alpha","hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":8023}]}]}`)
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	dpOut(t, dir, "lsof", dpLsof, 0)
	dpOut(t, dir, "arp", "? (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n", 0)
	cl := d.hub.register()
	clients := newDLFrames(cl, "clients")
	stop := dlRun(t, d.ClientsLoop)

	clients.waitFor(t, "clients frame", func(all []string) bool {
		return dlHas(all, `"tun":"alpha"`, "192.168.1.50", "aa:bb:cc:dd:ee:ff")
	})
	if !dpHasEvent(d.hub, "conn", "client 192.168.1.50 [aa:bb:cc:dd:ee:ff] -> localhost:8023") {
		t.Errorf("no MAC-labelled conn event: %v", dpEvents(d.hub))
	}
	if !dpHasEvent(d.hub, "conn", "client 127.0.0.1 (ssh) -> localhost:8023") {
		t.Errorf("no process-labelled conn event: %v", dpEvents(d.hub))
	}
	d.mu.Lock()
	ld := d.live["alpha"]
	d.mu.Unlock()
	if ld == nil || len(ld.clients) == 0 {
		t.Fatalf("live clients not stored: %+v", ld)
	}
	connsFrom := func(ip string) int {
		c := 0
		for _, e := range dpEvents(d.hub) {
			if e["level"] == "conn" && strings.Contains(fmt.Sprint(e["msg"]), "client "+ip) {
				c++
			}
		}
		return c
	}
	if n := connsFrom("192.168.1.50"); n != 1 {
		t.Fatalf("192.168.1.50 logged %d times on the first tick, want once", n)
	}

	// peers disappear -> forgotten; they come back -> logged again
	dpOut(t, dir, "lsof", "", 0) // nobody connected any more
	n := dpCount(dir, "lsof")
	dpWait(t, "an idle tick", func() bool { return dpCount(dir, "lsof") > n })
	time.Sleep(400 * time.Millisecond) // let that tick finish before the peers return
	dpOut(t, dir, "lsof", dpLsof, 0)
	dpWait(t, "peer logged again after reconnect", func() bool { return connsFrom("192.168.1.50") == 2 })
	time.Sleep(2500 * time.Millisecond) // a steady peer is not logged a third time
	if n := connsFrom("192.168.1.50"); n != 2 {
		t.Errorf("steady peer logged %d times, want 2", n)
	}
	stop()
}

func TestDLClientsLoopSkipsHostScanWithoutPublishedPorts(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "down", `{"hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":8023}]}]}`) // not running
	dpOut(t, dir, "ps", "", 0)
	dpOut(t, dir, "lsof", dpLsof, 0)
	stop := dlRun(t, d.ClientsLoop)
	dpWait(t, "two ticks", func() bool { return dpCount(dir, "docker ps") >= 2 })
	stop()
	if n := dpCount(dir, "lsof"); n != 0 {
		t.Errorf("lsof ran %d times although no running tunnel publishes a port", n)
	}
}

func TestDLHostPingLoopProbesHostsAndBroadcasts(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	lport := ln.Addr().(*net.TCPAddr).Port

	// alpha: vpn tunnel, probed from inside its container (stubbed docker exec)
	dpConf(t, d, "alpha", `{"type":"vpn","hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":9001},{"remote":80,"local":9002}]},{"ip":"10.0.0.6","forwards":[{"remote":0,"local":9003}]}]}`)
	// beta: ssh tunnel, its published local port is probed from the host
	dpConf(t, d, "beta", fmt.Sprintf(`{"type":"ssh","ssh":{"host":"10.99.0.1","port":22},"hosts":[{"ip":"10.1.0.7","forwards":[{"remote":443,"local":%d}]}]}`, lport))
	dpOut(t, dir, "ps",
		dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha,t-forward.type=vpn")+
			dpPS("tf-beta", "t-forward=1,t-forward.name=beta,t-forward.type=ssh"), 0)
	dpOut(t, dir, "exec-timeout", "", 0) // every port probe inside the container succeeds
	dpOut(t, dir, "exec-ping", "", 1)
	dpOut(t, dir, "exec-ip-addr", "4: tun0    inet 10.0.0.2/24 scope global tun0\n", 0)
	dpOut(t, dir, "exec-ip-route", "10.0.0.0/24 dev tun0 scope link\n", 0)
	// alpha's 10.0.0.5 was down on the previous poll: the flip is a "reach" change
	d.updateLive("alpha", func(ld *liveData) { ld.hostUp = map[string]bool{"10.0.0.5": false} })

	cl := d.hub.register()
	stop := dlRun(t, d.HostPingLoop)

	// the first poll fires after 3s
	var all []string
	dpWait(t, "hosts frames for both tunnels", func() bool {
		all = append(all, drainFrames(cl, "hosts", "netinfo")...)
		return dlHas(all, `"tun":"alpha"`, `"10.0.0.5":true`) && dlHas(all, `"tun":"beta"`, `"10.1.0.7":true`)
	})
	if !dlHas(all, `"tun":"alpha"`, `"portUp"`, `"10.0.0.5:22":true`, `"10.0.0.5:80":true`) {
		t.Errorf("alpha frame lacks the per-port result: %v", all)
	}
	if !dlHas(all, `"ip":"10.0.0.2"`, `"hostSubnets"`, "10.0.0.0/24") {
		t.Errorf("no netinfo frame with the tunnel IP and subnet: %v", all)
	}
	d.mu.Lock()
	ld := d.live["alpha"]
	d.mu.Unlock()
	if ld == nil || !ld.hostUp["10.0.0.5"] || ld.tunIP != "10.0.0.2" || ld.tunSubnet != "10.0.0.0/24" {
		t.Errorf("live[alpha] = %+v", ld)
	}
	if n := dpCount(dir, "docker exec tf-beta timeout"); n != 0 {
		t.Errorf("ssh tunnel was probed inside the container (%d exec calls); it must use the local port", n)
	}
	stop()
}

// drainFrames pulls frames of the given event types off the lossy channel.
func drainFrames(c *client, types ...string) []string {
	var out []string
	for {
		select {
		case b := <-c.lossy:
			s := string(b)
			for _, ty := range types {
				if h := "event: " + ty + "\ndata: "; strings.HasPrefix(s, h) {
					out = append(out, strings.TrimSuffix(strings.TrimPrefix(s, h), "\n\n"))
				}
			}
		default:
			return out
		}
	}
}

func TestDLHostPingLoopStopsBeforeFirstPoll(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.HostPingLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HostPingLoop ignored cancel while waiting for its first poll")
	}
	if n := dpCount(dir, "docker ps"); n != 0 {
		t.Errorf("polled %d times before the first timer", n)
	}
}
