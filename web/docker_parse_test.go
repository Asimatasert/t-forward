package main

// Tests for the output-parsing / state-computing parts of docker.go that sit
// behind a `docker`, `lsof`, `arp` or `yq` call.
//
// docker.go has no function-variable / interface seam, and this file adds none
// (no production hook). The only injection point is the one the existing
// stubDocker() in docker_test.go already uses: the binaries are resolved from
// PATH, so a POSIX-sh stub placed first on PATH feeds canned output. Loops
// (StateLoop, ClientsLoop, HostPingLoop, WaitingLoop, EventsLoop) stay out of
// scope.

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// dpStubScript is installed as docker, lsof, arp and yq. Per invocation it
// appends its argv to $DP_DIR/calls.log and replays $DP_DIR/<key>.out with
// exit code $DP_DIR/<key>.rc (default 0). A missing <key>.out means "exit 1,
// no output" (a failing command). <key>.hang makes it block (killable: exec).
const dpStubScript = `#!/bin/sh
n=$(basename "$0")
echo "$n $*" >> "$DP_DIR/calls.log"
if [ "$n" = yq ]; then
  if [ -f "$3.json" ]; then cat "$3.json"; exit 0; fi
  exit 1
fi
key="$n"
case "$n" in
  docker)
    key="$1"
    if [ "$1" = exec ]; then
      key="exec-$3"
      if [ "$3" = ip ]; then
        if [ "$5" = -o ]; then key=exec-ip-addr; else key=exec-ip-route; fi
      fi
    fi
    ;;
esac
if [ -f "$DP_DIR/$key.hang" ]; then exec sleep 30; fi
if [ ! -f "$DP_DIR/$key.out" ]; then exit 1; fi
cat "$DP_DIR/$key.out"
rc=0
if [ -f "$DP_DIR/$key.rc" ]; then rc=$(cat "$DP_DIR/$key.rc"); fi
exit "$rc"
`

// dpTools installs the stub binaries first on PATH and returns the directory
// the tests drop <key>.out files into.
func dpTools(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs need a POSIX sh")
	}
	bin := t.TempDir()
	for _, n := range []string{"docker", "lsof", "arp", "yq"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte(dpStubScript), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DP_DIR", dir)
	return dir
}

// dpOut sets what the stub prints for key ("ps", "port", "stats", "logs",
// "events", "exec-ping", "lsof", "arp", ...). rc != 0 makes it fail after printing.
func dpOut(t *testing.T, dir, key, out string, rc int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, key+".out"), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc != 0 {
		if err := os.WriteFile(filepath.Join(dir, key+".rc"), []byte(fmt.Sprint(rc)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func dpHang(t *testing.T, dir, key string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, key+".hang"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// dpCalls returns the argv lines the stubs recorded (e.g. "docker ps -a ...").
func dpCalls(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "calls.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func dpCount(dir, prefix string) int {
	n := 0
	for _, c := range dpCalls(dir) {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func dpWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// dpEvents returns copies of the console events recorded by the hub.
func dpEvents(h *Hub) []map[string]any {
	h.evMu.Lock()
	defer h.evMu.Unlock()
	var out []map[string]any
	for _, e := range h.evRing {
		if m, ok := e.Ev.(map[string]any); ok {
			cp := make(map[string]any, len(m))
			for k, v := range m {
				cp[k] = v
			}
			out = append(out, cp)
		}
	}
	return out
}

func dpHasEvent(h *Hub, level, msgPart string) bool {
	for _, e := range dpEvents(h) {
		if e["level"] == level && strings.Contains(fmt.Sprint(e["msg"]), msgPart) {
			return true
		}
	}
	return false
}

// dpConf writes conf.d/<name>.yaml plus the JSON the yq stub returns for it.
func dpConf(t *testing.T, d *Docker, name, jsonConf string) {
	t.Helper()
	if err := os.MkdirAll(d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := confPath(d.confDir, name)
	if err := os.WriteFile(p, []byte("# stub\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".json", []byte(jsonConf), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- dockerPorts

func TestDPDockerPorts(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "port", strings.Join([]string{
		"10001/tcp -> 0.0.0.0:8023",
		"10001/tcp -> [::]:8023", // same internal port again (IPv6 bind): last one wins
		"10002/tcp -> 127.0.0.1:9000",
		"10003 -> 127.0.0.1:9100", // no /proto suffix
		"",
		"garbage without arrow",
		" -> 127.0.0.1:1", // empty internal port
		"10004/tcp ->",    // empty published side
		"  10005/udp  ->  127.0.0.1:9500  ",
	}, "\n")+"\n", 0)

	got := dockerPorts("tf-a")
	want := map[string]string{
		"10001": "[::]:8023",
		"10002": "127.0.0.1:9000",
		"10003": "127.0.0.1:9100",
		"10005": "127.0.0.1:9500",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dockerPorts = %v, want %v", got, want)
	}
	if c := dpCalls(dir); len(c) != 1 || c[0] != "docker port tf-a" {
		t.Fatalf("calls = %v", c)
	}
}

func TestDPDockerPortsCommandFails(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "port", "10001/tcp -> 127.0.0.1:1\n", 3) // output is ignored on failure
	got := dockerPorts("tf-a")
	if got == nil || len(got) != 0 {
		t.Fatalf("dockerPorts on failure = %#v, want empty non-nil map", got)
	}
}

// ---------------------------------------------------------------- State

func dpPS(name, labels string) string {
	b, _ := json.Marshal(map[string]string{"Names": name, "State": "running", "Labels": labels})
	return string(b) + "\n"
}

func TestDPStateResolvesPortsAndJump(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)

	dpConf(t, d, "alpha", `{"name":"Alpha box","type":"ssh","ssh":{"host":"bastion.example","port":22},
		"hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":"any"},{"remote":5432,"local":"any"},{"remote":80,"local":8080}]}]}`)
	// beta reaches its targets THROUGH alpha: its ssh endpoint is alpha's first published forward
	dpConf(t, d, "beta", `{"type":"ssh","ssh":{"host":"127.0.0.1","port":2222},"hosts":[]}`)
	// a configured tunnel without a container
	dpConf(t, d, "down", `{"type":"vpn","hosts":[{"ip":"10.9.9.9","forwards":[{"remote":22,"local":"any"}]}]}`)

	dpOut(t, dir, "ps",
		dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha,t-forward.type=ssh")+
			"\n"+ // blank line
			"{not json}\n"+
			dpPS("tf-beta", "t-forward=1,t-forward.type=ssh"), // no .name label: id from tf- prefix
		0)
	dpOut(t, dir, "port", "10001/tcp -> 127.0.0.1:2222\n10002/tcp -> 127.0.0.1:2223\n", 0)

	res := d.State()
	m := byID(res)
	if len(res) != 3 {
		t.Fatalf("State returned %d tunnels, want 3 (alpha, beta, down): %+v", len(res), res)
	}
	if !sort.SliceIsSorted(res, func(i, j int) bool { return res[i].ID < res[j].ID }) {
		t.Fatalf("State not sorted by ID: %+v", res)
	}

	a := m["alpha"]
	if a.State != "on" || a.Desc != "Alpha box" || a.Type != "ssh" {
		t.Fatalf("alpha = %+v", a)
	}
	// forwards 1 and 2 take their real published port; forward 3 has no 10003 mapping
	wantLocals := []string{"127.0.0.1:2222", "127.0.0.1:2223", "127.0.0.1:8080"}
	for i, f := range a.Forwards {
		if f.Local != wantLocals[i] {
			t.Errorf("alpha forward %d local = %q, want %q", i, f.Local, wantLocals[i])
		}
	}
	if a.Forwards[0].Remote != "10.0.0.5:22" || a.Forwards[0].Service != "ssh" {
		t.Errorf("alpha forward 0 = %+v", a.Forwards[0])
	}
	if a.Jump != nil {
		t.Errorf("alpha must not be a jump tunnel: %+v", a.Jump)
	}

	b := m["beta"]
	if b.Jump == nil || b.Jump.Tun != "alpha" || b.Jump.Host != "10.0.0.5" {
		t.Fatalf("beta.Jump = %+v, want {alpha 10.0.0.5}", b.Jump)
	}

	if m["down"].State != "off" {
		t.Errorf("down state = %q, want off", m["down"].State)
	}
	// a stopped tunnel never asks docker for its ports, so it keeps the conf's auto bind
	if got := m["down"].Forwards[0].Local; got != publishBind+":auto" {
		t.Errorf("down forward local = %q, want %q", got, publishBind+":auto")
	}
	if n := dpCount(dir, "docker port "); n != 2 {
		t.Errorf("docker port called %d times, want 2 (alpha, beta only)", n)
	}
}

// The conf cache must hand out a copy of Forwards: resolving a published port
// on one State() call may not leak into the next one.
func TestDPStateDoesNotLeakResolvedPortsIntoCache(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "alpha", `{"type":"ssh","ssh":{"host":"h","port":22},"hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":"any"}]}]}`)
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	dpOut(t, dir, "port", "10001/tcp -> 127.0.0.1:2222\n", 0)

	if got := d.State()[0].Forwards[0].Local; got != "127.0.0.1:2222" {
		t.Fatalf("first State local = %q", got)
	}
	dpOut(t, dir, "port", "10001/tcp -> 127.0.0.1:3333\n", 0)
	if got := d.State()[0].Forwards[0].Local; got != "127.0.0.1:3333" {
		t.Fatalf("second State local = %q, want fresh 3333", got)
	}
	// docker reports no mapping any more: the conf value (not a stale 3333) shows
	dpOut(t, dir, "port", "", 0)
	if got := d.State()[0].Forwards[0].Local; got != publishBind+":auto" {
		t.Fatalf("third State local = %q, want %q", got, publishBind+":auto")
	}
	if n := dpCount(dir, "yq "); n != 1 {
		t.Errorf("yq ran %d times, want 1 (mtime/size cache)", n)
	}
}

func TestDPStateWaitingTunnelResolvesPorts(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "alpha", `{"hosts":[{"ip":"10.0.0.5","forwards":[{"remote":22,"local":"any"}]}]}`)
	dpOut(t, dir, "ps", dpPS("tf-alpha", "t-forward=1,t-forward.name=alpha"), 0)
	dpOut(t, dir, "port", "10001/tcp -> 127.0.0.1:2222\n", 0)
	wait := filepath.Join(d.stateDir, "auth-alpha")
	if err := os.MkdirAll(wait, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wait, "awaiting_code"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := d.State()
	if len(got) != 1 || got[0].State != "waiting" || got[0].Forwards[0].Local != "127.0.0.1:2222" {
		t.Fatalf("State = %+v", got)
	}
}

func TestDPStateDockerFailureFallsBackToConfs(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpConf(t, d, "only", `{"name":"Only conf"}`)
	dpOut(t, dir, "ps", "ignored\n", 1) // docker daemon down
	got := d.State()
	if len(got) != 1 || got[0].ID != "only" || got[0].State != "off" || got[0].Desc != "Only conf" {
		t.Fatalf("State = %+v", got)
	}
}

// ---------------------------------------------------------------- runningContainers

func TestDPRunningContainers(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "ps",
		dpPS("tf-alpha", "t-forward=1,t-forward.name=prod-alpha")+
			"\n"+
			"not json\n"+
			dpPS("tf-beta", "t-forward=1")+ // no name label: strip the tf- prefix
			dpPS("custom", ""), // no prefix to strip
		0)
	ids, names := d.runningContainers(t.Context())
	if want := []string{"tf-alpha", "tf-beta", "custom"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	wantNames := map[string]string{"tf-alpha": "prod-alpha", "tf-beta": "beta", "custom": "custom"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("names = %v, want %v", names, wantNames)
	}
}

func TestDPRunningContainersDockerFails(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "ps", "", 1)
	ids, names := d.runningContainers(t.Context())
	if ids != nil || names == nil || len(names) != 0 {
		t.Fatalf("ids=%v names=%#v, want nil + empty non-nil map", ids, names)
	}
}

// ---------------------------------------------------------------- sampleStats

func dpStat(name, netio string) string {
	b, _ := json.Marshal(map[string]string{"Name": name, "NetIO": netio})
	return string(b) + "\n"
}

// statFrames drains the lossy channel and decodes the 'stat' frames.
func dpStatFrames(t *testing.T, c *client) []map[string]any {
	t.Helper()
	var out []map[string]any
	for {
		select {
		case f := <-c.lossy:
			s := string(f)
			const head = "event: stat\ndata: "
			if !strings.HasPrefix(s, head) {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(s, head), "\n\n")), &m); err != nil {
				t.Fatalf("decode stat frame %q: %v", s, err)
			}
			out = append(out, m)
		default:
			return out
		}
	}
}

func TestDPSampleStatsRates(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	cl := d.hub.register()
	dpOut(t, dir, "ps",
		dpPS("tf-alpha", "t-forward=1,t-forward.name=prod-alpha")+
			dpPS("tf-beta", "t-forward=1")+ // id falls back to the tf- stripped name
			dpPS("tf-gamma", "t-forward=1,t-forward.name=gamma"),
		0)
	dpOut(t, dir, "stats",
		dpStat("tf-alpha", "21kB / 5.5kB")+
			"\n"+
			"garbage\n"+
			dpStat("tf-bad", "no slash here")+
			dpStat("tf-beta", "3kB / 4kB")+
			dpStat("tf-gamma", "1kB / 1kB"),
		0)

	// first sample only primes lastNet
	d.sampleStats(t.Context())
	if fr := dpStatFrames(t, cl); len(fr) != 0 {
		t.Fatalf("first sample broadcast %v, want nothing", fr)
	}
	d.mu.Lock()
	if _, ok := d.lastNet["tf-alpha"]; !ok {
		t.Fatal("first sample did not record tf-alpha")
	}
	if _, ok := d.lastNet["tf-bad"]; ok {
		t.Fatal("unparsable NetIO must not be recorded")
	}
	// pretend the previous samples were taken 10s ago
	ago := time.Now().Add(-10 * time.Second)
	d.lastNet["tf-alpha"] = netSample{rx: 1000, tx: 500, at: ago}
	d.lastNet["tf-beta"] = netSample{rx: 3000, tx: 100000, at: ago}                      // counters went backwards (container restarted)
	d.lastNet["tf-gamma"] = netSample{rx: 1000, tx: 1000, at: time.Now().Add(time.Hour)} // dt <= 0
	d.mu.Unlock()

	d.sampleStats(t.Context())
	frames := dpStatFrames(t, cl)
	byIDf := map[string]map[string]any{}
	for _, f := range frames {
		byIDf[fmt.Sprint(f["id"])] = f
	}
	if len(byIDf) != 2 {
		t.Fatalf("frames = %v, want alpha+beta only (gamma has dt<=0)", frames)
	}
	near := func(v any, want float64) bool {
		f, _ := v.(float64)
		return math.Abs(f-want) <= want*0.05+1
	}
	a := byIDf["prod-alpha"]
	if a == nil || !near(a["rxRate"], 2000) || !near(a["txRate"], 500) { // (21000-1000)/10, (5500-500)/10
		t.Fatalf("alpha frame = %v, want rx~2000 tx~500", a)
	}
	b := byIDf["beta"]
	if b == nil || b["rxRate"].(float64) != 0 || b["txRate"].(float64) != 0 {
		t.Fatalf("beta frame = %v, want rates clamped to 0 (rx 0/tx negative)", b)
	}
	if b != nil {
		// rx 3000 -> 3000 over 10s is exactly 0; tx fell 100000 -> 4000: clamped, never negative
		d.mu.Lock()
		ld := d.live["beta"]
		d.mu.Unlock()
		if ld == nil || ld.txRate != 0 || ld.rxRate != 0 {
			t.Fatalf("live[beta] = %+v", ld)
		}
	}
	d.mu.Lock()
	la := d.live["prod-alpha"]
	d.mu.Unlock()
	if la == nil || !near(float64(la.rxRate), 2000) {
		t.Fatalf("live[prod-alpha] = %+v", la)
	}
}

func TestDPSampleStatsNothingRunning(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "ps", "", 0)
	d.sampleStats(t.Context())
	if n := dpCount(dir, "docker stats"); n != 0 {
		t.Fatalf("docker stats called %d times with no running containers", n)
	}
}

func TestDPSampleStatsDockerFails(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	cl := d.hub.register()
	dpOut(t, dir, "ps", dpPS("tf-a", "t-forward=1"), 0)
	dpOut(t, dir, "stats", dpStat("tf-a", "1kB / 1kB"), 1)
	d.sampleStats(t.Context())
	if len(d.lastNet) != 0 || len(dpStatFrames(t, cl)) != 0 {
		t.Fatalf("failed docker stats must record nothing: %v", d.lastNet)
	}
	if got := dpCalls(dir); len(got) != 2 || !strings.HasPrefix(got[1], "docker stats --no-stream --format {{json .}} tf-a") {
		t.Fatalf("calls = %v", got)
	}
}

// ---------------------------------------------------------------- maybeNotifyWarn

func TestDPMaybeNotifyWarnCooldown(t *testing.T) {
	d, _ := newTestDocker(t) // no settings file: notifyState is a no-op, no network
	d.maybeNotifyWarn("a", "boom")
	d.mu.Lock()
	first, ok := d.lastWarnAt["a"]
	d.mu.Unlock()
	if !ok || time.Since(first) > 5*time.Second {
		t.Fatalf("first warn not recorded: %v", first)
	}

	d.maybeNotifyWarn("a", "boom again") // inside the cooldown: stamp unchanged
	d.mu.Lock()
	second := d.lastWarnAt["a"]
	d.mu.Unlock()
	if !second.Equal(first) {
		t.Fatalf("warn inside cooldown re-stamped: %v -> %v", first, second)
	}

	// another tunnel is independent
	d.maybeNotifyWarn("b", "x")
	d.mu.Lock()
	_, okB := d.lastWarnAt["b"]
	d.lastWarnAt["a"] = time.Now().Add(-warnCooldown - time.Second)
	d.mu.Unlock()
	if !okB {
		t.Fatal("tunnel b not tracked independently")
	}

	d.maybeNotifyWarn("a", "after cooldown")
	d.mu.Lock()
	third := d.lastWarnAt["a"]
	d.mu.Unlock()
	if time.Since(third) > 5*time.Second {
		t.Fatalf("warn after cooldown not re-stamped: %v", third)
	}
}

// ---------------------------------------------------------------- tailLogs / tailers

func TestDPTailLogsBroadcastsClassifiedEvents(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "logs", strings.Join([]string{
		"2026-11-02T10:00:00.000000000Z socat[7] N write(6, 0x1, 132) completed", // noisy: dropped
		"2026-11-02T10:00:01.000000000Z socat[7] N read(5, 0x1, 132) completed",  // noisy: dropped
		"",
		"2026-11-02T10:00:02.000000000Z ERROR: connection refused\r",
		"2026-11-02T10:00:03.000000000Z N accepting connection from 10.0.0.9",
		"2026-11-02T10:00:04.000000000Z tunnel is up",
		"line without timestamp",
	}, "\n")+"\n", 0)

	d.tailLogs(t.Context(), "tf-x", "x")

	evs := dpEvents(d.hub)
	type row struct{ ts, level, tun, msg string }
	var got []row
	for _, e := range evs {
		got = append(got, row{fmt.Sprint(e["ts"]), fmt.Sprint(e["level"]), fmt.Sprint(e["tun"]), fmt.Sprint(e["msg"])})
	}
	if len(got) != 4 {
		t.Fatalf("got %d events, want 4: %+v", len(got), got)
	}
	want := []row{
		{"2026-11-02T10:00:02.000000000Z", "error", "x", "ERROR: connection refused"},
		{"2026-11-02T10:00:03.000000000Z", "conn", "x", "N accepting connection from 10.0.0.9"},
		{"2026-11-02T10:00:04.000000000Z", "tunnel", "x", "tunnel is up"},
	}
	if !reflect.DeepEqual(got[:3], want) {
		t.Fatalf("events = %+v\nwant %+v", got[:3], want)
	}
	if got[3].level != "log" || got[3].msg != "line without timestamp" || got[3].ts == "" {
		t.Fatalf("untimestamped line = %+v", got[3])
	}
	// the error line armed the warn cooldown; the others did not
	d.mu.Lock()
	_, warned := d.lastWarnAt["x"]
	d.mu.Unlock()
	if !warned {
		t.Fatal("error line did not reach maybeNotifyWarn")
	}
	if c := dpCalls(dir); len(c) != 1 || c[0] != "docker logs -f --since=0s --timestamps tf-x" {
		t.Fatalf("calls = %v", c)
	}
}

// A log line longer than the 1 MiB scanner limit stops the scanner early; the
// pipe must still be drained so the child can exit and tailLogs returns.
func TestDPTailLogsOverlongLineDoesNotHang(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpOut(t, dir, "logs",
		"2026-11-02T10:00:00Z before\n"+strings.Repeat("a", 1100000)+"\n2026-11-02T10:00:02Z after\n", 0)

	done := make(chan struct{})
	go func() { d.tailLogs(t.Context(), "tf-x", "x"); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("tailLogs hung on an over-long line")
	}
	evs := dpEvents(d.hub)
	if len(evs) != 1 || evs[0]["msg"] != "before" {
		t.Fatalf("events = %v, want only the line before the over-long one", evs)
	}
}

func TestDPTailLogsDockerMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix only")
	}
	t.Setenv("PATH", t.TempDir()) // no docker at all: Start fails, must return quietly
	d, _ := newTestDocker(t)
	d.tailLogs(t.Context(), "tf-x", "x")
	if len(dpEvents(d.hub)) != 0 {
		t.Fatal("unexpected events")
	}
}

func TestDPStartAndStopTailer(t *testing.T) {
	dir := dpTools(t)
	dpHang(t, dir, "logs") // `docker logs -f` that never ends until killed
	dpOut(t, dir, "logs", "", 0)
	d, _ := newTestDocker(t)
	ctx := t.Context()

	d.startTailer(ctx, "tf-a", "a")
	d.mu.Lock()
	first := d.tailers["tf-a"]
	d.lastNet["tf-a"] = netSample{rx: 1}
	d.mu.Unlock()
	if first == nil {
		t.Fatal("tailer not registered")
	}
	dpWait(t, "docker logs to start", func() bool { return dpCount(dir, "docker logs") == 1 })

	// a live tailer suppresses a second one
	d.startTailer(ctx, "tf-a", "a")
	d.mu.Lock()
	same := d.tailers["tf-a"] == first
	d.mu.Unlock()
	if !same {
		t.Fatal("second startTailer replaced a live tailer")
	}

	d.stopTailer("tf-a")
	d.mu.Lock()
	_, still := d.tailers["tf-a"]
	_, hasNet := d.lastNet["tf-a"]
	d.mu.Unlock()
	if still || hasNet {
		t.Fatalf("stopTailer left state behind: tailer=%v lastNet=%v", still, hasNet)
	}
	select {
	case <-first.done:
	case <-time.After(10 * time.Second):
		t.Fatal("tailLogs did not exit after stopTailer cancelled it")
	}
	d.stopTailer("tf-unknown") // no-op, must not panic
}

func TestDPStartTailerReplacesExitedTailer(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "logs", "2026-11-02T10:00:00Z hello\n", 0) // exits right away
	d, _ := newTestDocker(t)

	dead := &tailer{cancel: func() {}, done: make(chan struct{})}
	close(dead.done)
	d.mu.Lock()
	d.tailers["tf-a"] = dead
	d.mu.Unlock()

	d.startTailer(t.Context(), "tf-a", "a")
	dpWait(t, "replacement tailer to log", func() bool { return dpHasEvent(d.hub, "log", "hello") })
	dpWait(t, "finished tailer to deregister", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.tailers) == 0
	})
}

// ---------------------------------------------------------------- watchEvents

func dpEv(action, name, tun string) string {
	attrs := map[string]string{}
	if name != "" {
		attrs["name"] = name
	}
	if tun != "" {
		attrs["t-forward.name"] = tun
	}
	b, _ := json.Marshal(map[string]any{"Action": action, "Actor": map[string]any{"Attributes": attrs}})
	return string(b) + "\n"
}

func TestDPWatchEvents(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	ctx := t.Context()
	dpOut(t, dir, "logs", "2026-11-02T10:00:00Z hello\n", 0)
	dpOut(t, dir, "events",
		dpEv("start", "tf-a", "custom")+ // tun from the label
			"\n"+
			"not json\n"+
			dpEv("start", "tf-b", "")+ // tun from the tf- stripped name
			dpEv("start", "", "")+ // no container name: state only, no tailer
			dpEv("exec_start", "tf-a", "")+ // not a lifecycle event: ignored
			dpEv("create", "tf-c", "")+
			dpEv("destroy", "tf-c", ""), 0)

	d.watchEvents(ctx)

	// start x3 + create + destroy broadcast state; exec_start / bad json do not
	if n := dpCount(dir, "docker ps"); n != 5 {
		t.Fatalf("broadcastState ran %d times, want 5; calls=%v", n, dpCalls(dir))
	}
	if !strings.HasPrefix(dpCalls(dir)[0], "docker events --filter label=t-forward --format") {
		t.Fatalf("calls[0] = %q", dpCalls(dir)[0])
	}
	dpWait(t, "both tailers to log", func() bool {
		tuns := map[string]bool{}
		for _, e := range dpEvents(d.hub) {
			if e["msg"] == "hello" {
				tuns[fmt.Sprint(e["tun"])] = true
			}
		}
		return tuns["custom"] && tuns["b"]
	})
	if n := dpCount(dir, "docker logs"); n != 2 {
		t.Fatalf("docker logs started %d times, want 2 (a, b; not the nameless one)", n)
	}
}

func TestDPWatchEventsDieStopsTailer(t *testing.T) {
	dir := dpTools(t)
	d, _ := newTestDocker(t)
	dpHang(t, dir, "logs")
	dpOut(t, dir, "logs", "", 0)

	dpOut(t, dir, "events", dpEv("start", "tf-a", ""), 0)
	d.watchEvents(t.Context())
	dpWait(t, "tailer to attach", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.tailers["tf-a"] != nil
	})
	d.mu.Lock()
	tl := d.tailers["tf-a"]
	d.mu.Unlock()

	for _, act := range []string{"die", "kill", "stop"} {
		dpOut(t, dir, "events", dpEv(act, "tf-a", ""), 0)
		d.watchEvents(t.Context())
	}
	d.mu.Lock()
	_, still := d.tailers["tf-a"]
	d.mu.Unlock()
	if still {
		t.Fatal("die/kill/stop did not remove the tailer")
	}
	select {
	case <-tl.done:
	case <-time.After(10 * time.Second):
		t.Fatal("tailer not cancelled")
	}
}

func TestDPWatchEventsDockerMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix only")
	}
	t.Setenv("PATH", t.TempDir())
	d, _ := newTestDocker(t)
	d.watchEvents(t.Context()) // Start fails: returns without a panic
}

// ---------------------------------------------------------------- maybeAutoCode

func dpFakeTF(t *testing.T, exit int) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "t-forward")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" >> %q\nexit %d\n", argsFile, exit)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func TestDPMaybeAutoCodeDeliversCode(t *testing.T) {
	dpTools(t)
	d, _ := newTestDocker(t)
	var argsFile string
	d.tfPath, argsFile = dpFakeTF(t, 0)
	d.allowTotpCmd = true
	dpConf(t, d, "vpn1", `{"type":"vpn","totp_command":"echo 'your code is 482913, valid 5 min'"}`)

	d.maybeAutoCode(t.Context(), "vpn1")
	dpWait(t, "delivery event", func() bool { return dpHasEvent(d.hub, "auth", "TOTP code delivered automatically") })

	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "code vpn1 482913" {
		t.Fatalf("t-forward args = %q, want %q", got, "code vpn1 482913")
	}
	if !dpHasEvent(d.hub, "auth", "fetching verification code") {
		t.Fatal("missing 'fetching' event")
	}

	// armed: a second call in the same wait does nothing
	before := len(dpEvents(d.hub))
	d.maybeAutoCode(t.Context(), "vpn1")
	time.Sleep(100 * time.Millisecond)
	if after := len(dpEvents(d.hub)); after != before {
		t.Fatalf("armed tunnel fired again: %d -> %d events", before, after)
	}
}

func TestDPMaybeAutoCodeFailurePaths(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		tfExit  int
		level   string
		wantMsg string
	}{
		{"command fails", "exit 3", 0, "error", "TOTP source failed or timed out"},
		{"no digits in output", "echo no code here 12", 0, "error", "TOTP source produced no code"},
		{"delivery fails", "echo 123456", 1, "error", "delivering TOTP code failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dpTools(t)
			d, _ := newTestDocker(t)
			d.tfPath, _ = dpFakeTF(t, tc.tfExit)
			d.allowTotpCmd = true
			cmdJSON, _ := json.Marshal(tc.cmd)
			dpConf(t, d, "vpn1", `{"type":"vpn","totp_command":`+string(cmdJSON)+`}`)
			d.maybeAutoCode(t.Context(), "vpn1")
			dpWait(t, tc.wantMsg, func() bool { return dpHasEvent(d.hub, tc.level, tc.wantMsg) })
			if dpHasEvent(d.hub, "auth", "delivered automatically") {
				t.Fatal("must not report delivery")
			}
		})
	}
}

func TestDPMaybeAutoCodeGuards(t *testing.T) {
	t.Run("auto-exec disabled by default", func(t *testing.T) {
		dpTools(t)
		d, _ := newTestDocker(t)
		var argsFile string
		d.tfPath, argsFile = dpFakeTF(t, 0)
		dpConf(t, d, "vpn1", `{"totp_command":"echo 111111"}`)
		d.maybeAutoCode(t.Context(), "vpn1")
		if !dpHasEvent(d.hub, "error", "auto-exec is disabled") {
			t.Fatalf("events = %v", dpEvents(d.hub))
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(argsFile); err == nil {
			t.Fatal("totp_command ran although -allow-totp-command is off")
		}
	})
	t.Run("no totp source configured", func(t *testing.T) {
		dpTools(t)
		d, _ := newTestDocker(t)
		d.allowTotpCmd = true
		dpConf(t, d, "vpn1", `{"type":"vpn","totp_command":"   "}`)
		d.maybeAutoCode(t.Context(), "vpn1")
		if n := len(dpEvents(d.hub)); n != 0 {
			t.Fatalf("events = %v", dpEvents(d.hub))
		}
	})
	t.Run("unreadable conf", func(t *testing.T) {
		dpTools(t)
		d, _ := newTestDocker(t)
		d.allowTotpCmd = true
		d.maybeAutoCode(t.Context(), "missing")
		if n := len(dpEvents(d.hub)); n != 0 {
			t.Fatalf("events = %v", dpEvents(d.hub))
		}
		d.mu.Lock()
		armed := d.armed["missing"]
		d.mu.Unlock()
		if !armed {
			t.Fatal("tunnel should still be marked armed for this wait")
		}
	})
	t.Run("imap needs the awaiting_code marker", func(t *testing.T) {
		dpTools(t)
		d, _ := newTestDocker(t)
		dpConf(t, d, "vpn1", `{"type":"vpn","vpn":{"totp":true,"totp_imap":{"host":"imap.example"}}}`)
		d.maybeAutoCode(t.Context(), "vpn1") // no marker file: returns before any goroutine
		if n := len(dpEvents(d.hub)); n != 0 {
			t.Fatalf("events = %v", dpEvents(d.hub))
		}
	})
}

// ---------------------------------------------------------------- hostConns / arpTable

const dpLsof = `COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
docker-pr  1234  me   10u  IPv4 0x1111111111      0t0  TCP 127.0.0.1:8023->192.168.1.50:51000 (ESTABLISHED)
docker-pr  1234  me   11u  IPv4 0x2222222222      0t0  TCP 127.0.0.1:8023->192.168.1.50:51001 (ESTABLISHED)
docker-pr  1234  me   12u  IPv4 0x3333333333      0t0  TCP 127.0.0.1:8023->10.0.0.9:51002 (ESTABLISHED)
OrbStack   2222  me   13u  IPv4 0x4444444444      0t0  TCP 127.0.0.1:9000->192.168.1.77:40000 (ESTABLISHED)
ssh        4567  me    5u  IPv4 0x5555555555      0t0  TCP 127.0.0.1:60000->127.0.0.1:8023 (ESTABLISHED)
curl       4568  me    5u  IPv4 0x6666666666      0t0  TCP 127.0.0.1:60001->127.0.0.1:8023 (ESTABLISHED)
psql       4569  me    5u  IPv4 0x7777777777      0t0  TCP 127.0.0.1:60002->127.0.0.1:9000 (ESTABLISHED)
chrome     7890  me   30u  IPv4 0x8888888888      0t0  TCP 192.168.1.2:60003->8.8.8.8:443 (ESTABLISHED)
docker-pr  9999  me    7u  IPv4 0x9999999999      0t0  TCP nocolon->10.1.1.1:5 (ESTABLISHED)
sshd       1111  me    3u  IPv4 0xaaaaaaaaaa      0t0  TCP *:22 (LISTEN)
short line
`

func TestDPHostConns(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "lsof", dpLsof, 0)

	got := hostConns()
	want := map[int][]Client{
		// proxy accept side: remote is the client (deduped per IP, sorted); local
		// processes connecting to the forward carry their process name.
		8023: {
			{IP: "10.0.0.9", Port: 8023},
			{IP: "127.0.0.1", Port: 8023, Proc: "ssh"}, // ssh first, curl on the same IP dropped
			{IP: "192.168.1.50", Port: 8023},
		},
		9000: {
			{IP: "127.0.0.1", Port: 9000, Proc: "psql"},
			{IP: "192.168.1.77", Port: 9000},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hostConns =\n %+v\nwant\n %+v", got, want)
	}
	if c := dpCalls(dir); len(c) != 1 || c[0] != "lsof -nP -sTCP:ESTABLISHED -iTCP" {
		t.Fatalf("calls = %v", c)
	}
}

// When both a proxy socket and a labelled local-process socket exist for the
// same IP, the labelled one wins regardless of line order.
func TestDPHostConnsPrefersProcLabel(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "lsof", `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
docker-pr 1 me 1u IPv4 0x1 0t0 TCP 127.0.0.1:8023->127.0.0.1:50000 (ESTABLISHED)
ssh 2 me 1u IPv4 0x2 0t0 TCP 127.0.0.1:50000->127.0.0.1:8023 (ESTABLISHED)
`, 0)
	got := hostConns()
	want := map[int][]Client{8023: {{IP: "127.0.0.1", Port: 8023, Proc: "ssh"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hostConns = %+v, want %+v", got, want)
	}
}

func TestDPHostConnsLsofFails(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "lsof", "", 1) // lsof exits 1 when nothing matches
	got := hostConns()
	if got == nil || len(got) != 0 {
		t.Fatalf("hostConns = %#v, want empty non-nil map", got)
	}
}

func TestDPArpTable(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "arp", strings.Join([]string{
		"? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]",
		"gw.local (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]",
		"? (10.0.0.6) at (incomplete) on en0 ifscope [ethernet]",
		"? (10.0.0.7) at ff on en0", // no colon: not a MAC
		"? (10.0.0.8) is-at aa:bb:cc:dd:ee:00 on en0",
		"too short",
		"",
	}, "\n"), 0)
	got := arpTable()
	want := map[string]string{"10.0.0.5": "aa:bb:cc:dd:ee:ff", "10.0.0.1": "0:1a:2b:3c:4d:5e"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arpTable = %v, want %v", got, want)
	}
	if c := dpCalls(dir); len(c) != 1 || c[0] != "arp -an" {
		t.Fatalf("calls = %v", c)
	}
}

func TestDPArpTableFails(t *testing.T) {
	dpTools(t) // arp stub exits 1
	got := arpTable()
	if got == nil || len(got) != 0 {
		t.Fatalf("arpTable = %#v, want empty non-nil map", got)
	}
}

// ---------------------------------------------------------------- reachability

func TestDPReachInContainer(t *testing.T) {
	dir := dpTools(t)
	ctx := t.Context()

	// invalid input never reaches docker (it would be interpolated into bash -c)
	for _, tc := range []struct{ ip, port string }{
		{"", ""}, {"not-an-ip", ""}, {"10.0.0.5;id", "22"}, {"$(id)", "22"},
		{"10.0.0.5", "0"}, {"10.0.0.5", "65536"}, {"10.0.0.5", "-1"}, {"10.0.0.5", "22;id"}, {"10.0.0.5", "ssh"},
	} {
		if reachInContainer(ctx, "tf-a", tc.ip, tc.port) {
			t.Errorf("reachInContainer(%q, %q) = true, want false", tc.ip, tc.port)
		}
	}
	if c := dpCalls(dir); len(c) != 0 {
		t.Fatalf("invalid input reached docker: %v", c)
	}

	// no port: ping
	dpOut(t, dir, "exec-ping", "", 0)
	if !reachInContainer(ctx, "tf-a", "10.0.0.5", "") {
		t.Error("ping success reported unreachable")
	}
	// port: bash /dev/tcp probe
	dpOut(t, dir, "exec-timeout", "", 0)
	if !reachInContainer(ctx, "tf-a", "10.0.0.5", "22") {
		t.Error("port probe success reported unreachable")
	}
	c := dpCalls(dir)
	if len(c) != 2 ||
		c[0] != "docker exec tf-a ping -c 1 -W 1 10.0.0.5" ||
		c[1] != "docker exec tf-a timeout 2 bash -c exec 3<>/dev/tcp/10.0.0.5/22" {
		t.Fatalf("calls = %q", c)
	}

	dpOut(t, dir, "exec-ping", "", 1)
	dpOut(t, dir, "exec-timeout", "", 1)
	if reachInContainer(ctx, "tf-a", "10.0.0.5", "") || reachInContainer(ctx, "tf-a", "10.0.0.5", "22") {
		t.Error("failing probe reported reachable")
	}
}

func TestDPReachLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctx := t.Context()
	if !reachLocalPort(ctx, addr) {
		t.Errorf("reachLocalPort(%q) = false for a live listener", addr)
	}
	_ = ln.Close()
	if reachLocalPort(ctx, addr) {
		t.Errorf("reachLocalPort(%q) = true after the listener closed", addr)
	}
	for _, hp := range []string{"", "127.0.0.1:auto", "127.0.0.1:"} {
		if reachLocalPort(ctx, hp) {
			t.Errorf("reachLocalPort(%q) = true, want false without dialling", hp)
		}
	}
}

func TestDPTunnelNet(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "exec-ip-addr",
		"4: tun0    inet 10.8.0.6/24 brd 10.8.0.255 scope global tun0\\       valid_lft forever preferred_lft forever\n"+
			"4: tun0    inet 10.9.9.9/24 scope global secondary tun0\n", 0)
	dpOut(t, dir, "exec-ip-route", strings.Join([]string{
		"default via 10.8.0.1",
		"10.0.0.0/16 via 10.8.0.1",
		"10.1.2.3 via 10.8.0.1",    // bare host route
		"10.2.0.5/32 via 10.8.0.1", // /32 host route
		"192.168.5.0/24 proto kernel scope link src 10.8.0.6",
		"bogus/33 via x",
		"",
	}, "\n"), 0)

	ip, nets := tunnelNet(t.Context(), "tf-a")
	if ip != "10.8.0.6" {
		t.Errorf("tunIP = %q, want the first inet address", ip)
	}
	var got []string
	for _, n := range nets {
		got = append(got, n.String())
	}
	if want := []string{"10.0.0.0/16", "192.168.5.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("nets = %v, want %v", got, want)
	}
	if s := subnetOf("10.0.3.4", nets); s != "10.0.0.0/16" {
		t.Errorf("subnetOf over parsed nets = %q", s)
	}
	c := dpCalls(dir)
	if len(c) != 2 ||
		c[0] != "docker exec tf-a ip -4 -o addr show tun0" ||
		c[1] != "docker exec tf-a ip -4 route show dev tun0" {
		t.Errorf("calls = %q", c)
	}
}

func TestDPTunnelNetCommandsFail(t *testing.T) {
	dpTools(t) // every docker exec exits 1
	ip, nets := tunnelNet(t.Context(), "tf-a")
	if ip != "" || len(nets) != 0 {
		t.Fatalf("ip=%q nets=%v, want empty", ip, nets)
	}
}

func TestDPTunnelNetAddrWithoutCIDR(t *testing.T) {
	dir := dpTools(t)
	dpOut(t, dir, "exec-ip-addr", "4: tun0 inet 999.1.1.1/24 scope global tun0\n", 0)
	ip, _ := tunnelNet(t.Context(), "tf-a")
	if ip != "" {
		t.Fatalf("tunIP = %q for an unparsable address, want empty", ip)
	}
}

// ---------------------------------------------------------------- parseBytes

func TestDPParseBytesUnknownUnitIsBytes(t *testing.T) {
	for in, want := range map[string]float64{"5XB": 5, "7 furlongs": 7, "1.5q": 1.5} {
		got, ok := parseBytes(in)
		if !ok || got != want {
			t.Errorf("parseBytes(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}
}
