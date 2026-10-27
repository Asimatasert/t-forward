package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServiceForPort(t *testing.T) {
	tests := []struct {
		port string
		want string
	}{
		{"22", "ssh"},
		{"80", "http"},
		{"8080", "http"},
		{"443", "https"},
		{"5432", "postgres"},
		{"3306", "mysql"},
		{"27017", "mongodb"},
		{"9200", "elastic"},
		{"6379", "redis"},
		{"12345", ""},  // numeric but unknown
		{"", ""},       // empty
		{"ssh", ""},    // not a number
		{"22/tcp", ""}, // suffix is not stripped
		{" 22", ""},    // no trimming
		{"-22", ""},
		{"0", ""},
	}
	for _, tc := range tests {
		t.Run(tc.port, func(t *testing.T) {
			if got := serviceForPort(tc.port); got != tc.want {
				t.Fatalf("serviceForPort(%q) = %q, want %q", tc.port, got, tc.want)
			}
		})
	}
}

func TestSplitTags(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"   ", []string{}},
		{"prod", []string{"prod"}},
		{"prod db", []string{"prod", "db"}},
		{"  prod \t db\n eu ", []string{"prod", "db", "eu"}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := splitTags(tc.in)
			if got == nil {
				t.Fatal("splitTags returned nil; panel JSON needs []")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitTags(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
	// JSON form: [] not null.
	b, _ := json.Marshal(splitTags(""))
	if string(b) != "[]" {
		t.Fatalf("json = %s, want []", b)
	}
}

func TestParseLabels(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"single", "a=b", map[string]string{"a": "b"}},
		{"several", "t-forward=1,t-forward.name=alpha,t-forward.type=ssh",
			map[string]string{"t-forward": "1", "t-forward.name": "alpha", "t-forward.type": "ssh"}},
		{"value with equals keeps rest", "k=a=b", map[string]string{"k": "a=b"}},
		{"empty value", "k=", map[string]string{"k": ""}},
		{"entry without equals skipped", "novalue,a=b", map[string]string{"a": "b"}},
		{"only junk", "x,y", map[string]string{}},
		{"tags with spaces", "t-forward.tags=prod db,t-forward.name=x",
			map[string]string{"t-forward.tags": "prod db", "t-forward.name": "x"}},
		{"later duplicate wins", "a=1,a=2", map[string]string{"a": "2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLabels(tc.in)
			if got == nil {
				t.Fatal("parseLabels returned nil map")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseLabels(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestMapState(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"running", "on"},
		{"Running", "on"},
		{"RUNNING", "on"},
		{"exited", "failed"},
		{"Exited", "failed"},
		{"dead", "failed"},
		{"created", "created"},
		{"restarting", "restarting"},
		{"paused", "paused"},
		{"", "off"},
		{"removing", "removing"}, // unknown states pass through
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := mapState(tc.in); got != tc.want {
				t.Fatalf("mapState(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alpha", "alpha"},
		{"Alpha", "alpha"},
		{"My VPN_01", "my-vpn-01"},
		{"a  b", "a-b"},
		{"a--b", "a-b"},
		{"a. _ b", "a-b"},
		{"--lead-and-trail--", "lead-and-trail"},
		{"  spaced  ", "spaced"},
		{"v2.0", "v2-0"},
		{"", ""},
		{"---", ""},
		{"!!!", ""},
		{"UPPER123", "upper123"},
		{"Çay", "ay"}, // non-ASCII letters are separators, as in the CLI
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := slugify(tc.in); got != tc.want {
				t.Fatalf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in     string
		want   float64
		wantOK bool
	}{
		{"0B", 0, true},
		{"512B", 512, true},
		{"512", 512, true}, // bare number = bytes
		{"1.2kB", 1200, true},
		{"1kB", 1000, true},
		{"1KB", 1000, true},
		{"1KiB", 1000, true}, // docker SI units: binary suffixes are treated as SI
		{"3.4MB", 3.4e6, true},
		{"2MiB", 2e6, true},
		{"1.5GB", 1.5e9, true},
		{"2TB", 2e12, true},
		{"  7kB  ", 7000, true},
		{"2 MB", 2e6, true}, // space between number and unit
		{".5kB", 500, true},
		{"", 0, false},
		{"   ", 0, false},
		{"kB", 0, false},  // no number
		{"abc", 0, false}, // no number
		{"1.2.3kB", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseBytes(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseBytes(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if ok && math.Abs(got-tc.want) > 1e-6 {
				t.Fatalf("parseBytes(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseNetIO(t *testing.T) {
	tests := []struct {
		in     string
		rx, tx float64
		wantOK bool
	}{
		{"0B / 0B", 0, 0, true},
		{"1.2kB / 3.4MB", 1200, 3.4e6, true},
		{"1.2kB/3.4MB", 1200, 3.4e6, true}, // spaces optional
		{"512B / 1GB", 512, 1e9, true},
		{"", 0, 0, false},
		{"garbage", 0, 0, false},
		{"1kB", 0, 0, false},             // no separator
		{"1kB / ", 0, 0, false},          // empty TX
		{" / 1kB", 0, 0, false},          // empty RX
		{"1kB / 2kB / 3kB", 0, 0, false}, // too many parts
		{"x / y", 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			rx, tx, ok := parseNetIO(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseNetIO(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if math.Abs(rx-tc.rx) > 1e-6 || math.Abs(tx-tc.tx) > 1e-6 {
				t.Fatalf("parseNetIO(%q) = %v,%v want %v,%v", tc.in, rx, tx, tc.rx, tc.tx)
			}
		})
	}
}

func TestNoisyLogLine(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"write completed", "2026/10/26 10:00:00 socat[42] N write(6, 0x55, 132) completed", true},
		{"read completed", "socat[42] N read(5, 0x55, 8192) completed", true},
		{"accepting connection kept", "socat[42] N accepting connection from AF=2 10.0.0.1:5555 on 10.0.0.2:22", false},
		{"write without completed", "socat[42] E write(6, 0x55, 132): Broken pipe", false},
		{"completed without socat", "rsync write(6, 1) completed", false},
		{"socat completed but not read/write", "socat[42] N poll() completed", false},
		{"plain log", "tunnel is up", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := noisyLogLine(tc.msg); got != tc.want {
				t.Fatalf("noisyLogLine(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		// benign container noise wins over the error keywords it contains
		{"vhost-net is benign", "Failed to open /dev/vhost-net", "log"},
		{"route flush benign", "Error: route/flush failed", "log"},
		{"read-only fs benign", "Failed to write: Read-only file system", "log"},
		{"cannot open benign", "Cannot open /proc/sys: Failed", "log"},

		{"accepting connection", "N accepting connection from 10.0.0.1", "conn"},
		{"connection from", "new connection from 10.0.0.1", "conn"},
		{"connect to", "connect to 10.0.0.5:22", "conn"},
		{"conn wins over failed", "connect to 10.0.0.5:22 failed", "conn"},

		{"tunnel is up", "tunnel is up", "tunnel"},
		{"READY", "READY", "tunnel"},
		{"reconnect", "reconnecting in 5s", "tunnel"},
		{"established", "ESP session established", "tunnel"},
		{"exited", "openconnect exited", "tunnel"},
		{"tunnel wins over failed", "reconnect failed", "tunnel"},

		{"password sent", "password sent", "auth"},
		{"verification code", "enter verification code", "auth"},
		{"awaiting", "awaiting_code", "auth"},
		{"waiting for", "waiting for TOTP", "auth"},
		{"auth wins over error", "waiting for code, previous attempt failed", "auth"},

		{"ERROR", "ERROR something broke", "error"},
		{"Error", "Error: boom", "error"},
		{"failed", "login failed", "error"},
		{"Failed", "Failed to connect", "error"},

		{"default", "just some output", "log"},
		{"empty", "", "log"},
		{"keywords are case-sensitive", "error occurred", "log"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.line); got != tc.want {
				t.Fatalf("classify(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		s    string
		subs []string
		want bool
	}{
		{"first matches", "hello world", []string{"hello", "xyz"}, true},
		{"last matches", "hello world", []string{"xyz", "world"}, true},
		{"none match", "hello world", []string{"foo", "bar"}, false},
		{"no subs", "hello", nil, false},
		{"empty haystack", "", []string{"a"}, false},
		{"case-sensitive", "Hello", []string{"hello"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := contains(tc.s, tc.subs...); got != tc.want {
				t.Fatalf("contains(%q, %v) = %v, want %v", tc.s, tc.subs, got, tc.want)
			}
		})
	}
}

func TestSplitTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantTS  string
		wantMsg string
	}{
		{"nano Z", "2026-10-26T10:00:00.123456789Z hello world", "2026-10-26T10:00:00.123456789Z", "hello world"},
		{"offset", "2026-10-26T10:00:00+03:00 msg", "2026-10-26T10:00:00+03:00", "msg"},
		{"message trimmed", "2026-10-26T10:00:00Z    padded  ", "2026-10-26T10:00:00Z", "padded"},
		{"timestamp only message empty", "2026-10-26T10:00:00Z ", "2026-10-26T10:00:00Z", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, msg := splitTimestamp(tc.line)
			if ts != tc.wantTS || msg != tc.wantMsg {
				t.Fatalf("splitTimestamp(%q) = (%q, %q), want (%q, %q)", tc.line, ts, msg, tc.wantTS, tc.wantMsg)
			}
		})
	}

	// No parsable leading timestamp: the whole line is the message and the
	// timestamp falls back to "now" in RFC3339.
	fallbacks := []string{
		"no timestamp here",
		"singleword",
		"",
		" leading space",
		"2026-10-26 10:00:00 date without T",     // head has no 'T'
		"Tuesday message with T but no colon-ts", // head has 'T' but no ':'
	}
	for _, line := range fallbacks {
		t.Run("fallback/"+line, func(t *testing.T) {
			before := time.Now().Add(-2 * time.Second)
			ts, msg := splitTimestamp(line)
			if msg != line {
				t.Fatalf("msg = %q, want whole line %q", msg, line)
			}
			parsed, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				t.Fatalf("fallback ts %q is not RFC3339: %v", ts, err)
			}
			if parsed.Before(before) || parsed.After(time.Now().Add(2*time.Second)) {
				t.Fatalf("fallback ts %q is not ~now", ts)
			}
		})
	}
}

func TestExtractCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "123456", "123456"},
		{"in sentence", "Your verification code is 482913. Do not share.", "482913"},
		{"newline terminated", "004321\n", "004321"}, // leading zeros kept
		{"first of several", "code 111111 then 222222", "111111"},
		{"4 digits", "pin 1234", "1234"},
		{"8 digits", "pin 12345678", "12345678"},
		{"too short", "abc 123", ""},
		{"no digits", "no digits here", ""},
		{"empty", "", ""},
		{"short run skipped for later long run", "id 12 code 998877", "998877"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractCode(tc.in); got != tc.want {
				t.Fatalf("extractCode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- state logic

func newTestDocker(t *testing.T) (*Docker, string) {
	t.Helper()
	dir := t.TempDir()
	d := NewDocker(NewHub(), dir, "t-forward")
	return d, dir
}

func TestNewDockerPaths(t *testing.T) {
	d := NewDocker(NewHub(), "/cfg", "/usr/bin/t-forward")
	if d.confDir != filepath.Join("/cfg", "conf.d") {
		t.Errorf("confDir = %q", d.confDir)
	}
	if d.stateDir != filepath.Join("/cfg", ".auth") {
		t.Errorf("stateDir = %q", d.stateDir)
	}
	if d.tfPath != "/usr/bin/t-forward" || d.hub == nil {
		t.Errorf("tfPath/hub not set: %q %v", d.tfPath, d.hub)
	}
	if d.live == nil || d.tailers == nil || d.lastNet == nil || d.armed == nil ||
		d.confCache == nil || d.lastWarnAt == nil {
		t.Error("NewDocker left a map nil")
	}
	if d.lastTunState != nil {
		t.Error("lastTunState must start nil so startup never notifies")
	}
}

func TestUpdateLive(t *testing.T) {
	d, _ := newTestDocker(t)

	d.updateLive("alpha", func(ld *liveData) {
		ld.txRate, ld.rxRate = 10, 20
		ld.tunIP = "10.0.0.2"
	})
	ld := d.live["alpha"]
	if ld == nil || ld.txRate != 10 || ld.rxRate != 20 || ld.tunIP != "10.0.0.2" {
		t.Fatalf("created entry = %+v", ld)
	}

	// Second update mutates the same entry in place and keeps other fields.
	first := ld
	d.updateLive("alpha", func(ld *liveData) { ld.txRate = 99 })
	if d.live["alpha"] != first {
		t.Fatal("updateLive replaced the entry instead of mutating it")
	}
	if first.txRate != 99 || first.rxRate != 20 || first.tunIP != "10.0.0.2" {
		t.Fatalf("after update = %+v", first)
	}

	// Entries are per tunnel id.
	d.updateLive("beta", func(ld *liveData) { ld.tunSubnet = "10.1.0.0/24" })
	if d.live["alpha"].tunSubnet != "" || d.live["beta"].tunSubnet != "10.1.0.0/24" {
		t.Fatalf("entries leaked across ids: %+v %+v", d.live["alpha"], d.live["beta"])
	}
	if len(d.live) != 2 {
		t.Fatalf("live has %d entries, want 2", len(d.live))
	}
}

func TestUpdateLiveConcurrent(t *testing.T) {
	d, _ := newTestDocker(t)
	const workers, iters = 8, 250
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				d.updateLive("t", func(ld *liveData) { ld.txRate++ })
			}
		}()
	}
	wg.Wait()
	if got := d.live["t"].txRate; got != workers*iters {
		t.Fatalf("txRate = %d, want %d (lost updates)", got, workers*iters)
	}
}

func TestIsWaiting(t *testing.T) {
	d, stateDir := newTestDocker(t)
	d.stateDir = stateDir

	mark := func(id string, files ...string) {
		t.Helper()
		dir := filepath.Join(stateDir, "auth-"+slugify(id))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	tests := []struct {
		name  string
		id    string
		files []string // nil + skipMark => no dir at all
		skip  bool
		want  bool
	}{
		{"no auth dir", "ghost", nil, true, false},
		{"empty auth dir", "empty", nil, false, false},
		{"awaiting only", "waiter", []string{"awaiting_code"}, false, true},
		{"ready only", "ready-only", []string{"ready"}, false, false},
		{"awaiting and ready", "done", []string{"awaiting_code", "ready"}, false, false},
		{"id is slugified", "My VPN", []string{"awaiting_code"}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.skip {
				mark(tc.id, tc.files...)
			}
			if got := d.isWaiting(tc.id); got != tc.want {
				t.Fatalf("isWaiting(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}

	// Becoming ready flips a waiting tunnel back.
	mark("flip", "awaiting_code")
	if !d.isWaiting("flip") {
		t.Fatal("expected waiting")
	}
	mark("flip", "ready")
	if d.isWaiting("flip") {
		t.Fatal("ready marker must end the waiting state")
	}
}

// stubDocker puts a fake `docker` first on PATH. `docker ps` prints the
// contents of the returned psFile (one JSON object per line); every other
// subcommand (port, …) exits 1 with no output. This keeps the tests off the
// real daemon and independent of whatever containers the host runs.
func stubDocker(t *testing.T) (psFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs need a POSIX sh")
	}
	dir := t.TempDir()
	psFile = filepath.Join(dir, "ps.json")
	script := "#!/bin/sh\nif [ \"$1\" = ps ]; then cat \"$TEST_DOCKER_PS\"; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(psFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty `yq` dir entry is not needed: without yq the conf reader fails
	// and tunnelFromConf falls back to a bare "off" tunnel, which is all
	// these tests rely on.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_DOCKER_PS", psFile)
	return psFile
}

func psLine(name, state string) string {
	b, _ := json.Marshal(map[string]string{
		"Names":  "tf-" + name,
		"State":  state,
		"Labels": "t-forward=1,t-forward.name=" + name + ",t-forward.type=ssh,t-forward.tags=prod eu",
		"Ports":  "",
	})
	return string(b) + "\n"
}

func setPS(t *testing.T, psFile string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(psFile, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// snapshotOf pulls the pending 'state' frame off the client and decodes it.
func snapshotOf(t *testing.T, c *client) []Tunnel {
	t.Helper()
	select {
	case f := <-c.state:
		s := string(f)
		const head = "event: state\ndata: "
		if !strings.HasPrefix(s, head) {
			t.Fatalf("not a state frame: %q", s)
		}
		var out []Tunnel
		if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(s, head), "\n\n")), &out); err != nil {
			t.Fatalf("decode snapshot: %v\n%s", err, s)
		}
		return out
	default:
		t.Fatal("no state frame was broadcast")
		return nil
	}
}

func byID(ts []Tunnel) map[string]Tunnel {
	m := make(map[string]Tunnel, len(ts))
	for _, tn := range ts {
		m[tn.ID] = tn
	}
	return m
}

func TestBroadcastStateSnapshot(t *testing.T) {
	psFile := stubDocker(t)
	d, dir := newTestDocker(t)
	setPS(t, psFile, psLine("alpha", "running"), psLine("beta", "exited"), psLine("gamma", "running"))
	// gamma is running but waiting for a TOTP code
	waitDir := filepath.Join(d.stateDir, "auth-gamma")
	if err := os.MkdirAll(waitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(waitDir, "awaiting_code"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// delta is configured (conf.d) but has no container
	if err := os.MkdirAll(d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.confDir, "delta.yaml"), []byte("type: vpn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// non-yaml files and directories in conf.d are ignored
	_ = os.WriteFile(filepath.Join(d.confDir, "notes.txt"), nil, 0o600)
	_ = os.MkdirAll(filepath.Join(d.confDir, "sub.yaml"), 0o700)
	_ = dir

	c := d.hub.register()
	d.broadcastState()
	snap := snapshotOf(t, c)

	ids := make([]string, len(snap))
	for i, tn := range snap {
		ids[i] = tn.ID
	}
	if want := []string{"alpha", "beta", "delta", "gamma"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("snapshot ids = %v, want %v (sorted)", ids, want)
	}
	m := byID(snap)
	for id, want := range map[string]string{"alpha": "on", "beta": "failed", "gamma": "waiting", "delta": "off"} {
		if got := m[id].State; got != want {
			t.Errorf("%s state = %q, want %q", id, got, want)
		}
	}
	if m["alpha"].Type != "ssh" {
		t.Errorf("alpha type = %q, want ssh (from label)", m["alpha"].Type)
	}
	if !reflect.DeepEqual(m["alpha"].Tags, []string{"prod", "eu"}) {
		t.Errorf("alpha tags = %v", m["alpha"].Tags)
	}

	// first snapshot only records state; it must not diff against anything
	d.mu.Lock()
	got := d.lastTunState
	d.mu.Unlock()
	want := map[string]string{"alpha": "on", "beta": "failed", "gamma": "waiting", "delta": "off"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lastTunState = %v, want %v", got, want)
	}
}

func TestBroadcastStateTracksTransitions(t *testing.T) {
	psFile := stubDocker(t)
	d, _ := newTestDocker(t)
	c := d.hub.register()

	setPS(t, psFile, psLine("alpha", "running"))
	d.broadcastState()
	snapshotOf(t, c)
	d.mu.Lock()
	first := d.lastTunState
	d.mu.Unlock()
	if first == nil || first["alpha"] != "on" {
		t.Fatalf("lastTunState after 1st = %v", first)
	}

	// alpha goes down, a new tunnel appears
	setPS(t, psFile, psLine("alpha", "exited"), psLine("beta", "running"))
	d.broadcastState()
	snap := byID(snapshotOf(t, c))
	if snap["alpha"].State != "failed" || snap["beta"].State != "on" {
		t.Fatalf("2nd snapshot = %+v", snap)
	}
	d.mu.Lock()
	second := d.lastTunState
	d.mu.Unlock()
	if !reflect.DeepEqual(second, map[string]string{"alpha": "failed", "beta": "on"}) {
		t.Fatalf("lastTunState after 2nd = %v", second)
	}
	// previous map is replaced, not mutated in place
	if first["alpha"] != "on" {
		t.Fatal("lastTunState map was mutated in place")
	}

	// alpha comes back
	setPS(t, psFile, psLine("alpha", "running"), psLine("beta", "running"))
	d.broadcastState()
	snapshotOf(t, c)
	d.mu.Lock()
	third := d.lastTunState
	d.mu.Unlock()
	if third["alpha"] != "on" {
		t.Fatalf("lastTunState after 3rd = %v", third)
	}
}

// Live data cached by the background loops is folded into running tunnels in
// the snapshot, but not into tunnels that are not "on".
func TestBroadcastStateFoldsLiveData(t *testing.T) {
	psFile := stubDocker(t)
	d, _ := newTestDocker(t)
	setPS(t, psFile, psLine("up", "running"), psLine("down", "exited"))
	for _, id := range []string{"up", "down"} {
		d.updateLive(id, func(ld *liveData) {
			ld.txRate, ld.rxRate = 111, 222
			ld.tunIP = "10.9.9.9"
			ld.hostUp = map[string]bool{"10.0.0.5": true}
			ld.portUp = map[string]bool{"10.0.0.5:22": false}
		})
	}
	c := d.hub.register()
	d.broadcastState()
	m := byID(snapshotOf(t, c))

	up := m["up"]
	if up.TxRate != 111 || up.RxRate != 222 || up.TunIP != "10.9.9.9" ||
		!up.HostUp["10.0.0.5"] || up.PortUp["10.0.0.5:22"] {
		t.Errorf("running tunnel missing live data: %+v", up)
	}
	down := m["down"]
	if down.TxRate != 0 || down.RxRate != 0 || down.TunIP != "" || down.HostUp != nil {
		t.Errorf("non-running tunnel must not carry live data: %+v", down)
	}
}

func TestBroadcastStateNoDockerNoConf(t *testing.T) {
	psFile := stubDocker(t)
	d, _ := newTestDocker(t) // confDir does not exist, docker ps prints nothing
	_ = psFile
	c := d.hub.register()
	d.broadcastState()
	snap := snapshotOf(t, c)
	if len(snap) != 0 {
		t.Fatalf("snapshot = %+v, want empty", snap)
	}
	// An empty snapshot must serialise as [] for the panel, not null.
	d.broadcastState()
	f := string(<-c.state)
	if !strings.Contains(f, "data: []") {
		t.Fatalf("empty snapshot frame = %q, want data: []", f)
	}
}
