package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Edge cases of the conf -> Tunnel mapping: entries with missing keys are
// skipped instead of producing half-empty forwards/notes, and ssh defaults apply.

func TestCEJumpHopUnmarshalRejectsBrokenInput(t *testing.T) {
	var h jumpHop
	if err := h.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Error("an unterminated string must be an error")
	}
	if err := h.UnmarshalJSON([]byte(`{"host": 5}`)); err == nil {
		t.Error("a non-string host must be an error")
	}
	if err := h.UnmarshalJSON([]byte(`  "bob@bastion:2200" `)); err != nil || h.Host != "bob@bastion:2200" {
		t.Errorf("string form: err=%v host=%q", err, h.Host)
	}
}

func TestCETunnelFromConfSkipsIncompleteEntriesAndAppliesSSHDefaults(t *testing.T) {
	requireYq(t)
	d, _ := newTestDocker(t)
	if err := os.MkdirAll(d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const conf = `
socks: 1080
ssh:
  host: bastion
  user: ops
  jump:
    - first-hop
    - {host: second-hop, user: bob, port: 2222}
    - ""
hosts:
  - ip: ""
    forwards: [{remote: 22}]
  - ip: 10.0.0.5
    name: db
    tags: [prod]
    forwards:
      - remote: 22
      - local: 9999
      - remote: 5432
        local: 15432
        note: main
        user: pg
subnets:
  - cidr: ""
    label: ignored
  - cidr: 10.0.0.0/24
    label: LAN
    tags: [a]
  - cidr: 10.1.0.0/24
`
	if err := os.WriteFile(confPath(d.confDir, "edge"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	tun := d.tunnelFromConf("edge")

	if tun.Type != "vpn" {
		t.Errorf("a conf without type defaults to vpn, got %q", tun.Type)
	}
	if tun.Socks != "127.0.0.1:1080" {
		t.Errorf("socks = %q, want a bare port bound to loopback", tun.Socks)
	}
	if tun.sshEndpoint != "bastion:22" || tun.SSHHost != "bastion" || tun.User != "ops" {
		t.Errorf("ssh = endpoint %q host %q user %q", tun.sshEndpoint, tun.SSHHost, tun.User)
	}
	if want := []string{"first-hop", "bob@second-hop:2222"}; !reflect.DeepEqual(tun.SSHJump, want) {
		t.Errorf("SSHJump = %v, want %v (empty hop dropped)", tun.SSHJump, want)
	}
	if len(tun.Forwards) != 2 {
		t.Fatalf("forwards = %+v, want 2 (host without ip and forward without remote skipped)", tun.Forwards)
	}
	if f := tun.Forwards[0]; f.Remote != "10.0.0.5:22" || f.Service != "ssh" {
		t.Errorf("forward 0 = %+v", f)
	}
	if f := tun.Forwards[1]; f.Remote != "10.0.0.5:5432" || f.Service != "postgres" || f.Note != "main" || f.User != "pg" {
		t.Errorf("forward 1 = %+v", f)
	}
	if !reflect.DeepEqual(tun.HostNotes, map[string]string{"10.0.0.5": "db"}) ||
		!reflect.DeepEqual(tun.HostTags, map[string][]string{"10.0.0.5": {"prod"}}) {
		t.Errorf("host notes/tags = %v / %v", tun.HostNotes, tun.HostTags)
	}
	if !reflect.DeepEqual(tun.SubnetNotes, map[string]string{"10.0.0.0/24": "LAN"}) ||
		!reflect.DeepEqual(tun.SubnetTags, map[string][]string{"10.0.0.0/24": {"a"}}) {
		t.Errorf("subnet notes/tags = %v / %v (empty cidr must be skipped)", tun.SubnetNotes, tun.SubnetTags)
	}
}

func TestCETunnelFromConfSSHWithoutHostHasNoEndpoint(t *testing.T) {
	requireYq(t)
	d, _ := newTestDocker(t)
	if err := os.MkdirAll(d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath(d.confDir, "nohost"), []byte("type: ssh\nssh:\n  user: ops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tun := d.tunnelFromConf("nohost")
	if tun.sshEndpoint != "" || tun.SSHHost != "" || tun.User != "ops" {
		t.Errorf("endpoint %q host %q user %q", tun.sshEndpoint, tun.SSHHost, tun.User)
	}
}

func TestCETunnelFromConfUnreadableFileFallsBackToOffTunnel(t *testing.T) {
	requireYq(t)
	d, _ := newTestDocker(t)
	if err := os.MkdirAll(d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// not valid YAML: yq fails, the tunnel still shows up (off) instead of vanishing
	if err := os.WriteFile(filepath.Join(d.confDir, "broken.yaml"), []byte("a: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tun := d.tunnelFromConf("broken")
	if tun.ID != "broken" || tun.State != "off" || tun.Type != "vpn" || tun.Forwards == nil || tun.Tags == nil {
		t.Errorf("fallback tunnel = %+v", tun)
	}
}
