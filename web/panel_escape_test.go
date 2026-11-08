package main

// Static guards for the panel's innerHTML output escaping. The panel
// (panel/index.html) renders daemon/config-derived text (tunnel ids, notes,
// hosts, SSE event text, scan results) through innerHTML, so every such value
// must pass through esc() first. Inventory: see the PR description
// (23 innerHTML sites, one missing escape found and fixed: `pill ${t.state}`).
//
// All identifiers carry the tEsc prefix to stay clear of other test files.

import (
	"regexp"
	"strings"
	"testing"
)

func tEscPanel(t *testing.T) string {
	t.Helper()
	b, err := panelFS.ReadFile("panel/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// esc() must cover & < > " ' (text AND attribute contexts), with & first so
// the entities it produces are not double-escaped.
func TestTEscFuncCoversFiveChars(t *testing.T) {
	src := tEscPanel(t)
	m := regexp.MustCompile(`(?s)function esc\(s\) \{(.*?)\n\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("function esc(s) not found in panel/index.html")
	}
	body := m[1]
	steps := []struct{ char, from, to string }{
		{"&", `/&/g`, `"&amp;"`},
		{"<", `/</g`, `"&lt;"`},
		{">", `/>/g`, `"&gt;"`},
		{`"`, `/"/g`, `"&quot;"`},
		{"'", `/'/g`, `"&#39;"`},
	}
	last := -1
	for _, s := range steps {
		re := regexp.MustCompile(`\.replace\(` + regexp.QuoteMeta(s.from) + `,\s*` + regexp.QuoteMeta(s.to) + `\)`)
		loc := re.FindStringIndex(body)
		if loc == nil {
			t.Errorf("esc() does not escape %s (want .replace(%s, %s))", s.char, s.from, s.to)
			continue
		}
		if s.char == "&" {
			last = loc[0]
		} else if last >= 0 && loc[0] < last {
			t.Errorf("esc() must escape & first, but %s is replaced before it", s.char)
		}
	}
	if !strings.Contains(body, `s == null ? ""`) {
		t.Error("esc() must map null/undefined to the empty string")
	}
}

// The one gap found by the audit: the tunnel state came from the daemon
// (mapState passes unknown values through) and landed raw in a class attribute.
func TestTEscTunnelStateNotRawInAttribute(t *testing.T) {
	src := tEscPanel(t)
	if strings.Contains(src, "${t.state}") {
		t.Error("raw ${t.state} interpolated into innerHTML; wrap it in esc()")
	}
	if !strings.Contains(src, `<span class="pill ${esc(t.state)} `) {
		t.Error(`renderTunnel pill must use class="pill ${esc(t.state)} …"`)
	}
}

// Every daemon/config-derived value that reaches innerHTML, pinned by its
// escaped form. Removing an esc( call makes the matching entry go missing.
func TestTEscPinnedInterpolations(t *testing.T) {
	src := tEscPanel(t)
	pinned := []string{
		// events (SSE text)
		"${esc(e.ts)}", "${esc(e.lvl)}", "${esc(e.lvl.toUpperCase())}", "${esc(e.tun)}", "${esc(e.msg)}",
		// tag bar / LAN port chips
		`"#" + esc(tag)`, `data-port="${esc(String(port))}">${esc(String(port))}`,
		// tree
		`data-tun="${esc(t.id)}" data-host="${esc(h)}"`, `data-cidr="${esc(cidr)}"`,
		"${esc(f.service)}", "${esc(f.note)}", "${esc(lp)}", "${esc(name)}",
		`<span class="tr-name">${esc(t.id)}</span>`, "${esc(note)}${esc(ourIP)}",
		"via ${esc(t.jump.tun)} @ ${esc(t.jump.host)}", `.map((x) => esc(x)).join(" → ")`,
		`tr-dot ${esc(t.state)}`,
		// LAN overview + device panel
		`data-rescan="${esc(i.name)}"`, "${esc(i.cidr || \"\")}", "<h1>${esc(ip)}</h1>",
		"${esc(dtitle)}", `${esc(dev.name || "(no name)")}`, "${esc(dev.ip)}", "${esc(dev.host)}",
		"${esc(ifname)}", "${esc(dev.mac)}", "${esc(deviceKey(dev))}", "#${esc(x)}",
		`data-fwd="${esc(String(p.port))}"`,
		// tunnel panel
		"<h1>${esc(t.id)} ", `${esc(String(t.type || "").toUpperCase())}`, `${esc(t.desc || "(no name)")}`,
		"${esc(t.tunIP)}", "${esc(t.tunSubnet)}", "${esc(t.socks)}",
		`title="${esc(connString(f))}"`, `title="open ${esc(uri)}"`,
		"${esc(f.local)}", "${esc(f.remote)}", `${esc(c.ip === "127.0.0.1" ? "localhost" : c.ip)}`,
		`${esc(c.proc || c.mac || "")} :${esc(String(c.port))}`,
		`${esc(t.user ? t.user + "@" : "")}${esc(t.sshHost || "(no host)")}`,
		"${esc(t.sshHost)}", "t-forward logs ${esc(t.id)}",
		// host / subnet panels
		"<h1>${esc(host)} ", `${esc(note || "(no name)")}`, "${esc(t.type)} · ${esc(t.state)}",
		"${esc(hostSub)}", "<h1>${esc(cidr)} ", `${esc(note || "(no label)")}`,
		`data-host="${esc(ip)}"`, "${esc(nm)}", `${esc(t.tunIP || "—")}`,
		// pubHost banner
		"${esc(pubHost())}",
		// settings (server-provided values in value="")
		`value="${esc(topics[k] || "")}"`, `value="${esc(s.telegramChatId || "")}"`,
	}
	for _, p := range pinned {
		if !strings.Contains(src, p) {
			t.Errorf("escaped interpolation missing from panel/index.html: %s", p)
		}
	}
}

// The inventory in the PR covers exactly the current innerHTML sites. A new
// one must be audited (and the inventory + this number updated) on purpose.
func TestTEscInnerHTMLSiteCount(t *testing.T) {
	src := tEscPanel(t)
	n := len(regexp.MustCompile(`\.innerHTML\s*=`).FindAllStringIndex(src, -1))
	if n != 23 {
		t.Errorf("panel/index.html has %d innerHTML assignments, audited 23: audit the new/removed site for esc() and update panel-esc-envanter.md + this count", n)
	}
	for _, sink := range []string{".outerHTML", "insertAdjacentHTML", "document.write(", "eval("} {
		if strings.Contains(src, sink) {
			t.Errorf("unaudited HTML sink %q in panel/index.html", sink)
		}
	}
}
