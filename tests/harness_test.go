// Package dissector drives `tshark` against the committed pcap fixtures
// (tests/pcap/) with the Lua dissector loaded, and asserts on the decoded
// protocol tree and extracted field values. It exercises both install forms in
// one run: the amalgamated single-file build (dist/tarantool.dissector.lua, if
// built) and the modular src/ loader (tarantool.lua). Set DISS to pin a single
// dissector path, TSHARK to override the tshark binary.
package dissector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pcapDir = "pcap"

var tsharkBin string

// isolatedEnv is the environment every tshark subprocess runs under: a throwaway
// HOME/XDG so tshark never auto-loads the user's *personal* Lua plugins. If those
// include a copy of this dissector, it collides with the one under test ("there
// cannot be two protocols with the same description") and derails every check.
var isolatedEnv []string

func TestMain(m *testing.M) {
	tsharkBin = findTshark()

	tmp, err := os.MkdirTemp("", "tnt-dissector-test-")
	if err != nil {
		panic(err)
	}
	isolatedEnv = append(os.Environ(),
		"HOME="+tmp,
		"XDG_DATA_HOME="+filepath.Join(tmp, "data"),
		"XDG_CONFIG_HOME="+filepath.Join(tmp, "config"),
	)

	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func findTshark() string {
	if t := os.Getenv("TSHARK"); t != "" {
		return t
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		return p
	}
	for _, c := range []string{"/Applications/Wireshark.app/Contents/MacOS/tshark"} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// requireTshark skips when the environment can't run the dissector: no tshark,
// or running as root (Wireshark disables -X lua_script under root).
func requireTshark(t *testing.T) {
	t.Helper()
	if tsharkBin == "" {
		t.Skip("tshark not found; set TSHARK or install Wireshark")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; Wireshark disables -X lua_script under root")
	}
}

type form struct {
	name string
	path string
}

// discoverForms returns the dissector forms to test. DISS pins a single path;
// otherwise both the amalgamated build (when dist/ has been generated) and the
// modular loader are tested, so a change that breaks only one form is caught.
func discoverForms(t *testing.T) []form {
	t.Helper()
	if d := os.Getenv("DISS"); d != "" {
		abs, err := filepath.Abs(d)
		require.NoErrorf(t, err, "resolving DISS=%q", d)
		return []form{{name: "custom", path: abs}}
	}
	var fs []form
	for _, c := range []struct{ name, rel string }{
		{"amalgamated", filepath.Join("..", "dist", "tarantool.dissector.lua")},
		{"modular", filepath.Join("..", "tarantool.lua")},
	} {
		if fi, err := os.Stat(c.rel); err == nil && !fi.IsDir() {
			abs, _ := filepath.Abs(c.rel)
			fs = append(fs, form{name: c.name, path: abs})
		}
	}
	require.NotEmpty(t, fs,
		"no dissector found: run ./amalgamate.sh to build dist/, or keep tarantool.lua in place")

	names := make([]string, len(fs))
	for i, f := range fs {
		names[i] = f.name
	}
	t.Logf("dissector forms under test: %v", names)

	// CI builds dist/ first and sets REQUIRE_AMALGAMATED so a missing amalgamated
	// build fails loudly instead of silently degrading to a modular-only run.
	if os.Getenv("REQUIRE_AMALGAMATED") != "" {
		hasAmalgamated := false
		for _, f := range fs {
			if f.name == "amalgamated" {
				hasAmalgamated = true
			}
		}
		require.True(t, hasAmalgamated,
			"REQUIRE_AMALGAMATED set but dist/tarantool.dissector.lua not found; run ./amalgamate.sh")
	}
	return fs
}

// run is one loaded capture: the cached protocol tree (-O tarantool) plus the
// context to re-run tshark for field/filter queries against the same capture.
type run struct {
	t    *testing.T
	diss string
	pcap string
	args []string // extra decode args, e.g. -d tcp.port==33013,tarantool
	tree string
	terr string
}

// decode loads a capture and caches its protocol tree, without asserting that
// anything decoded (used by the "dissector disabled" case).
func decode(t *testing.T, f form, pcap string, extra ...string) *run {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(pcapDir, pcap))
	require.NoErrorf(t, err, "resolving pcap %q", pcap)
	r := &run{t: t, diss: f.path, pcap: abs, args: extra}
	r.tree, r.terr = r.exec("-O", "tarantool")
	return r
}

// newRun is decode plus a preflight that fails fast if the dissector produced no
// output at all, rather than surfacing as dozens of missing-string errors.
func newRun(t *testing.T, f form, pcap string, extra ...string) *run {
	t.Helper()
	r := decode(t, f, pcap, extra...)
	require.Containsf(t, r.tree, "Tarantool",
		"dissector produced no Tarantool output for %s\ntshark stderr:\n%s", pcap, r.terr)
	return r
}

// exec runs tshark with the base capture/dissector args plus extra. The exit
// code is ignored (tshark exits 0 even when a filter matches nothing); the
// assertions read the output instead.
func (r *run) exec(extra ...string) (string, string) {
	r.t.Helper()
	args := []string{"-r", r.pcap, "-X", "lua_script:" + r.diss}
	args = append(args, r.args...)
	args = append(args, extra...)

	cmd := exec.Command(tsharkBin, args...)
	cmd.Env = isolatedEnv
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()
	return stdout.String(), stderr.String()
}

func (r *run) label() string { return filepath.Base(r.pcap) }

func (r *run) contains(sub string) {
	r.t.Helper()
	assert.Containsf(r.t, r.tree, sub, "decode of %s", r.label())
}

func (r *run) containsAll(subs ...string) {
	r.t.Helper()
	for _, s := range subs {
		r.contains(s)
	}
}

func (r *run) notContains(sub string) {
	r.t.Helper()
	assert.NotContainsf(r.t, r.tree, sub, "decode of %s", r.label())
}

func (r *run) matches(pattern string) {
	r.t.Helper()
	assert.Regexpf(r.t, pattern, r.tree, "decode of %s", r.label())
}

func (r *run) requests(names ...string) {
	r.t.Helper()
	for _, n := range names {
		r.contains("Request name: " + n)
	}
}

// tokens returns every value of a field, one per decoded PDU. A frame carrying
// pipelined PDUs yields comma-separated values, so both commas and newlines are
// split.
func (r *run) tokens(field string) []string {
	r.t.Helper()
	out, _ := r.exec("-T", "fields", "-e", field)
	return splitTokens(out)
}

// fieldWhere returns a field's values across frames matching a display filter.
func (r *run) fieldWhere(field, filter string) []string {
	r.t.Helper()
	out, _ := r.exec("-T", "fields", "-e", field, "-Y", filter)
	return splitTokens(out)
}

func splitTokens(out string) []string {
	var toks []string
	for _, line := range strings.Split(out, "\n") {
		for _, tok := range strings.Split(line, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				toks = append(toks, tok)
			}
		}
	}
	return toks
}

// requestHistogram counts request-direction PDUs per request name, PDU-scoped.
// Restricting to the request direction matters for the legacy protocol, where a
// response echoes the request's name (a "call" response also decodes as "call").
// A frame filter would be frame-scoped and over-count when a single segment
// pipelines both directions (e.g. a replication heartbeat OK alongside relayed
// rows); instead, tnt.request and tnt.response are extracted together (TAB-
// separated columns, comma-separated per PDU) and zipped so each name is counted
// only when its own tnt.response flag is False.
func (r *run) requestHistogram() map[string]int {
	r.t.Helper()
	out, _ := r.exec("-T", "fields", "-e", "tnt.request", "-e", "tnt.response")
	h := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) < 2 {
			continue
		}
		names := strings.Split(cols[0], ",")
		flags := strings.Split(cols[1], ",")
		for i, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			flag := ""
			if i < len(flags) {
				flag = strings.TrimSpace(flags[i])
			}
			if flag != "True" && flag != "1" {
				h[name]++
			}
		}
	}
	return h
}

// directionTotals counts the per-PDU tnt.response flag, authoritative even for
// pipelined frames.
func (r *run) directionTotals() (reqs, resps int) {
	r.t.Helper()
	for _, tok := range r.tokens("tnt.response") {
		switch tok {
		case "True", "1":
			resps++
		case "False", "0":
			reqs++
		}
	}
	return
}

// frames counts frames matching a display filter. A non-zero count also proves
// the field is registered and usable as a display filter.
func (r *run) frames(filter string) int {
	r.t.Helper()
	out, _ := r.exec("-T", "fields", "-e", "frame.number", "-Y", filter)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func (r *run) filterYields(filter string) {
	r.t.Helper()
	assert.NotZerof(r.t, r.frames(filter),
		"%s: display filter %q matched no frames (field unregistered or value absent)",
		r.label(), filter)
}

func (r *run) pduTotals(reqs, resps int) {
	r.t.Helper()
	gotReqs, gotResps := r.directionTotals()
	assert.Equalf(r.t, reqs, gotReqs, "%s: request PDU count", r.label())
	assert.Equalf(r.t, resps, gotResps, "%s: response PDU count", r.label())
}

// requestCounts asserts the exact count of each named request type. Only the
// listed names are checked, so responses (OK/ERROR) are ignored.
//
// requestHistogram is frame-filtered (-Y tnt.response==0), so it is only
// PDU-accurate when request and response PDUs never share a frame. Guard that
// assumption: the histogram's token total must equal the authoritative per-PDU
// request count, else a pipelined mixed-direction frame has leaked in.
func (r *run) requestCounts(want map[string]int) {
	r.t.Helper()
	h := r.requestHistogram()
	total := 0
	for _, n := range h {
		total += n
	}
	reqs, _ := r.directionTotals()
	assert.Equalf(r.t, reqs, total, "%s: histogram token total vs request PDU count", r.label())
	for name, n := range want {
		assert.Equalf(r.t, n, h[name], "%s: count of %q PDUs", r.label(), name)
	}
}

func (r *run) hasRequestsAndResponses() {
	r.t.Helper()
	reqs, resps := r.directionTotals()
	assert.NotZerof(r.t, reqs, "%s: no request PDUs decoded (tnt.response==0)", r.label())
	assert.NotZerof(r.t, resps, "%s: no response PDUs decoded (tnt.response==1)", r.label())
}

// syncPaired asserts every response's sync matches some request's sync. Only
// valid for captures without server-initiated PDUs in the response direction.
func (r *run) syncPaired() {
	r.t.Helper()
	reqSyncs := map[string]bool{}
	for _, s := range r.fieldWhere("tnt.sync", "tnt.response==0") {
		reqSyncs[s] = true
	}
	for _, s := range r.fieldWhere("tnt.sync", "tnt.response==1") {
		assert.Truef(r.t, reqSyncs[s], "%s: response sync %s has no matching request", r.label(), s)
	}
}

// decodesCleanly asserts no Lua error (tree or stderr), no payload-bearing frame
// left as generic "Data" (catches silent gaps), and no malformed dissection.
func (r *run) decodesCleanly() {
	r.t.Helper()
	assert.NotContainsf(r.t, r.tree, "Lua Error", "%s: 'Lua Error' in decoded tree", r.label())
	for _, marker := range []string{"Error during loading", "Lua: Error"} {
		assert.NotContainsf(r.t, r.terr, marker, "%s: tshark stderr reports a Lua error:\n%s", r.label(), r.terr)
	}
	assert.Zerof(r.t, r.frames("tcp.len>0 && data"),
		"%s: payload frame(s) left undecoded as generic Data", r.label())
	assert.Zerof(r.t, r.frames("_ws.malformed"), "%s: malformed frame(s)", r.label())
	// The dissector's own decode-failure markers: a body decoder that threw was
	// caught by a pcall. This is the primary signal that an unpinned PDU decoded
	// wrong. (The deliberate top-level "malformed or truncated MsgPack" note for a
	// non-conforming PDU is a different, expected string and is not flagged here.)
	assert.NotContainsf(r.t, r.tree, "malformed or non-conforming body", "%s: a body decoder threw", r.label())
	assert.NotContainsf(r.t, r.tree, "malformed legacy body", "%s: a legacy body decoder threw", r.label())
}

// TestModularLoaderIndirect guards the loader package.path fix: when tarantool.lua
// is dofile'd from a plugins-folder stub (the documented GUI-modular install)
// rather than being the -X lua_script target, it must still resolve the bundled
// MessagePack.lua (which lives at the repo root, not in src/).
func TestModularLoaderIndirect(t *testing.T) {
	requireTshark(t)
	loader, err := filepath.Abs(filepath.Join("..", "tarantool.lua"))
	require.NoError(t, err)
	if fi, statErr := os.Stat(loader); statErr != nil || fi.IsDir() {
		t.Skip("modular loader tarantool.lua not present")
	}
	stub := filepath.Join(t.TempDir(), "tnt.lua")
	require.NoError(t, os.WriteFile(stub, []byte("dofile(\""+loader+"\")\n"), 0o644))

	pcap, err := filepath.Abs(filepath.Join(pcapDir, "tarantool-3.x.pcap"))
	require.NoError(t, err)
	cmd := exec.Command(tsharkBin, "-r", pcap, "-X", "lua_script:"+stub, "-O", "tarantool")
	cmd.Env = isolatedEnv
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	_ = cmd.Run()

	assert.NotContains(t, errb.String(), "module 'MessagePack' not found")
	assert.NotContains(t, errb.String(), "Error during loading")
	assert.Contains(t, out.String(), "Request name:")
	// A decoded MP_EXT uuid proves the bundled MessagePack actually loaded.
	assert.Contains(t, out.String(), "55eca2de-8996-4375-9152-8fb5a4e7bb0a")
}

// TestNumberModelUnderLuaJIT runs the pure-Lua decoders under luajit (a
// float-number runtime) to prove uint64 and negative-epoch datetime decode
// exactly there — the case the Lua 5.4 reference tshark cannot exercise. Skips
// when luajit is unavailable.
func TestNumberModelUnderLuaJIT(t *testing.T) {
	lj, err := exec.LookPath("luajit")
	if err != nil {
		t.Skip("luajit not found; float-number exactness verified elsewhere")
	}
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	script, err := filepath.Abs("luajit_numbers.lua")
	require.NoError(t, err)
	out, err := exec.Command(lj, script, root).CombinedOutput()
	require.NoErrorf(t, err, "luajit number-model check failed:\n%s", out)
}

// TestModularLoaderCollision guards the private-registry isolation: a co-loaded
// plugin that squats the generic module names ('MessagePack', 'core', ...) in the
// global registry before ours loads must not break our decode. Without the shim,
// our require('core') would return the foreign empty table and crash.
func TestModularLoaderCollision(t *testing.T) {
	requireTshark(t)
	loader, err := filepath.Abs(filepath.Join("..", "tarantool.lua"))
	require.NoError(t, err)
	if fi, statErr := os.Stat(loader); statErr != nil || fi.IsDir() {
		t.Skip("modular loader tarantool.lua not present")
	}
	dir := t.TempDir()
	foreign := filepath.Join(dir, "aaa_foreign.lua")
	require.NoError(t, os.WriteFile(foreign, []byte(
		"package.loaded[\"MessagePack\"] = { unpackers = {}, packers = {} }\n"+
			"package.loaded[\"core\"] = {}\n"+
			"package.loaded[\"msgpack_ext\"] = {}\n"), 0o644))

	pcap, err := filepath.Abs(filepath.Join(pcapDir, "tarantool-3.x.pcap"))
	require.NoError(t, err)
	// Load the foreign plugin first, then ours.
	cmd := exec.Command(tsharkBin, "-r", pcap,
		"-X", "lua_script:"+foreign, "-X", "lua_script:"+loader, "-O", "tarantool")
	cmd.Env = isolatedEnv
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	_ = cmd.Run()

	assert.NotContains(t, errb.String(), "Error during loading")
	assert.Contains(t, out.String(), "Request name:")
	assert.Contains(t, out.String(), "55eca2de-8996-4375-9152-8fb5a4e7bb0a")
}
