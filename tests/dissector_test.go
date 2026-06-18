package dissector

import (
	"strings"
	"testing"
)

var replicationPorts = []string{
	"-d", "tcp.port==3311,tarantool",
	"-d", "tcp.port==3312,tarantool",
	"-d", "tcp.port==3313,tarantool",
}

// scenarios is the per-fixture test table. Every scenario runs against every
// discovered install form.
var scenarios = []struct {
	name string
	fn   func(*testing.T, form)
}{
	{"fields_registered", testFieldsRegistered},
	{"legacy_1.5", testLegacy15},
	{"modern_1.10", testModern110},
	{"modern_2.11", testModern211},
	{"enabled_pref", testEnabledPref},
	{"modern_3.x", testModern3x},
	{"combined", testCombined},
	{"replication_async", testReplicationAsync},
	{"replication_sync", testReplicationSync},
	{"ports_range_pref", testPortsRange},
	{"null_in_tuple", testNullInTuple},
	{"uint64_render", testUint64Render},
	{"datetime_negative", testDatetimeNegative},
	{"reassembly", testReassembly},
	{"misc_opcodes", testMiscOpcodes},
}

// The exact PDU totals and per-request-type counts below are properties of the
// committed captures. Re-capturing a fixture means updating its numbers here --
// which is the point: a decode regression that drops or misclassifies PDUs shows
// up as a count mismatch. "OK" request-direction PDUs (replication heartbeats /
// pushes) are intentionally left unpinned.
func TestDissector(t *testing.T) {
	requireTshark(t)
	for _, f := range discoverForms(t) {
		t.Run(f.name, func(t *testing.T) {
			for _, sc := range scenarios {
				t.Run(sc.name, func(t *testing.T) { sc.fn(t, f) })
			}
		})
	}
}

// testFieldsRegistered verifies all six declared ProtoFields are registered and
// usable as display filters, using the 2.11 capture (which exercises each one).
func testFieldsRegistered(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-2.11.pcap")
	for _, field := range []string{
		"tnt.type", "tnt.request", "tnt.sync",
		"tnt.schema_version", "tnt.stream_id", "tnt.response",
	} {
		r.filterYields(field)
	}
}

// Tarantool 1.5: legacy binary protocol (captured on 33013).
func testLegacy15(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-1.5.pcap", "-d", "tcp.port==33013,tarantool")
	r.decodesCleanly()

	r.pduTotals(20, 20)
	r.requestCounts(map[string]int{
		"call": 12, "insert": 4, "select": 2, "update": 1, "delete": 1,
	})
	r.requests("insert", "select", "update", "delete", "call")
	r.containsAll(
		"Tarantool request (legacy <= 1.5)",
		"Tarantool response (legacy <= 1.5)",
		"legacy header: type 13 (insert)",
		"legacy header: type 17 (select)",
		"legacy header: type 19 (update)",
		"legacy header: type 21 (delete)",
		"legacy header: type 22 (call)",
		"function: box.dostring",
		`{1, "alpha", 100}`,
		`{2, "beta", 200}`,
		`{3, "gamma", 300}`,
		`{1, "ALPHA", 111}`,
		`{"beta"}`,
		`{"return box.space[0]:len()"}`,
		"return code: 0x00000000 (ok)",
		"error: Procedure 'nonexistent_function' is not defined",
		"limit: unlimited", // legacy SELECT with limit 0xffffffff
	)
	r.hasRequestsAndResponses()
	r.filterYields(`tnt.request=="call"`)
	r.filterYields("tnt.type==0x16")
}

// Tarantool 1.10: MsgPack, no SQL/streams/watchers.
func testModern110(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-1.10.pcap")
	r.decodesCleanly()

	r.pduTotals(15, 15)
	r.requestCounts(map[string]int{
		"auth": 1, "ping": 1, "insert": 3, "replace": 1, "update": 1,
		"upsert": 1, "delete": 1, "select": 4, "call": 1, "eval": 1,
	})
	r.requests("auth", "ping", "insert", "replace", "update", "upsert", "delete", "select", "call", "eval")
	r.matches("Sync: [0-9]")
	r.containsAll(
		`tuple: {1, "a", 10}`,
		`tuple: {1, "b", 20}`,
		"myfunc(2, 3)",
		"eval return 1 + 1, box.info.version with args ()",
		"message: Duplicate key exists in unique index 'pk' in space 'tester'",
	)
	r.contains("Tarantool greeting")
	r.contains("Server version: Tarantool 1.10")
	r.matches(`Salt: [A-Za-z0-9+/]+=*`)
	r.hasRequestsAndResponses()
	r.syncPaired()
	r.filterYields(`tnt.request=="auth"`)
	r.filterYields("tnt.type==0x40")
	r.filterYields("tnt.sync>0")
}

// Tarantool 2.11: + SQL, streams, watchers, structured error stack.
func testModern211(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-2.11.pcap")
	r.decodesCleanly()

	r.pduTotals(41, 34)
	r.requestCounts(map[string]int{
		"auth": 1, "id": 1, "ping": 1, "insert": 5, "replace": 1, "update": 1,
		"upsert": 1, "delete": 1, "select": 10, "call": 1, "eval": 1,
		"execute": 4, "prepare": 2, "begin": 2, "commit": 1, "rollback": 1,
		"watch": 4, "unwatch": 1, "event": 2,
	})
	r.requests("auth", "id", "ping", "insert", "replace", "update", "upsert", "delete",
		"select", "call", "eval", "execute", "prepare", "begin", "commit", "rollback",
		"watch", "unwatch", "event")
	r.containsAll(
		`tuple: {1, "a", 10}`,
		`tuple: {100, "tx", 1}`,
		`tuple: {101, "rb", 1}`,
		`execute SQL "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v STRING)"`,
		`prepare SQL "SELECT * FROM t WHERE id = ?"`,
		"ID : integer",
		"V : string",
		`{1, "one"}`,
		`{2, "two"}`,
		"sql row_count: 2",
		`[1] ClientError (code 3): Duplicate key exists in unique index "pk" in space "tester" with old tuple - [1, "b", 99] and new tuple - [1, "dup"]`,
		`Authentication: user "test", mechanism chap-sha1`,
		`SELECT FROM space 512 WHERE index(0) = (2) LIMIT 2 OFFSET 0 ITERATOR EQ`,
		`SELECT FROM space 512 WHERE index(0) = () LIMIT 10 OFFSET 0 ITERATOR ALL`,
		`DELETE FROM space(512) WHERE index(0) = (2)`,
		"execute prepared statement id", // prepared-statement execute
		"with parameters (",             // SQL bind parameters
		`ops: {`,                        // update/upsert operations list
		`{"+", 3, 5}`,                   // a decoded update operation
		"at ./src/box/",                 // structured error frame file:line
	)
	r.contains("Tarantool greeting")
	r.contains("Server version: Tarantool 2.11")
	r.hasRequestsAndResponses()
	r.filterYields(`tnt.request=="execute"`)
	r.filterYields("tnt.type==0x40")
	r.filterYields("tnt.stream_id")
	r.filterYields("tnt.schema_version>0")
}

// "enabled" preference: FALSE unregisters the port so nothing is decoded. The
// enabled control over the same capture proves an empty result means "disabled",
// not "failed to load".
func testEnabledPref(t *testing.T, f form) {
	on := newRun(t, f, "tarantool-2.11.pcap")
	on.contains("Request name:")

	// Positive control: an explicit enabled:TRUE still decodes, proving the
	// preference name is honored — so the FALSE case's empty output means
	// "disabled", not "tshark rejected an unknown -o flag".
	ctrl := decode(t, f, "tarantool-2.11.pcap", "-o", "tarantool.enabled:TRUE")
	ctrl.contains("Request name:")

	off := decode(t, f, "tarantool-2.11.pcap", "-o", "tarantool.enabled:FALSE")
	off.notContains("Request name:")
	off.notContains("Tarantool request") // actual disabled-case labels, not a string the dissector never emits
	off.notContains("Tarantool response")
	off.pduTotals(0, 0)
}

// Tarantool 3.x: + watch_once + MsgPack ext types.
func testModern3x(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-3.x.pcap")
	r.decodesCleanly()

	r.pduTotals(44, 37)
	r.requestCounts(map[string]int{
		"auth": 1, "id": 1, "ping": 1, "insert": 5, "replace": 3, "update": 1,
		"upsert": 1, "delete": 1, "select": 10, "call": 1, "eval": 1,
		"execute": 4, "prepare": 2, "begin": 2, "commit": 1, "rollback": 1,
		"watch": 4, "unwatch": 1, "watch_once": 1, "event": 2,
	})
	r.requests("auth", "id", "ping", "insert", "replace", "update", "upsert", "delete",
		"select", "call", "eval", "execute", "prepare", "begin", "commit", "rollback",
		"watch", "unwatch", "watch_once", "event")
	r.containsAll(
		`tuple: {1, "a", 10}`,
		`tuple: {100, "tx", 1}`,
		`execute SQL "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v STRING)"`,
		"id : integer", // 3.x preserves lower-case (2.11 upper-cases)
		"v : string",
		`{1, "one"}`,
		"sql row_count: 2",
		`[1] ClientError (code 3): Duplicate key exists in unique index "pk" in space "tester" with old tuple - [1, "b", 99] and new tuple - [1, "dup"]`,
		`tuple: {200, -12.345, 55eca2de-8996-4375-9152-8fb5a4e7bb0a, 2026-06-16T21:04:20.672283Z}`,
		`tuple: {201, {year=26, month=5, day=15, hour=21, min=4, sec=20, nsec=672379000, adjust=1}}`,
		"execute prepared statement id",
		"with parameters (",
		`ops: {`,
		`{"+", 3, 5}`,
		"at ./src/box/",
	)
	r.contains("Server version: Tarantool 3.")
	r.hasRequestsAndResponses()
	r.filterYields(`tnt.request=="watch_once"`)
}

// Combined 1.5 + 3.x: both framings decoded in one mixed capture.
func testCombined(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-combined.pcap", "-d", "tcp.port==33013,tarantool")
	r.decodesCleanly()

	r.pduTotals(64, 57)
	// call/insert/select counts are legacy 1.5 + 3.x merged; execute/prepare/
	// watch_once are modern-only.
	r.requestCounts(map[string]int{
		"call": 13, "insert": 9, "select": 12,
		"execute": 4, "prepare": 2, "watch_once": 1,
	})
	r.containsAll(
		"Tarantool request (legacy <= 1.5)",
		"Tarantool response (legacy <= 1.5)",
		"function: box.dostring",
		`{1, "alpha", 100}`,
	)
	r.requests("execute", "prepare", "watch_once")
	r.containsAll(
		`[1] ClientError (code 3): Duplicate key exists in unique index "pk" in space "tester" with old tuple - [1, "b", 99] and new tuple - [1, "dup"]`,
		`tuple: {200, -12.345, 55eca2de-8996-4375-9152-8fb5a4e7bb0a, 2026-06-16T21:04:20.672283Z}`,
	)
	r.hasRequestsAndResponses()
}

// Master-master replication, ASYNC: 3-node full mesh (ports 3311-3313).
// Bootstrap (join/subscribe), then asynchronous writes -- non-conflicting,
// conflicting and over a stream -- replicated across the mesh.
func testReplicationAsync(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-replication-async.pcap", replicationPorts...)
	r.decodesCleanly()

	r.pduTotals(1823, 955)
	r.requestCounts(map[string]int{
		"join": 2, "join_meta": 2, "join_snapshot": 2, "subscribe": 7,
		"auth": 7, "insert": 894, "select": 616, "eval": 21, "raft": 9,
		"raft_promote": 2, "watch": 51, "event": 39, "id": 164,
		"begin": 2, "commit": 1, "rollback": 1, "ping": 3,
	})
	r.requests("join", "subscribe", "insert", "select", "begin", "commit", "rollback")
	r.containsAll(
		"instance_uuid:",
		"replicaset_uuid:",
		"vclock:",
		"event key: internal.ballot",
		`tuple: {100, "node-1-row-0"}`,     // non-conflicting async write
		`tuple: {1, "inserted-on-node-2"}`, // conflicting writes from two nodes
		`tuple: {1, "inserted-on-node-3"}`,
		`tuple: {500, "tx-a"}`, // streamed transaction body
		`tuple: {501, "tx-b"}`,
	)
}

// Master-master replication, SYNC: node 1 promoted to leader. RAFT_PROMOTE then
// synchronous-space commits acknowledged with quorum (RAFT_CONFIRM).
func testReplicationSync(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-replication-sync.pcap", replicationPorts...)
	r.decodesCleanly()

	r.pduTotals(73, 72)
	r.requestCounts(map[string]int{
		"raft": 6, "raft_promote": 4, "raft_confirm": 12,
		"insert": 16, "replace": 5, "select": 12, "begin": 1, "commit": 1,
	})
	r.requests("raft", "raft_promote", "raft_confirm")
	r.containsAll(
		"replica_id: 1, lsn:",
		"term: 2",
		`tuple: {1, "sync-quorum-commit"}`,
		`tuple: {1, "sync-updated"}`,
		`tuple: {2, "sync-tx-1"}`,
		`tuple: {3, "sync-tx-2"}`,
	)
}

// Ports-range preference: point the default-3301 build's "ports" range at the
// mesh and confirm it decodes there with no -d mapping.
func testPortsRange(t *testing.T, f form) {
	r := newRun(t, f, "tarantool-replication-async.pcap", "-o", "tarantool.ports:3311-3313")
	r.decodesCleanly()
	r.requestCounts(map[string]int{"join": 2, "subscribe": 7, "insert": 894})
	r.requests("join", "subscribe", "insert")
	r.contains("vclock:")
}

// The synthetic-*.pcap fixtures below are hand-crafted (tests/gen_synthetic_pcaps.py)
// to exercise edge cases real captures don't. They decode on the default port 3301.

// box.NULL in a non-final array position must be preserved, not dropped. Guards
// the regression where a msgpack nil became a Lua table hole that truncated the
// tuple ("{1}") or misrendered a result row ("{1, 3 = 3}").
func testNullInTuple(t *testing.T, f form) {
	r := newRun(t, f, "synthetic-null.pcap")
	r.decodesCleanly()
	r.contains(`tuple: {1, nil, 3}`) // request tuple
	r.contains(`{1, nil, 3}`)        // response data row
	r.notContains("3 = 3")           // the pre-fix map-key misrender must not reappear
}

// uint64 body values render as exact unsigned decimals (no double precision loss,
// no signed wrap), independent of the Lua number model — through the tuple path,
// the bare-rendered synchro path, and the header (exact_uint) path.
func testUint64Render(t *testing.T, f form) {
	r := newRun(t, f, "synthetic-uint64.pcap")
	r.decodesCleanly()
	r.contains(`tuple: {18446744073709551615, 9223372036854775808}`) // 2^64-1 and 2^63 in a tuple
	r.contains("replica_id: 1, lsn: 5000000000, term: 2")            // synchro LSN >= 2^32 (regression guard)
	r.notContains("table: 0x")                                       // an ext marker never leaks as a table address
	r.filterYields("tnt.sync==9223372036854775808")                  // header uint64 >= 2^63 read exactly
}

// MP_DATETIME with a negative (pre-1970) epoch decodes via signed le_int seconds.
func testDatetimeNegative(t *testing.T, f form) {
	r := newRun(t, f, "synthetic-datetime.pcap")
	r.decodesCleanly()
	r.contains(`tuple: {1, 1966-10-31T14:13:20Z}`)
}

// A PDU split across two TCP segments reassembles into one decoded PDU, with no
// payload frame left as generic Data.
func testReassembly(t *testing.T, f form) {
	r := newRun(t, f, "synthetic-reassembly.pcap")
	r.decodesCleanly()
	r.requests("eval")
	r.contains("Reassembled TCP Segments") // the PDU spanned two segments and was reassembled
	// The reassembled body decoded; assert only a prefix, since Wireshark
	// truncates a tree-item label near 240 chars (the full expr is longer).
	r.contains("eval return " + strings.Repeat("A", 100))
}

// Decoders/paths wired in but not reached by any real fixture: insert_arrow,
// nop, and the malformed-MsgPack fallback (a well-framed PDU with an invalid
// body must be caught, noted, consumed, and not abort the segment).
func testMiscOpcodes(t *testing.T, f form) {
	r := newRun(t, f, "synthetic-misc.pcap")
	r.decodesCleanly()
	r.requests("insert_arrow", "nop", "CHUNK")
	r.containsAll(
		"arrow: <Arrow IPC payload>",
		"NOP (No Operation)",
		"Tarantool PDU (undecodable)",
		"malformed or truncated MsgPack",
		`{"push-payload"}`,     // CHUNK (box.session.push) response body
		"<error ext, 3 bytes>", // opaque MP_EXT labelled-blob fallback
	)
}
