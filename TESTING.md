## Testing

`tests/pcap/` holds captures from real servers of several Tarantool versions,
each exercising the functionality that version supports:

| Fixture | Captured from | Covers |
| --- | --- | --- |
| `tarantool-1.5.pcap` | Tarantool **1.5.5** (legacy binary, port 33013) | insert, select, update, delete, call |
| `tarantool-1.10.pcap` | Tarantool **1.10.15** (MsgPack) | auth, ping, CRUD, call, eval |
| `tarantool-2.11.pcap` | Tarantool **2.11.5** (`2.11.5-0-g12a9ceb870`, MsgPack) | the above + SQL, streams (begin/commit/rollback), `id`, watchers, error stack |
| `tarantool-3.x.pcap` | Tarantool **3.7.0** (`3.7.0-0-g78b01ace947`, MsgPack) | the above + `watch_once` and MsgPack ext types (decimal, uuid, datetime, interval) |
| `tarantool-combined.pcap` | 1.5.5 + 3.7.0 merged | both framings in one capture — exercises the per-PDU legacy/modern dispatch |
| `tarantool-replication-async.pcap` | 3-node master-master, Tarantool **3.8.0** (`3.8.0-entrypoint-49-g97a3b38040`), ports 3311–3313 | bootstrap (`join`/`subscribe`) + asynchronous master-master writes: non-conflicting, conflicting and over a stream (`begin`/`commit`/`rollback`) |
| `tarantool-replication-sync.pcap` | same cluster (3.8.0), node 1 promoted | synchronous replication: `raft_promote` + quorum-acknowledged commits (`raft_confirm`) into a synchronous space |
| `synthetic-*.pcap` | hand-crafted (`tests/gen_synthetic_pcaps.py`) | edge cases real captures don't reach: `box.NULL` in a non-final tuple position; exact uint64 rendering (2⁶⁴-1, 2⁶³) in a tuple, a bare-rendered synchro `LSN`, and a header `sync`; a negative pre-1970 `datetime`; TCP reassembly of a PDU split across segments; and the `insert_arrow`/`nop`/`CHUNK`/opaque-ext/malformed-body paths |

The exact servers used to generate these captures: **1.10.15**, **2.11.5** and
**3.7.0** are what the official `tarantool/tarantool:1.10`, `:2.11` and `:3`
Docker images resolved to at the time of testing; **1.5.5** was built from
source off the `1_5_branch` branch (no MsgPack
greeting, so the version isn't embedded in the capture); the **3.8.0**
replication captures come from a local build
(`3.8.0-entrypoint-49-g97a3b38040`). Version strings other than 1.5 are the
greeting banners stored in the pcaps themselves.

The suite is a Go test harness under `tests/` (using `testify` for assertions)
that drives `tshark` against each fixture and asserts, per version: a clean
decode (zero Lua errors, no malformed frames, no payload-bearing frame left as
generic `Data`); the expected request types; decoded request bodies (e.g.
`box.dostring`, `myfunc(2, 3)`, the SQL text, the rendered `SELECT`/`DELETE` and
auth line); response decoding (legacy return codes, SQL `row_count`/`metadata`,
the structured error stack `[1] ClientError (code 3)` vs. the 1.10 string error);
and the 3.x MsgPack ext values (decimal, uuid, datetime, interval).

Beyond string matches it pins **exact structural counts** extracted via
`tshark -T fields`/`-Y`: the total request and response PDU counts and a
per-request-type histogram for each capture, so a regression that drops or
misclassifies PDUs surfaces as a count mismatch (these are properties of the
frozen fixtures — re-capturing one means updating its numbers). It also checks
that every declared display filter (`tnt.type`, `tnt.request`, `tnt.sync`,
`tnt.schema_version`, `tnt.stream_id`, `tnt.response`) is registered and usable,
that both request and response PDUs are classified, and — where the capture is a
clean request/response exchange — that every response's sync matches a request.

Each scenario runs against **both install forms** — the amalgamated build and
the modular `src/` loader — discovered automatically (`DISS` pins a single
dissector path; `TSHARK` overrides the binary). Every `tshark` subprocess runs
with an isolated `HOME`/`XDG` so it never picks up a personally installed copy of
the dissector (which would collide with the one under test). Run as a non-root
user — Wireshark disables `-X lua_script` under root, and the suite skips itself
in that case (and when no `tshark` is found).

CI (`.github/workflows/tests.yml`) runs on every change across **Wireshark 3.x
and 4.x** — both on `ubuntu-24.04`, the 3.x leg pulling Wireshark 3.6 from
jammy's packages. Because `dist/` is not committed, the workflow first runs
`./amalgamate.sh` to build it, then `go test ./tests/`, which exercises both the
amalgamated build and the modular loader. The single amalgamated file is built
and attached to the GitHub Release by a separate tag-triggered workflow
(`.github/workflows/release.yml`); see [INSTALLATION.md](INSTALLATION.md).

```sh
go test ./tests/ -v
# macOS (Wireshark.app is auto-detected, or point TSHARK at any tshark):
TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark go test ./tests/ -v
```

### Generating traffic by hand

`test.lua` drives a local Tarantool 3.x instance through most IProto commands —
CRUD, `call`/`eval`, SQL (`execute`/`prepare`), event watchers, interactive
transactions over streams and replication (`join`/`subscribe`). Capture loopback
on port 3301 (e.g. in Wireshark on `lo`/`lo0`) and run `tarantool test.lua`.
