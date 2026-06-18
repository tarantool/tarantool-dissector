## Tarantool protocol dissector

[Tarantool](https://www.tarantool.io/en/) is an in-memory computing platform.
It uses binary protocol named IProto for communicating. See protocol
description in [documentation][box-protocol].

In Wireshark the user can control how protocols are dissected. Each protocol
has its own dissector and user may add his own dissectors written in Lua. This
dissector implemented for Tarantool binary protocol.

![Wireshark][screenshot]

The dissector auto-detects the wire format per PDU by inspecting the leading
bytes: the modern MsgPack IProto (Tarantool 1.6–3.x, always framed with a 5-byte
`0xce` length prefix) and the legacy ≤1.5 binary protocol (a fixed 12-byte
little-endian `<type><len><req_id>` header). It loops over every PDU in a
segment, so it also decodes a mixed capture where old and new clients share one
port (e.g. legacy `box.dostring` calls alongside MsgPack `call_16`/`ping`).

The dissector ships in two interchangeable forms — both cover **all versions**
(modern + legacy, auto-detected) and decode identically:

- **Single amalgamated file** — one self-contained `tarantool.dissector.lua`
  with MsgPack bundled in and nothing else to copy. Built by CI and attached to
  every [GitHub Release][releases]; the drop-in choice for the Wireshark GUI.
- **Modular `src/` tree** — the real sources as small `require`-able modules,
  run through the `tarantool.lua` loader. Best for development and command-line
  use.

See [INSTALLATION.md](INSTALLATION.md) for step-by-step setup of either form.

For the modern format it understands the current IProto request set, including
SQL (`execute`, `prepare`), interactive transactions over streams (`begin`,
`commit`, `rollback`), protocol negotiation (`id`), event watchers (`watch`,
`unwatch`, `event`, `watch_once`) and the structured (`MP_ERROR`) error format.
Tuple values encoded as MsgPack extensions are decoded too: `decimal`, `uuid`,
`datetime` and `interval` render as real values, while opaque extensions
(`error`, `compression`, `tuple`, `arrow`) show as a labelled blob. Unsigned
64-bit values are rendered unsigned, and it handles TCP reassembly of large
packets and several pipelined packets in a single segment.

The following display filter fields are available:

| Field | Description |
| --- | --- |
| `tnt.type` | request/response code, e.g. `tnt.type == 0x01` for selects |
| `tnt.request` | request name, e.g. `tnt.request == "call"` |
| `tnt.sync` | request id, handy to match a response to its request |
| `tnt.schema_version` | schema version reported in responses |
| `tnt.stream_id` | stream id of an interactive transaction |
| `tnt.response` | `true` for responses, `false` for requests |

### Installation

Full instructions for both forms — including the platform-specific plugin
folders — are in [INSTALLATION.md](INSTALLATION.md). In short:

**Amalgamated single file (recommended for the GUI).** Download
`tarantool.dissector.lua` from the [latest release][releases] into Wireshark's
Personal Lua Plugins folder, renamed to `tarantool.lua` — Wireshark treats a dot
in a plugin filename as a module path, so the extra `.dissector` would stop it
auto-loading:

```sh
# find the folder with: tshark -G folders   (look for "Personal Lua Plugins")
DEST=~/.local/lib/wireshark/plugins
mkdir -p "$DEST"
curl -L -o "$DEST/tarantool.lua" \
  https://github.com/tarantool/tarantool-dissector/releases/latest/download/tarantool.dissector.lua
```

Then restart Wireshark, or reload plugins with *Analyze → Reload Lua Plugins*
(**Ctrl+Shift+L**, **⌘⇧L** on macOS). Keep only one Tarantool dissector in that
folder — a second one registering the same protocol name fails to load.

**Modular sources (development / CLI).** Clone the repo and point Wireshark at
the `tarantool.lua` loader, which runs the `src/` modules directly:

```sh
wireshark -X lua_script:/path/to/tarantool.lua
tshark    -X lua_script:/path/to/tarantool.lua -V -r capture.pcap
```

### Building from source

The single-file build is generated; the real source lives under `src/` as small
modules, combined by `amalgamate.sh` (POSIX shell, no toolchain needed):

| Path | Role |
| --- | --- |
| `src/core.lua` | Proto, ProtoFields, port pref, greeting, main loop, registration |
| `src/msgpack_ext.lua` | MsgPack ext decoding (decimal/uuid/datetime/interval) + unsigned-64 fix |
| `src/modern.lua` | modern MsgPack IProto constants + decoders |
| `src/legacy.lua` | legacy ≤1.5 framing + decoders |
| `src/entry_all.lua` | entry point wiring the combined (modern + legacy) dispatch |
| `MessagePack.lua` | vendored pure-Lua MsgPack (inlined into the build) |
| `tarantool.lua` | loader that runs the `src/` modules directly, without amalgamation |

The build inlines each module via a private registry, so the modules stay
independent (and `require`-able) while the output is one self-contained file.
`dist/` is build output and is **not committed** — the released file is produced
by CI and attached to each release. Edit `src/`, then regenerate with:

```sh
./amalgamate.sh
```

### How to use

By default the dissector decodes TCP packets on port 3301. The port is
configurable in *Edit → Preferences → Protocols → Tarantool*, or apply it to a
single conversation via *Decode As…*, see chapter [Control Protocol
dissection][control-protocol-dissection]. Capturing requires permission to read
from the network interface (root, or membership in a capture group such as
`access_bpf` on macOS / `wireshark` on Linux).

Legacy ≤1.5 servers default to a different binary port (33013). Since the
dissector only auto-attaches to the configured port (3301), point it at the
legacy port too — set the Tarantool port preference to 33013, or use *Decode
As… → tcp.port 33013 → Tarantool*. (This is why the test suite passes
`-d tcp.port==33013,tarantool` for the 1.5 capture.)

### Tests

The dissector is verified against captures from real servers of several
Tarantool versions — **1.5.5** (source build off `1_5_branch`), **1.10.15**,
**2.11.5**, **3.7.0** and **3.8.0** (replication) — and traffic can be
regenerated by hand. See [TESTING.md](TESTING.md) for the exact builds and what
each capture covers.

[box-protocol]: https://www.tarantool.io/en/doc/latest/reference/internals/box_protocol/
[screenshot]: screenshot.png
[control-protocol-dissection]: https://www.wireshark.org/docs/wsug_html_chunked/ChCustProtocolDissectionSection.html
[releases]: https://github.com/tarantool/tarantool-dissector/releases
