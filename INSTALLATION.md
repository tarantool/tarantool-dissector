# Installing the Tarantool dissector

The dissector comes in two interchangeable forms. Both cover **all Tarantool
versions** (modern MsgPack IProto + legacy ≤1.5, auto-detected per packet) and
decode identically — they are the same code, one amalgamated into a single file
and one kept as separate modules.

| Form | Best for | Where to get it |
| --- | --- | --- |
| **Amalgamated single file** | the Wireshark GUI, sharing one file | `tarantool.dissector.lua` from the [latest release][releases] |
| **Modular `src/` tree** | development, command-line use | this repository (`git clone`) |

`dist/` is **not** committed to the repository. The amalgamated file is built by
CI and attached to each GitHub Release; if you want to build it yourself, run
`./amalgamate.sh` (see [Building it yourself](#building-it-yourself)).

## Finding your Personal Lua Plugins folder

Run `tshark -G folders` and look for the `Personal Lua Plugins` line, or in the
GUI open *Help → About Wireshark → Folders*. Typical locations:

| OS | Path |
| --- | --- |
| Linux / macOS | `~/.local/lib/wireshark/plugins` |
| Windows | `%APPDATA%\Wireshark\plugins` |

Wireshark **auto-runs every `.lua` file** it finds in that folder (recursing into
subfolders on recent versions). Keep only one Tarantool dissector there — a
second one registering the same protocol name fails to load with *"there cannot
be two protocols with the same description"*.

## Form 1 — amalgamated single file (recommended for the GUI)

One self-contained file with MsgPack bundled in; nothing else to copy.

1. Download `tarantool.dissector.lua` from the [latest release][releases].

2. Copy it into the Personal Lua Plugins folder, **renamed so the filename has
   no extra dot before `.lua`**. Wireshark treats a dot in a plugin filename as a
   module path, so `tarantool.dissector.lua` would be looked up as the module
   `tarantool/dissector.lua` and never auto-load. Install it as `tarantool.lua`:

   ```sh
   DEST=~/.local/lib/wireshark/plugins
   mkdir -p "$DEST"
   curl -L -o "$DEST/tarantool.lua" \
     https://github.com/tarantool/tarantool-dissector/releases/latest/download/tarantool.dissector.lua
   ```

3. Load it: restart Wireshark, or in a running GUI reload plugins with
   *Analyze → Reload Lua Plugins* (**Ctrl+Shift+L**, **⌘⇧L** on macOS).

You can also skip installation and pass it ad-hoc on the command line:

```sh
wireshark -X lua_script:tarantool.dissector.lua
tshark    -X lua_script:tarantool.dissector.lua -V -r capture.pcap
```

## Form 2 — modular sources

The `src/` modules are run through the `tarantool.lua` loader, which finds its
own directory and loads the combined entry point from there into a private module
registry (so it never collides with another Wireshark Lua plugin). Keep
`tarantool.lua` next to `src/` and the bundled `MessagePack.lua` (as in the
repository).

### Command line / development (recommended)

Point Wireshark or tshark straight at the loader — no copying, no renaming:

```sh
git clone https://github.com/tarantool/tarantool-dissector
cd tarantool-dissector

wireshark -X lua_script:$PWD/tarantool.lua
tshark    -X lua_script:$PWD/tarantool.lua -V -r capture.pcap
```

### Installing the modular form into the GUI

This takes one extra step, because Wireshark auto-runs *every* `.lua` file in the
plugins folder. If you copied the whole `src/` tree in, the modules would be
executed standalone and out of order (e.g. `modern.lua` reads `core`'s fields
before the entry point initialises them) and fail to load. So keep the modules
**outside** the plugins folder and place only a one-line loader inside it:

1. Put the checkout somewhere stable, e.g. `~/src/tarantool-dissector`.

2. Create a loader in the plugins folder that points at it by absolute path:

   ```sh
   SRC=~/src/tarantool-dissector          # holds tarantool.lua + src/
   DEST=~/.local/lib/wireshark/plugins
   mkdir -p "$DEST"
   printf 'dofile("%s")\n' "$SRC/tarantool.lua" > "$DEST/tarantool.lua"
   ```

3. Reload Lua plugins (*Analyze → Reload Lua Plugins*).

If this feels fiddly, use the amalgamated single file for the GUI instead — it is
exactly the same dissector.

## Building it yourself

`amalgamate.sh` is POSIX shell and needs no toolchain. It inlines the `src/`
modules (and the bundled `MessagePack.lua`) into one file under `dist/`:

```sh
./amalgamate.sh
# -> dist/tarantool.dissector.lua
```

Install the result exactly like the released file (Form 1).

## Using it

By default the dissector decodes TCP on port **3301**. Change it in
*Edit → Preferences → Protocols → Tarantool*, or apply it to one conversation via
*Decode As…*. Legacy ≤1.5 servers default to port **33013**; point the port
preference there, or use *Decode As… → tcp.port 33013 → Tarantool*. Capturing
needs permission to read the interface (root, or a capture group such as
`access_bpf` on macOS / `wireshark` on Linux).

[releases]: https://github.com/tarantool/tarantool-dissector/releases
