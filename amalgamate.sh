#!/bin/sh
#
# Amalgamate the src/ modules into a single self-contained dissector:
#   dist/tarantool.dissector.lua     all versions (modern MsgPack + legacy)
# It inlines every module it needs (including the bundled MessagePack) so the
# output is one file with nothing else to copy. dist/ is build output, not
# committed -- the released file is attached to GitHub Releases by CI, and the
# modular src/ tree is the other supported install form (see INSTALLATION.md).
# Edit src/, then run ./amalgamate.sh.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dist="$here/dist"
mkdir -p "$dist"

# print_header TITLE -- the banner prepended to every generated file.
print_header() {
    cat <<EOF
--
-- Tarantool protocol dissector for Wireshark -- $1.
--
-- GENERATED FILE -- do not edit. Built from src/ by amalgamate.sh; edit the
-- modules under src/ and re-run ./amalgamate.sh to regenerate.
--
-- Install: copy this file into Wireshark's Personal Lua Plugins folder, renamed
-- so the filename has no extra dot before .lua (e.g. tarantool.lua), then reload
-- Lua plugins. Or run ad-hoc: tshark -X lua_script:<thisfile> -r capture.pcap
--
-- Protocol reference:
--   https://www.tarantool.io/en/doc/latest/reference/internals/box_protocol/
--
EOF
}

# emit_prologue -- a private module loader prepended before the module bodies,
# so each amalgamated file keeps its own core/modern/legacy registry instead of
# sharing the process-global package.preload/package.loaded. This stops our
# generic module names from colliding with any other Lua plugin (or another copy
# of this dissector) loaded in the same Wireshark session.
emit_prologue() {
    cat <<'EOF'
local _mods, _loaded = {}, {}
local _require = require                       -- real require, for string/math/jit/...
local function require(name)
    if _loaded[name] ~= nil then return _loaded[name] end
    local m = _mods[name]
    if not m then return _require(name) end    -- not one of ours: defer to stdlib
    local r = m()
    _loaded[name] = (r == nil) or r
    return _loaded[name]
end

EOF
}

# emit_module NAME FILE -- register a module body in the private registry.
emit_module() {
    printf "_mods['%s'] = function(...)\n" "$1"
    cat "$2"
    printf '\nend\n\n'
}

# build OUTFILE TITLE ENTRY MODULESPEC...  -- assemble one dissector; each
# MODULESPEC is "name:path_relative_to_repo_root", ENTRY is appended last.
build() {
    out="$dist/$1"
    title="$2"
    entry="$here/$3"
    shift 3
    {
        print_header "$title"
        emit_prologue
        for spec in "$@"; do
            emit_module "${spec%%:*}" "$here/${spec#*:}"
        done
        cat "$entry"
    } > "$out"
    printf 'wrote %s\n' "$out"
}

build tarantool.dissector.lua \
    "all versions (modern MsgPack IPROTO + legacy <= 1.5)" \
    src/entry_all.lua \
    MessagePack:MessagePack.lua \
    msgpack_ext:src/msgpack_ext.lua \
    core:src/core.lua \
    modern:src/modern.lua \
    legacy:src/legacy.lua
