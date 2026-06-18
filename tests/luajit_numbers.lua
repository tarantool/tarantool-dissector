-- Verify the number-model-sensitive decoders in src/msgpack_ext.lua are exact on
-- a FLOAT-number Lua (LuaJIT / Lua 5.1-5.2), the case the reference tshark (Lua
-- 5.4) cannot exercise. msgpack_ext is pure Lua (no Wireshark API), so it loads
-- under bare luajit. Run: luajit tests/luajit_numbers.lua <repo-root>
-- Driven by TestNumberModelUnderLuaJIT (skips when luajit is absent).

local root = arg[1] or "."
package.path = root .. "/src/?.lua;" .. root .. "/?.lua;" .. package.path
bit = require("bit") -- msgpack_ext captures the global `bit` Wireshark provides

local mp = require("msgpack_ext").msgpack

local fail = 0
local function eq(name, got, want)
	if got ~= want then
		fail = fail + 1
		io.stderr:write(string.format("FAIL %s: got %q want %q\n", name, tostring(got), tostring(want)))
	else
		print("ok " .. name)
	end
end

local function bytes(...)
	local t = { ... }
	for i = 1, #t do
		t[i] = string.char(t[i])
	end
	return table.concat(t)
end

-- MP_DATETIME (fixext8), negative pre-1970 epoch: -100000000 s little-endian.
eq("datetime -1e8", mp.build_ext(4, bytes(0x00, 0x1F, 0x0A, 0xFA, 0xFF, 0xFF, 0xFF, 0xFF)).text, "1966-10-31T14:13:20Z")

-- uint64 body values: exact unsigned decimals, no double rounding, no signed wrap.
eq("uint64 max", mp.unpack(bytes(0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)).text, "18446744073709551615")
eq("uint64 2^63", mp.unpack(bytes(0xCF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)).text, "9223372036854775808")

os.exit(fail == 0 and 0 or 1)
