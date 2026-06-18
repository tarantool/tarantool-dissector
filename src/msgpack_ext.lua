-- Tarantool MsgPack ext (MP_EXT) decoding layered onto the bundled
-- MessagePack.lua, which by default drops ext values and renders uint64 >= 2^63
-- as negative. Exports the configured msgpack module and the `ext_mt` marker.
-- Used only by the modern decoder (legacy <= 1.5 is not MsgPack-based).

local msgpack = require("MessagePack")

-- Wireshark bundles the Lua BitOp library as a global `bit` on every build with
-- Lua support (LuaJIT and plain Lua 5.x alike -- see the Wireshark developer
-- guide, "Bitwise Operations"). Captured locally for byte-nibble extraction,
-- where BitOp's 32-bit domain is sufficient. The integer readers below stay
-- arithmetic: they handle 64-bit MsgPack values, which exceed that domain.
local bit = bit

local M = {}

-- MsgPack first-byte type markers, used to length-decode integers by hand (see
-- read_mp_int). Names and encoding follow the MessagePack specification
-- (https://github.com/msgpack/msgpack/blob/master/spec.md), as implemented by
-- the bundled MessagePack.lua.
local MP_FIXINT_POSITIVE_MAX = 0x7f -- 0x00..0x7f: positive fixint (value == byte)
local MP_FIXINT_NEGATIVE_MIN = 0xe0 -- 0xe0..0xff: negative fixint (value == byte - 0x100)
local MP_UINT8 = 0xcc
local MP_UINT16 = 0xcd
local MP_UINT32 = 0xce
local MP_UINT64 = 0xcf
local MP_INT8 = 0xd0
local MP_INT16 = 0xd1
local MP_INT32 = 0xd2
local MP_INT64 = 0xd3
local BYTE = 0x100 -- one byte's worth of values, for fixint wrap

-- MP_EXT type ids (src/lib/core/mp_extension_types.h).
local MP_UNKNOWN = 0
local MP_DECIMAL = 1
local MP_UUID = 2
local MP_ERROR = 3
local MP_DATETIME = 4
local MP_COMPRESSION = 5
local MP_INTERVAL = 6
local MP_TUPLE = 7
local MP_ARROW = 8

local MP_EXT_NAME = {
	[MP_UNKNOWN] = "unknown",
	[MP_DECIMAL] = "decimal",
	[MP_UUID] = "uuid",
	[MP_ERROR] = "error",
	[MP_DATETIME] = "datetime",
	[MP_COMPRESSION] = "compression",
	[MP_INTERVAL] = "interval",
	[MP_TUPLE] = "tuple",
	[MP_ARROW] = "arrow",
}

-- Marks a pre-formatted ext value; escape_call_arg renders its .text verbatim.
local ext_mt = {}

local function le_uint(s, from, len)
	local v = 0
	for i = len, 1, -1 do
		v = v * BYTE + s:byte(from + i - 1)
	end
	return v
end

local function be_uint(s, from, len)
	local v = 0
	for i = 0, len - 1 do
		v = v * BYTE + s:byte(from + i)
	end
	return v
end

-- Reinterpret an unsigned `len`-byte value as two's-complement signed. Kept as
-- arithmetic (rather than LuaJIT bit ops) because len can be 8: 64-bit values
-- exceed the 32-bit signed domain of the bit library.
local function to_signed(v, len)
	local sign_bit = 2 ^ (len * 8 - 1)
	if v >= sign_bit then
		v = v - sign_bit * 2
	end
	return v
end

local function le_int(s, from, len)
	return to_signed(le_uint(s, from, len), len)
end

-- Exact two's-complement signed 64-bit read (big-endian bytes at `from`) as a Lua
-- number. Correct on every runtime for |v| < 2^53 (all real datetimes/intervals):
-- for negatives it builds the magnitude directly from (~bytes)+1 rather than the
-- ~2^64 intermediate of to_signed(le_uint(...,8),8), which rounds in a double on
-- float-number Lua (LuaJIT / Lua 5.1-5.2) and corrupts pre-1970 timestamps.
local function be_int64(s, from)
	if s:byte(from) < 0x80 then
		return be_uint(s, from, 8) -- non-negative: exact for < 2^53
	end
	local bytes = { s:byte(from, from + 7) } -- big-endian, index 1 = MSB
	local carry = 1
	for i = 8, 1, -1 do
		local x = (255 - bytes[i]) + carry
		if x >= 256 then
			x, carry = x - 256, 1
		else
			carry = 0
		end
		bytes[i] = x
	end
	local mag = 0
	for i = 1, 8 do
		mag = mag * 0x100 + bytes[i]
	end
	return -mag
end

local function le_int64(s, from)
	return be_int64(s:sub(from, from + 7):reverse(), 1)
end

-- Read one MsgPack integer at `from`; returns the value and the next index.
local function read_mp_int(s, from)
	local b = s:byte(from)
	if b <= MP_FIXINT_POSITIVE_MAX then
		return b, from + 1
	elseif b >= MP_FIXINT_NEGATIVE_MIN then
		return b - BYTE, from + 1
	elseif b == MP_UINT8 then
		return s:byte(from + 1), from + 2
	elseif b == MP_UINT16 then
		return be_uint(s, from + 1, 2), from + 3
	elseif b == MP_UINT32 then
		return be_uint(s, from + 1, 4), from + 5
	elseif b == MP_UINT64 then
		return be_uint(s, from + 1, 8), from + 9
	elseif b == MP_INT8 then
		return to_signed(s:byte(from + 1), 1), from + 2
	elseif b == MP_INT16 then
		return to_signed(be_uint(s, from + 1, 2), 2), from + 3
	elseif b == MP_INT32 then
		return to_signed(be_uint(s, from + 1, 4), 4), from + 5
	elseif b == MP_INT64 then
		return be_int64(s, from + 1), from + 9
	end
	return 0, from + 1
end

-- MP_UUID (fixext16): 16 bytes -> canonical UUID string.
local function decode_uuid(data)
	local h = {}
	for i = 1, 16 do
		h[i] = string.format("%02x", data:byte(i))
	end
	return table.concat(h, "", 1, 4)
		.. "-"
		.. table.concat(h, "", 5, 6)
		.. "-"
		.. table.concat(h, "", 7, 8)
		.. "-"
		.. table.concat(h, "", 9, 10)
		.. "-"
		.. table.concat(h, "", 11, 16)
end

-- MP_DATETIME (fixext8/16): int64 LE seconds [+ nsec, tzoffset, tzindex].
local function decode_datetime(data)
	-- struct field offsets: int64 seconds, then uint32 nsec and int16 tzoffset
	-- (src/lib/core/datetime.h struct datetime).
	local secs = le_int64(data, 1)
	local nsec, tzoffset = 0, 0
	if #data >= 16 then
		nsec = le_uint(data, 9, 4)
		tzoffset = le_int(data, 13, 2) -- minutes east of UTC, signed
	end
	-- Shift the UTC instant by the stored offset so the printed wall clock
	-- matches the appended timezone.
	local out = "epoch=" .. string.format("%d", secs)
	if os and os.date then
		local ok, formatted = pcall(os.date, "!%Y-%m-%dT%H:%M:%S", secs + tzoffset * 60)
		if ok and formatted then
			out = formatted
		end
	end
	if nsec > 0 then
		local frac = string.format("%09d", nsec):gsub("0+$", "")
		out = out .. "." .. frac
	end
	if tzoffset ~= 0 then
		local m = math.abs(tzoffset)
		out = out .. string.format("%s%02d:%02d", tzoffset < 0 and "-" or "+", math.floor(m / 60), m % 60)
	else
		out = out .. "Z"
	end
	return out
end

-- Packed-BCD nibbles: each byte holds two decimal digits (high then low), and
-- the final low nibble is a sign code (src/lib/core/decimal.c, via the decNumber
-- library -- see decPackedToNumber / DECPMINUS).
local LOW_NIBBLE = 0x0f
local BCD_SIGN_MINUS_B = 0x0b
local BCD_SIGN_MINUS_D = 0x0d

-- MP_DECIMAL: MsgPack scale (-exponent) followed by packed-BCD coefficient.
local function decode_decimal(data)
	local scale, pos = read_mp_int(data, 1)
	local digits, sign, last = {}, "", #data
	for i = pos, last do
		local byte = data:byte(i)
		digits[#digits + 1] = bit.rshift(byte, 4)
		if i < last then
			digits[#digits + 1] = bit.band(byte, LOW_NIBBLE)
		else
			local nibble = bit.band(byte, LOW_NIBBLE) -- last low nibble is the sign
			sign = (nibble == BCD_SIGN_MINUS_B or nibble == BCD_SIGN_MINUS_D) and "-" or ""
		end
	end
	local s = table.concat(digits):gsub("^0+(%d)", "%1")
	if scale > 0 then
		if #s <= scale then
			s = string.rep("0", scale - #s + 1) .. s
		end
		s = s:sub(1, #s - scale) .. "." .. s:sub(#s - scale + 1)
	elseif scale < 0 then
		s = s .. string.rep("0", -scale)
	end
	return sign .. s
end

-- MP_INTERVAL field ids (src/lib/core/datetime.h enum interval_fields).
local INTERVAL_FIELD = {
	[0] = "year",
	[1] = "month",
	[2] = "week",
	[3] = "day",
	[4] = "hour",
	[5] = "min",
	[6] = "sec",
	[7] = "nsec",
	[8] = "adjust",
}

-- MP_INTERVAL: u8 count, then count (u8 field_id, MsgPack value) pairs.
local function decode_interval(data)
	local count, pos = data:byte(1), 2
	local parts = {}
	for _ = 1, count do
		local fid = data:byte(pos)
		local val
		val, pos = read_mp_int(data, pos + 1)
		parts[#parts + 1] = (INTERVAL_FIELD[fid] or ("f" .. fid)) .. "=" .. val
	end
	return "{" .. table.concat(parts, ", ") .. "}"
end

local EXT_DECODER = {
	[MP_DECIMAL] = decode_decimal,
	[MP_UUID] = decode_uuid,
	[MP_DATETIME] = decode_datetime,
	[MP_INTERVAL] = decode_interval,
}

-- Decode known scalar ext types; render opaque ones as a labelled blob.
function msgpack.build_ext(tag, data)
	local decoder = EXT_DECODER[tag]
	if decoder then
		local ok, result = pcall(decoder, data)
		if ok and result ~= nil then
			return setmetatable({ text = result }, ext_mt)
		end
	end
	return setmetatable(
		{
			text = string.format(
				"<%s ext, %d byte%s>",
				MP_EXT_NAME[tag] or ("type " .. tag),
				#data,
				#data == 1 and "" or "s"
			),
		},
		ext_mt
	)
end

-- msgpack nil (0xc0, box.NULL) would otherwise decode to a Lua nil, which is a
-- hole in an array table: table.concat / ipairs / # stop at it, so a tuple or
-- result row with a NULL in a non-final position gets truncated or misrendered.
-- Decode it to a shared marker (rendered "nil" by escape_call_arg) so arrays
-- stay dense.
local null_marker = setmetatable({ text = "nil" }, ext_mt)
msgpack.unpackers["nil"] = function()
	return null_marker
end

-- Format 8 big-endian bytes as an exact unsigned decimal string, independent of
-- the Lua number model: MessagePack.lua reconstructs uint64 through doubles,
-- which lose precision >= 2^53 on LuaJIT / Lua 5.1-5.2 (float-number Wireshark
-- builds), so we never route a body uint64 through that lossy value.
local function bytes_to_udec(s)
	local digits = { 0 }
	for k = 1, #s do
		local carry = s:byte(k)
		for d = 1, #digits do
			local v = digits[d] * 0x100 + carry
			digits[d] = v % 10
			carry = math.floor(v / 10)
		end
		while carry > 0 do
			digits[#digits + 1] = carry % 10
			carry = math.floor(carry / 10)
		end
	end
	local out = {}
	for d = #digits, 1, -1 do
		out[#out + 1] = tostring(digits[d])
	end
	return table.concat(out)
end

-- Render uint64 body values exactly and unsigned on every runtime, reading the
-- raw 8 bytes rather than the vendored (lossy) double reconstruction. Header
-- fields use exact_uint on the tvb accessors instead.
msgpack.unpackers["uint64"] = function(c)
	local s, i, j = c.s, c.i, c.j
	if i + 7 > j then
		c:underflow(i + 7)
		s, i, j = c.s, c.i, c.j
	end
	local raw = s:sub(i, i + 7)
	c.i = i + 8
	return setmetatable({ text = bytes_to_udec(raw) }, ext_mt)
end

M.msgpack = msgpack
M.ext_mt = ext_mt
return M
