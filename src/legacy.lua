-- Legacy pre-MsgPack decoder (Tarantool <= 1.5). Per doc/box-protocol.txt:
--   header ::= <type><body_length><request_id>   -- three int32, little-endian
--   tuple  ::= <cardinality><field>+              -- cardinality int32 LE
--   field  ::= <int32_varint><data>               -- length is a VLQ (MSB-first)
-- Exports dissect(tvb, pinfo, tree, offset). Pure binary parsing, no MsgPack.

local core = require("core")

local tarantool_proto = core.proto
local need_more = core.need_more
local pf_type = core.pf.type
local pf_request = core.pf.request
local pf_sync = core.pf.sync
local pf_is_resp = core.pf.is_resp

-- Read a VLQ field length at `off`. Returns the value and bytes consumed.
local function legacy_varint(b, off)
	local value, used = 0, 0
	while true do
		local byte = b(off + used, 1):uint()
		used = used + 1
		value = value * 128 + (byte % 128)
		if byte < 128 then
			break
		end
	end
	return value, used
end

-- Legacy fields are typeless on the wire, so guess from the bytes: printable
-- text that fills the whole field -> quoted string; otherwise a 4-/8-byte field
-- -> its little-endian unsigned integer (NUM/NUM64); else a byte count. The
-- "fills the whole field" check (#s == len) keeps this independent of how a
-- Wireshark version truncates :string() at embedded NUL bytes.
local function legacy_field_text(range)
	local len = range:len()
	local ok, s = pcall(function()
		return range:string()
	end)
	if ok and #s == len and s:match("^[\32-\126]*$") then
		return '"' .. s .. '"'
	elseif len == 4 then
		return tostring(range:le_uint())
	elseif len == 8 then
		return tostring(range:le_uint64())
	end
	return string.format("<%d bytes>", len)
end

-- tuple ::= <cardinality:u32><field>+. Returns bytes the tuple occupies.
local function legacy_add_tuple(b, subtree, num)
	local card = b(0, 4):le_uint()
	local off, parts = 4, {}
	local node = subtree:add(b(0, 4), string.format("tuple #%d (cardinality %d)", num, card))
	for i = 1, card do
		local flen, used = legacy_varint(b, off)
		local text = legacy_field_text(b(off + used, flen))
		node:add(b(off, used + flen), string.format("[%d] %s", i, text))
		parts[#parts + 1] = text
		off = off + used + flen
	end
	node:append_text("  {" .. table.concat(parts, ", ") .. "}")
	return off
end

local function legacy_call_req(b, subtree)
	subtree:add(b(0, 4), string.format("flags: 0x%08x", b(0, 4):le_uint()))
	local nlen, used = legacy_varint(b, 4)
	local name = b(4 + used, nlen):string()
	subtree:add(b(4, used + nlen), "function: " .. name)
	local args_off = 4 + used + nlen
	if b:len() > args_off then
		legacy_add_tuple(b(args_off), subtree, 0)
	end
	subtree:append_text(string.format("  call %s(...)", name))
end

local function legacy_select_req(b, subtree)
	local lim = b(12, 4):le_uint()
	subtree:add(b(0, 4), "space: " .. b(0, 4):le_uint())
	subtree:add(b(4, 4), "index: " .. b(4, 4):le_uint())
	subtree:add(b(8, 4), "offset: " .. b(8, 4):le_uint())
	subtree:add(b(12, 4), "limit: " .. (lim == 4294967295 and "unlimited" or lim))
	local count = b(16, 4):le_uint()
	subtree:add(b(16, 4), "keys: " .. count)
	local o = 20
	for i = 1, count do
		o = o + legacy_add_tuple(b(o), subtree, i)
	end
end

local function legacy_insert_req(b, subtree)
	subtree:add(b(0, 4), "space: " .. b(0, 4):le_uint())
	subtree:add(b(4, 4), string.format("flags: 0x%08x", b(4, 4):le_uint()))
	legacy_add_tuple(b(8), subtree, 0)
end

local function legacy_delete_req(b, subtree)
	subtree:add(b(0, 4), "space: " .. b(0, 4):le_uint())
	subtree:add(b(4, 4), string.format("flags: 0x%08x", b(4, 4):le_uint()))
	legacy_add_tuple(b(8), subtree, 0)
end

-- Pre-1.5 obsolete DELETE (type 20): <space_no><tuple>, no flags.
local function legacy_delete_v13_req(b, subtree)
	subtree:add(b(0, 4), "space: " .. b(0, 4):le_uint())
	legacy_add_tuple(b(4), subtree, 0)
end

-- UPDATE: <space_no><flags><tuple (key)><count><operation>+. Op encoding is
-- version-specific, so show the key, op count and the rest as a blob.
local function legacy_update_req(b, subtree)
	subtree:add(b(0, 4), "space: " .. b(0, 4):le_uint())
	subtree:add(b(4, 4), string.format("flags: 0x%08x", b(4, 4):le_uint()))
	local off = 8 + legacy_add_tuple(b(8), subtree, 0)
	if b:len() >= off + 4 then
		subtree:add(b(off, 4), "operations: " .. b(off, 4):le_uint())
		if b:len() > off + 4 then
			subtree:add(b(off + 4), string.format("ops payload: %d bytes", b:len() - off - 4))
		end
	end
end

-- fq_tuples: count-prefixed list, each tuple preceded by its u32 byte size.
local function legacy_add_fqtuples(b, subtree, count)
	local o = 0
	for i = 1, count do
		subtree:add(b(o, 4), string.format("tuple #%d size: %d", i, b(o, 4):le_uint()))
		o = o + 4 + legacy_add_tuple(b(o + 4), subtree, i)
	end
end

-- response ::= <header><return_code>{<body>}. return_code: low byte = status
-- (0 ok, 1 try again, 2 error), upper 3 bytes = error code. Body only on success.
local LEGACY_STATUS = { [0] = "ok", [1] = "try again", [2] = "error" }
local function legacy_response(rtype, b, subtree)
	local code = b(0, 4):le_uint()
	local status, errcode = code % 256, math.floor(code / 256)
	subtree:add(
		b(0, 4),
		string.format(
			"return code: 0x%08x (%s%s)",
			code,
			LEGACY_STATUS[status] or ("status " .. status),
			status ~= 0 and string.format(", error 0x%x", errcode) or ""
		)
	)
	if status ~= 0 then
		if b:len() > 4 then
			subtree:add(b(4), "error: " .. b(4):string())
		end
		return
	end
	if b:len() > 4 then
		local count = b(4, 4):le_uint()
		subtree:add(b(4, 4), "count: " .. count)
		if b:len() > 8 then
			legacy_add_fqtuples(b(8), subtree, count)
		end
	end
end

-- 1.5 request types (doc/box-protocol.txt), plus the pre-1.5 obsolete DELETE (20).
local LEGACY_NAME = {
	[13] = "insert",
	[17] = "select",
	[19] = "update",
	[20] = "delete_v13",
	[21] = "delete",
	[22] = "call",
	[65280] = "ping",
}
local LEGACY_REQ = {
	[13] = legacy_insert_req,
	[17] = legacy_select_req,
	[19] = legacy_update_req,
	[20] = legacy_delete_v13_req,
	[21] = legacy_delete_req,
	[22] = legacy_call_req,
	-- 65280 (ping) has an empty body.
}

local function dissect_legacy(tvb, pinfo, tree, offset)
	local available = tvb:len() - offset
	if available < 4 then
		return need_more(pinfo, offset, DESEGMENT_ONE_MORE_SEGMENT)
	end
	local rtype = tvb(offset, 4):le_uint()
	local name = LEGACY_NAME[rtype]
	if name == nil then
		return false -- not a legacy header we recognise; leave it for Data
	end
	if available < 12 then
		return need_more(pinfo, offset, 12 - available)
	end
	local body_len = tvb(offset + 4, 4):le_uint()
	local req_id = tvb(offset + 8, 4):le_uint()
	local total = 12 + body_len
	if available < total then
		return need_more(pinfo, offset, total - available)
	end

	-- Request and response share the header (same type), so direction is the
	-- only signal: match a configured server port if possible, else assume the
	-- server is the lower (well-known) port. Keeps responses decoding even on a
	-- non-default port via Decode As (e.g. legacy 33013).
	local is_response
	if core.is_server_port(pinfo.src_port) then
		is_response = true
	elseif core.is_server_port(pinfo.dst_port) then
		is_response = false
	else
		is_response = pinfo.src_port < pinfo.dst_port
	end
	local subtree = tree:add(
		tarantool_proto,
		tvb(offset, total),
		is_response and "Tarantool response (legacy <= 1.5)" or "Tarantool request (legacy <= 1.5)"
	)
	subtree:add(pf_type, tvb(offset, 4), rtype)
	subtree:add(pf_request, tvb(offset, 4), name)
	subtree:add(pf_is_resp, tvb(offset, 4), is_response)
	subtree:add(pf_sync, tvb(offset + 8, 4), UInt64(req_id))
	subtree:add(
		tvb(offset, 12),
		string.format("legacy header: type %d (%s), body_len %d, req_id 0x%08x", rtype, name, body_len, req_id)
	)

	if body_len > 0 then
		local body = tvb(offset + 12, body_len)
		local ok = pcall(function()
			if is_response then
				legacy_response(rtype, body, subtree)
			else
				local fn = LEGACY_REQ[rtype]
				if fn then
					fn(body, subtree)
				else
					subtree:add(body, string.format("body: %d bytes", body_len))
				end
			end
		end)
		if not ok then
			subtree:add(body, "malformed legacy body")
		end
	end

	pinfo.cols.info:append((is_response and "resp " or "") .. name .. " ")
	return total
end

return { dissect = dissect_legacy }
