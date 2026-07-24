-- Modern MsgPack IPROTO decoder (Tarantool 1.6 .. 3.x). A PDU is a 5-byte 0xce
-- uint32 length prefix, then a header map and an optional body map. Exports
-- dissect(tvb, pinfo, tree, offset).

local core = require("core")
local mpx = require("msgpack_ext")

local msgpack = mpx.msgpack
local ext_mt = mpx.ext_mt

local tarantool_proto = core.proto
local need_more = core.need_more
local pf_type = core.pf.type
local pf_request = core.pf.request
local pf_sync = core.pf.sync
local pf_schema = core.pf.schema
local pf_stream = core.pf.stream
local pf_is_resp = core.pf.is_resp

-- iproto_type: request/command codes (src/box/iproto_constants.h).
local OK = 0x00
local SELECT = 0x01
local INSERT = 0x02
local REPLACE = 0x03
local UPDATE = 0x04
local DELETE = 0x05
local CALL_16 = 0x06
local AUTH = 0x07
local EVAL = 0x08
local UPSERT = 0x09
local CALL = 0x0a
local EXECUTE = 0x0b
local NOP = 0x0c
local PREPARE = 0x0d
local BEGIN = 0x0e
local COMMIT = 0x0f
local ROLLBACK = 0x10
local INSERT_ARROW = 0x11
local RAFT = 0x1e
local RAFT_PROMOTE = 0x1f
local RAFT_DEMOTE = 0x20
local RAFT_CONFIRM = 0x28
local RAFT_ROLLBACK = 0x29
local PING = 0x40
local JOIN = 0x41
local SUBSCRIBE = 0x42
local VOTE_DEPRECATED = 0x43
local VOTE = 0x44
local FETCH_SNAPSHOT = 0x45
local REGISTER = 0x46
local JOIN_META = 0x47
local JOIN_SNAPSHOT = 0x48
local ID = 0x49
local WATCH = 0x4a
local UNWATCH = 0x4b
local EVENT = 0x4c
local WATCH_ONCE = 0x4d

local CHUNK = 0x80 -- non-final response chunk (box.session.push)
local TYPE_ERROR = 0x8000 -- bit 15 set => error, low 15 bits = errcode

-- iproto_key: header keys (0x00 .. 0x0b).
local TYPE = 0x00 -- IPROTO_REQUEST_TYPE
local SYNC = 0x01
local REPLICA_ID = 0x02
local LSN = 0x03
local TIMESTAMP = 0x04
local SCHEMA_VERSION = 0x05
local SERVER_VERSION = 0x06
local GROUP_ID = 0x07
local TSN = 0x08
local FLAGS = 0x09
local STREAM_ID = 0x0a
local THREAD_ID = 0x0b

-- iproto_key: DML body keys (0x10 .. 0x2f).
local SPACE_ID = 0x10
local INDEX_ID = 0x11
local LIMIT = 0x12
local OFFSET = 0x13
local ITERATOR = 0x14
local INDEX_BASE = 0x15
local FETCH_POSITION = 0x1f
local KEY = 0x20
local TUPLE = 0x21
local FUNCTION_NAME = 0x22
local USER_NAME = 0x23
local INSTANCE_UUID = 0x24
local REPLICASET_UUID = 0x25
local VCLOCK = 0x26
local EXPRESSION = 0x27
local OPS = 0x28
local BALLOT = 0x29
local OLD_TUPLE = 0x2c
local NEW_TUPLE = 0x2d
local AFTER_POSITION = 0x2e
local AFTER_TUPLE = 0x2f

-- iproto_key: response keys (0x30 .. 0x35).
local DATA = 0x30
local ERROR_24 = 0x31 -- legacy string error
local METADATA = 0x32
local BIND_METADATA = 0x33
local BIND_COUNT = 0x34
local POSITION = 0x35

-- iproto_key: SQL keys (0x40 .. 0x43).
local SQL_TEXT = 0x40
local SQL_BIND = 0x41
local SQL_INFO = 0x42
local STMT_ID = 0x43

-- Nested keys inside response sub-structures.
local FIELD_NAME = 0x00 -- column maps in METADATA
local FIELD_TYPE = 0x01
local SQL_INFO_ROW_COUNT = 0x00 -- inside SQL_INFO map

-- iproto_key: extended keys (0x50 .. 0x64).
local REPLICA_ANON = 0x50
local ID_FILTER = 0x51
local ERROR = 0x52 -- structured error stack (MP_MAP)
local TERM = 0x53
local VERSION = 0x54
local FEATURES = 0x55
local TIMEOUT = 0x56
local EVENT_KEY = 0x57
local EVENT_DATA = 0x58
local TXN_ISOLATION = 0x59
local VCLOCK_SYNC = 0x5a
local AUTH_TYPE = 0x5b
local REPLICASET_NAME = 0x5c
local INSTANCE_NAME = 0x5d
local SPACE_NAME = 0x5e
local INDEX_NAME = 0x5f
local IS_SYNC = 0x61

-- iterator types (box.index iterator codes), for nicer SELECT output.
local ITERATOR_NAME = {
	[0] = "EQ",
	[1] = "REQ",
	[2] = "ALL",
	[3] = "LT",
	[4] = "LE",
	[5] = "GE",
	[6] = "GT",
	[7] = "BITS_ALL_SET",
	[8] = "BITS_ANY_SET",
	[9] = "BITS_ALL_NOT_SET",
	[10] = "OVERLAPS",
	[11] = "NEIGHBOR",
}

-- MsgPack map first-byte markers (MessagePack specification), used to locate
-- header-map value offsets by hand in map_value_offsets.
local MP_FIXMAP_MIN = 0x80 -- 0x80..0x8f: fixmap, low nibble == entry count
local MP_FIXMAP_MAX = 0x8f
local MP_MAP16 = 0xde
local MP_MAP32 = 0xdf
local MP_FIXINT_POSITIVE_MAX = 0x7f -- 0x00..0x7f: positive fixint (value == byte)
local MP_UINT8 = 0xcc
local MP_UINT16 = 0xcd
local MP_UINT32 = 0xce
local MP_UINT64 = 0xcf
local BYTE = 0x100 -- radix for big-endian byte assembly

-- 0-based wire offset of each value in a top-level MsgPack map, keyed by map key,
-- so 64-bit header fields can be read exactly (see exact_uint) instead of via
-- MessagePack.lua's lossy decode.
local function map_value_offsets(raw, base_off)
	local b = raw:byte(1)
	local count, first
	if b >= MP_FIXMAP_MIN and b <= MP_FIXMAP_MAX then
		count, first = b - MP_FIXMAP_MIN, 2
	elseif b == MP_MAP16 then
		count, first = raw:byte(2) * BYTE + raw:byte(3), 4
	elseif b == MP_MAP32 then
		count = ((raw:byte(2) * BYTE + raw:byte(3)) * BYTE + raw:byte(4)) * BYTE + raw:byte(5)
		first = 6
	else
		return {}
	end
	local offsets = {}
	local iter = msgpack.unpacker(raw:sub(first))
	for _ = 1, count do
		local _, key = iter()
		local value_pos = iter() -- start of value element (1-based within sub)
		if value_pos == nil then
			break
		end
		offsets[key] = base_off + first + value_pos - 2
	end
	return offsets
end

-- Read the MsgPack uint at `off` as a full-precision Wireshark UInt64, or nil if
-- `off` is nil or the bytes are not a uint.
local function exact_uint(tvb, off)
	if off == nil then
		return nil
	end
	local b = tvb(off, 1):uint()
	if b <= MP_FIXINT_POSITIVE_MAX then
		return UInt64(b)
	elseif b == MP_UINT8 then
		return UInt64(tvb(off + 1, 1):uint())
	elseif b == MP_UINT16 then
		return UInt64(tvb(off + 1, 2):uint())
	elseif b == MP_UINT32 then
		return UInt64(tvb(off + 1, 4):uint())
	elseif b == MP_UINT64 then
		return tvb(off + 1, 8):uint64()
	end
	return nil
end

local function map(tbl, callback)
	local result = {}
	if tbl == nil then
		return result
	end
	for k, v in pairs(tbl) do
		result[k] = callback(v)
	end
	return result
end

local function table_kv_concat(tbl, sep)
	local result = {}
	local used_keys = {}
	for i, v in ipairs(tbl) do
		used_keys[i] = true
		table.insert(result, v)
	end
	for k, v in pairs(tbl) do
		if not used_keys[k] then
			local key = (type(k) == "table" and getmetatable(k) == ext_mt) and k.text or tostring(k)
			table.insert(result, key .. " = " .. tostring(v))
		end
	end
	return table.concat(result, sep)
end

local function escape_call_arg(a)
	if type(a) == "table" and getmetatable(a) == ext_mt then
		return a.text
	end
	local t = type(a)
	if t == "number" or t == "boolean" then
		return tostring(a)
	elseif t == "string" then
		return '"' .. a .. '"'
	elseif t == "table" then
		return "{" .. table_kv_concat(map(a, escape_call_arg), ", ") .. "}"
	elseif a == nil then
		return "nil"
	end
	return tostring(a)
end

-- Concatenate an array (possibly nil) of msgpack values into a readable string.
local function join_args(arr)
	return table.concat(map(arr, escape_call_arg), ", ")
end

local function add_opt(subtree, buffer, label, value)
	if value ~= nil then
		subtree:add(buffer, label .. ": " .. escape_call_arg(value))
	end
end

-- Render one decoded scalar field printed outside escape_call_arg (which handles
-- nested structures and string quoting). Unwraps an ext/marker table to its text
-- -- uuid/decimal/datetime/interval, the unsigned uint64 marker, box.NULL --
-- otherwise tostring. For plain numbers/strings this is exactly tostring, so it
-- is a safe drop-in; it only fixes the case where a 64-bit-capable field (LSN,
-- OFFSET, ...) arrived MsgPack-uint64-encoded and would otherwise print a table.
local function scalar(v)
	if type(v) == "table" and getmetatable(v) == ext_mt then
		return v.text
	end
	return tostring(v)
end

-- Each decoder receives (body_table, body_tvbrange, subtree); body_table may be
-- empty for body-less requests (PING, VOTE, ...).

local function parse_call(tbl, buffer, subtree)
	local name = tbl[FUNCTION_NAME]
	local args = tbl[TUPLE]
	subtree:add(buffer, string.format("%s(%s)", scalar(name), join_args(args)))
end

local function parse_eval(tbl, buffer, subtree)
	local expression = tbl[EXPRESSION]
	local args = tbl[TUPLE]
	subtree:add(buffer, string.format("eval %s with args (%s)", scalar(expression), join_args(args)))
end

local function parse_select(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	local index = tbl[INDEX_NAME] or tbl[INDEX_ID] or 0
	local limit = tbl[LIMIT]
	local offset = tbl[OFFSET] or 0
	local iterator = tbl[ITERATOR] or 0

	subtree:add(
		buffer,
		string.format(
			"SELECT FROM space %s WHERE index(%s) = (%s) LIMIT %s OFFSET %s ITERATOR %s",
			scalar(space),
			scalar(index),
			join_args(tbl[KEY]),
			scalar(limit),
			scalar(offset),
			ITERATOR_NAME[iterator] or tostring(iterator)
		)
	)
	add_opt(subtree, buffer, "fetch_position", tbl[FETCH_POSITION])
	add_opt(subtree, buffer, "after_position", tbl[AFTER_POSITION])
	if tbl[AFTER_TUPLE] ~= nil then
		subtree:add(buffer, "after_tuple: {" .. join_args(tbl[AFTER_TUPLE]) .. "}")
	end
end

local function parse_insert(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	subtree:add(buffer, "space: " .. scalar(space))
	subtree:add(buffer, "tuple: {" .. join_args(tbl[TUPLE]) .. "}")
	-- Before/after images carried by replicated DML rows.
	add_opt(subtree, buffer, "old_tuple", tbl[OLD_TUPLE])
	add_opt(subtree, buffer, "new_tuple", tbl[NEW_TUPLE])
end

local function parse_delete(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	local index = tbl[INDEX_NAME] or tbl[INDEX_ID] or 0
	subtree:add(
		buffer,
		string.format(
			"DELETE FROM space(%s) WHERE index(%s) = (%s)",
			scalar(space),
			scalar(index),
			join_args(tbl[KEY])
		)
	)
end

local function parse_upsert(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	subtree:add(buffer, "space: " .. scalar(space))
	subtree:add(buffer, "tuple: {" .. join_args(tbl[TUPLE]) .. "}")
	subtree:add(buffer, "ops: {" .. join_args(tbl[OPS]) .. "}")
	add_opt(subtree, buffer, "index_base", tbl[INDEX_BASE])
end

local function parse_update(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	local index = tbl[INDEX_NAME] or tbl[INDEX_ID] or 0
	subtree:add(buffer, "space: " .. scalar(space))
	subtree:add(buffer, "index: " .. scalar(index))
	subtree:add(buffer, "key: {" .. join_args(tbl[KEY]) .. "}")
	subtree:add(buffer, "ops: {" .. join_args(tbl[TUPLE]) .. "}")
	add_opt(subtree, buffer, "index_base", tbl[INDEX_BASE])
	add_opt(subtree, buffer, "old_tuple", tbl[OLD_TUPLE])
	add_opt(subtree, buffer, "new_tuple", tbl[NEW_TUPLE])
end

local function parse_auth(tbl, buffer, subtree)
	local user = tbl[USER_NAME]
	local tuple = tbl[TUPLE] or {}
	subtree:add(buffer, string.format('Authentication: user "%s", mechanism %s', scalar(user), scalar(tuple[1])))
end

local function parse_id(tbl, buffer, subtree)
	subtree:add(buffer, "protocol version: " .. scalar(tbl[VERSION]))
	subtree:add(buffer, "features: {" .. join_args(tbl[FEATURES]) .. "}")
	if tbl[AUTH_TYPE] ~= nil then
		subtree:add(buffer, "auth_type: " .. scalar(tbl[AUTH_TYPE]))
	end
end

local function parse_execute(tbl, buffer, subtree)
	local stmt_id = tbl[STMT_ID]
	local sql_text = tbl[SQL_TEXT]
	local bind = join_args(tbl[SQL_BIND])
	if bind ~= "" then
		bind = string.format(", with parameters (%s)", bind)
	end
	if stmt_id ~= nil then
		subtree:add(buffer, string.format("execute prepared statement id %s%s", scalar(stmt_id), bind))
	else
		subtree:add(buffer, string.format('execute SQL "%s"%s', scalar(sql_text), bind))
	end
end

local function parse_prepare(tbl, buffer, subtree)
	local stmt_id = tbl[STMT_ID]
	local sql_text = tbl[SQL_TEXT]
	if stmt_id ~= nil then
		subtree:add(buffer, "unprepare/prepare statement id " .. scalar(stmt_id))
	else
		subtree:add(buffer, string.format('prepare SQL "%s"', scalar(sql_text)))
	end
end

local function parse_begin(tbl, buffer, subtree)
	add_opt(subtree, buffer, "timeout", tbl[TIMEOUT])
	add_opt(subtree, buffer, "txn_isolation", tbl[TXN_ISOLATION])
	add_opt(subtree, buffer, "is_sync", tbl[IS_SYNC])
end

local function parse_commit(tbl, buffer, subtree)
	add_opt(subtree, buffer, "is_sync", tbl[IS_SYNC])
end

local function parse_insert_arrow(tbl, buffer, subtree)
	local space = tbl[SPACE_NAME] or tbl[SPACE_ID]
	subtree:add(buffer, "space: " .. scalar(space))
	subtree:add(buffer, "arrow: <Arrow IPC payload>")
end

local function parse_watch(tbl, buffer, subtree)
	subtree:add(buffer, "event key: " .. scalar(tbl[EVENT_KEY]))
	if tbl[EVENT_DATA] ~= nil then
		subtree:add(buffer, "event data: " .. escape_call_arg(tbl[EVENT_DATA]))
	end
end

local function parse_synchro(tbl, buffer, subtree)
	subtree:add(
		buffer,
		string.format(
			"replica_id: %s, lsn: %s, term: %s",
			scalar(tbl[REPLICA_ID]),
			scalar(tbl[LSN]),
			scalar(tbl[TERM])
		)
	)
end

-- Render a vclock ({replica_id = lsn}) as "{0 = 2, 1 = 9}", iterating sorted keys
-- (a plain table_kv_concat would print id 1 positionally as "{9, 0 = 2}").
local function vclock_str(vclock)
	if type(vclock) ~= "table" then
		return tostring(vclock)
	end
	local keys = {}
	for k in pairs(vclock) do
		keys[#keys + 1] = k
	end
	table.sort(keys)
	local parts = {}
	for _, k in ipairs(keys) do
		parts[#parts + 1] = tostring(k) .. " = " .. escape_call_arg(vclock[k])
	end
	return "{" .. table.concat(parts, ", ") .. "}"
end

local function parse_subscribe(tbl, buffer, subtree)
	subtree:add(buffer, "instance_uuid: " .. scalar(tbl[INSTANCE_UUID]))
	subtree:add(buffer, "replicaset_uuid: " .. scalar(tbl[REPLICASET_UUID]))
	if tbl[VCLOCK] ~= nil then
		subtree:add(buffer, "vclock: " .. vclock_str(tbl[VCLOCK]))
	end
	add_opt(subtree, buffer, "instance_name", tbl[INSTANCE_NAME])
	add_opt(subtree, buffer, "replicaset_name", tbl[REPLICASET_NAME])
	add_opt(subtree, buffer, "server_version", tbl[SERVER_VERSION])
	add_opt(subtree, buffer, "replica_anon", tbl[REPLICA_ANON])
	if tbl[ID_FILTER] ~= nil then
		subtree:add(buffer, "id_filter: {" .. join_args(tbl[ID_FILTER]) .. "}")
	end
end

-- Shared by JOIN, FETCH_SNAPSHOT and REGISTER.
local function parse_join(tbl, buffer, subtree)
	subtree:add(buffer, "instance_uuid: " .. scalar(tbl[INSTANCE_UUID]))
	add_opt(subtree, buffer, "instance_name", tbl[INSTANCE_NAME])
	add_opt(subtree, buffer, "server_version", tbl[SERVER_VERSION])
	if tbl[VCLOCK] ~= nil then
		subtree:add(buffer, "vclock: " .. vclock_str(tbl[VCLOCK]))
	end
end

-- IPROTO_ERROR (0x52) is a map { MP_ERROR_STACK: [ frame, ... ] }; each frame is
-- a map keyed by these field ids (src/box/mp_error.cc).
local MP_ERROR_STACK = 0x00
local MP_ERROR_TYPE = 0x00
local MP_ERROR_FILE = 0x01
local MP_ERROR_LINE = 0x02
local MP_ERROR_MESSAGE = 0x03
local MP_ERROR_ERRNO = 0x04
local MP_ERROR_CODE = 0x05
local MP_ERROR_FIELDS = 0x06

-- Render the structured error stack as named fields instead of a raw map dump.
local function add_error_stack(subtree, buffer, err)
	local stack = (type(err) == "table") and err[MP_ERROR_STACK] or nil
	if type(stack) ~= "table" then
		subtree:add(buffer, "error: " .. escape_call_arg(err))
		return
	end
	local node = subtree:add(buffer, "error stack")
	for i, frame in ipairs(stack) do
		if type(frame) == "table" then
			local head = string.format("[%d] %s", i, tostring(frame[MP_ERROR_TYPE] or "?"))
			if frame[MP_ERROR_CODE] ~= nil then
				head = head .. string.format(" (code %s)", tostring(frame[MP_ERROR_CODE]))
			end
			if frame[MP_ERROR_MESSAGE] ~= nil then
				head = head .. ": " .. tostring(frame[MP_ERROR_MESSAGE])
			end
			local fnode = node:add(buffer, head)
			add_opt(fnode, buffer, "errno", frame[MP_ERROR_ERRNO])
			if frame[MP_ERROR_FILE] ~= nil then
				fnode:add(
					buffer,
					string.format("at %s:%s", tostring(frame[MP_ERROR_FILE]), tostring(frame[MP_ERROR_LINE]))
				)
			end
			if frame[MP_ERROR_FIELDS] ~= nil then
				fnode:add(buffer, "fields: " .. escape_call_arg(frame[MP_ERROR_FIELDS]))
			end
		end
	end
end

local function parse_error_response(tbl, buffer, subtree)
	if tbl == nil then
		subtree:add(buffer, "(empty response body)")
		return
	end
	if tbl[ERROR_24] ~= nil then
		subtree:add(buffer, "message: " .. scalar(tbl[ERROR_24]))
	end
	if tbl[ERROR] ~= nil then
		add_error_stack(subtree, buffer, tbl[ERROR])
	end
	if tbl[ERROR_24] == nil and tbl[ERROR] == nil then
		subtree:add(buffer, "(empty response body)")
	end
end

-- Responses carry no request type, so surface whichever known response keys are
-- present (data, SQL metadata, PREPARE info, cursor, ballot, ID/SUBSCRIBE).
local function parse_response(tbl, buffer, subtree)
	if tbl == nil or next(tbl) == nil then
		subtree:add(buffer, "(empty response body)")
		return
	end

	if tbl[METADATA] ~= nil then
		local node = subtree:add(buffer, "metadata")
		for _, col in ipairs(tbl[METADATA]) do
			node:add(buffer, tostring(col[FIELD_NAME]) .. " : " .. tostring(col[FIELD_TYPE]))
		end
	end
	if tbl[DATA] ~= nil then
		local node = subtree:add(buffer, "data")
		if type(tbl[DATA]) == "table" and getmetatable(tbl[DATA]) ~= ext_mt then
			for _, v in ipairs(map(tbl[DATA], escape_call_arg)) do
				node:add(buffer, v)
			end
		else
			node:add(buffer, escape_call_arg(tbl[DATA]))
		end
	end
	if tbl[SQL_INFO] ~= nil then
		add_opt(subtree, buffer, "sql row_count", tbl[SQL_INFO][SQL_INFO_ROW_COUNT])
	end
	add_opt(subtree, buffer, "position", tbl[POSITION])
	add_opt(subtree, buffer, "stmt_id", tbl[STMT_ID])
	add_opt(subtree, buffer, "bind_count", tbl[BIND_COUNT])
	add_opt(subtree, buffer, "bind_metadata", tbl[BIND_METADATA])
	add_opt(subtree, buffer, "version", tbl[VERSION])
	if tbl[FEATURES] ~= nil then
		subtree:add(buffer, "features: {" .. join_args(tbl[FEATURES]) .. "}")
	end
	add_opt(subtree, buffer, "auth_type", tbl[AUTH_TYPE])
	add_opt(subtree, buffer, "ballot", tbl[BALLOT])
	add_opt(subtree, buffer, "replicaset_uuid", tbl[REPLICASET_UUID])
	if tbl[VCLOCK] ~= nil then
		subtree:add(buffer, "vclock: " .. vclock_str(tbl[VCLOCK]))
	end
end

local function parse_nop(tbl, buffer, subtree)
	subtree:add(buffer, "NOP (No Operation)")
end

local function parse_empty(tbl, buffer, subtree)
	-- Body-less request (PING, VOTE, ROLLBACK, UNWATCH, ...) — nothing to show.
end

local function parser_not_implemented(tbl, buffer, subtree)
	subtree:add(buffer, "parser not yet implemented")
end

local UNKNOWN_COMMAND = { name = "UNKNOWN", decoder = parser_not_implemented }

local COMMANDS = {
	[SELECT] = { name = "select", decoder = parse_select },
	[INSERT] = { name = "insert", decoder = parse_insert },
	[REPLACE] = { name = "replace", decoder = parse_insert },
	[UPDATE] = { name = "update", decoder = parse_update },
	[DELETE] = { name = "delete", decoder = parse_delete },
	[CALL] = { name = "call", decoder = parse_call },
	[CALL_16] = { name = "call_16", decoder = parse_call },
	[AUTH] = { name = "auth", decoder = parse_auth },
	[EVAL] = { name = "eval", decoder = parse_eval },
	[UPSERT] = { name = "upsert", decoder = parse_upsert },
	[EXECUTE] = { name = "execute", decoder = parse_execute },
	[NOP] = { name = "nop", decoder = parse_nop },
	[PREPARE] = { name = "prepare", decoder = parse_prepare },
	[BEGIN] = { name = "begin", decoder = parse_begin },
	[COMMIT] = { name = "commit", decoder = parse_commit },
	[ROLLBACK] = { name = "rollback", decoder = parse_empty },
	[INSERT_ARROW] = { name = "insert_arrow", decoder = parse_insert_arrow },
	[ID] = { name = "id", decoder = parse_id },
	[WATCH] = { name = "watch", decoder = parse_watch },
	[UNWATCH] = { name = "unwatch", decoder = parse_watch },
	[EVENT] = { name = "event", decoder = parse_watch },
	[WATCH_ONCE] = { name = "watch_once", decoder = parse_watch },
	[JOIN] = { name = "join", decoder = parse_join },
	[JOIN_META] = { name = "join_meta", decoder = parse_empty },
	[JOIN_SNAPSHOT] = { name = "join_snapshot", decoder = parse_empty },
	[SUBSCRIBE] = { name = "subscribe", decoder = parse_subscribe },
	[VOTE] = { name = "vote", decoder = parse_empty },
	[VOTE_DEPRECATED] = { name = "vote_deprecated", decoder = parse_empty },
	[FETCH_SNAPSHOT] = { name = "fetch_snapshot", decoder = parse_join },
	[REGISTER] = { name = "register", decoder = parse_join },
	[RAFT] = { name = "raft", decoder = parser_not_implemented },
	[RAFT_PROMOTE] = { name = "raft_promote", decoder = parse_synchro },
	[RAFT_DEMOTE] = { name = "raft_demote", decoder = parse_synchro },
	[RAFT_CONFIRM] = { name = "raft_confirm", decoder = parse_synchro },
	[RAFT_ROLLBACK] = { name = "raft_rollback", decoder = parse_synchro },
	[PING] = { name = "ping", decoder = parse_empty },
	[OK] = { name = "OK", is_response = true, decoder = parse_response },
	[CHUNK] = { name = "CHUNK", is_response = true, decoder = parse_response },
}

local function code_to_command(code)
	-- A corrupt header can decode TYPE to a non-number (string/array/map, or a
	-- uint64 >= 2^63 that msgpack_ext wraps into an ext marker). This runs before
	-- the rendering pcall, so guard the comparison rather than let it throw.
	if type(code) ~= "number" then
		return UNKNOWN_COMMAND
	end
	if code >= TYPE_ERROR then
		return {
			name = string.format("ERROR(0x%x)", code - TYPE_ERROR),
			is_response = true,
			decoder = parse_error_response,
		}
	end
	return COMMANDS[code] or UNKNOWN_COMMAND
end

-- Dissect one modern PDU at `offset`; returns bytes consumed, nil (reassembly)
-- or false (not a modern PDU).
local function dissect_modern(tvb, pinfo, tree, offset)
	local available = tvb:len() - offset

	-- Tarantool always frames the length as a 5-byte 0xce uint32.
	if tvb(offset, 1):uint() ~= 0xce then
		return false
	end
	local prefix_len = 5
	if available < prefix_len then
		return need_more(pinfo, offset, DESEGMENT_ONE_MORE_SEGMENT)
	end

	local _, packet_length = msgpack.unpacker(tvb:raw(offset, prefix_len))()
	-- Reject an absurd length instead of asking TCP to reassemble ~4 GB.
	if type(packet_length) ~= "number" or packet_length < 0 or packet_length > 0x10000000 then
		return false
	end
	local total = prefix_len + packet_length
	if available < total then
		return need_more(pinfo, offset, total - available)
	end

	-- Decode header + optional body; catch malformed inner MsgPack so one bad
	-- PDU never aborts the whole segment (mirrors the legacy path's pcall).
	local ok, header_data, body_start, body_data = pcall(function()
		local iter = msgpack.unpacker(tvb:raw(offset, total))
		iter() -- skip the length prefix already decoded above
		local _, hdr = iter()
		local bstart, bdata = iter()
		return hdr, bstart, bdata
	end)

	if not ok or type(header_data) ~= "table" then
		local subtree = tree:add(tarantool_proto, tvb(offset, total), "Tarantool PDU (undecodable)")
		subtree:add(tvb(offset, total), "malformed or truncated MsgPack")
		return total -- consume it and carry on with the next PDU
	end

	local command = code_to_command(header_data[TYPE] or 0)
	local subtree = tree:add(
		tarantool_proto,
		tvb(offset, total),
		command.is_response and "Tarantool response" or "Tarantool request"
	)

	-- Guard the table indexing below so a non-conforming PDU renders a note
	-- instead of throwing and aborting the rest of the segment.
	local rendered = pcall(function()
		local header_end = body_start and (body_start - 1) or total
		local header_len = header_end - prefix_len
		local body_off = offset + header_end
		local body_len = total - header_end
		local header_range = tvb(offset + prefix_len, header_len)
		local voff = map_value_offsets(tvb:raw(offset + prefix_len, header_len), offset + prefix_len)

		-- Add a header int, reading the exact wire value (see map_value_offsets);
		-- nil `field` renders a "label: value" text node.
		local function add_hdr_uint(field, label, key)
			if header_data[key] == nil then
				return
			end
			local value = exact_uint(tvb, voff[key]) or UInt64(header_data[key])
			if field ~= nil then
				subtree:add(field, header_range, value)
			else
				subtree:add(header_range, label .. ": " .. tostring(value))
			end
		end

		subtree:add(pf_type, header_range, header_data[TYPE] or 0)
		subtree:add(pf_request, header_range, command.name)
		subtree:add(pf_is_resp, header_range, command.is_response and true or false)
		add_hdr_uint(pf_sync, nil, SYNC)
		add_hdr_uint(pf_schema, nil, SCHEMA_VERSION)
		add_hdr_uint(pf_stream, nil, STREAM_ID)
		-- Replication / transaction header fields (WAL rows, multi-stmt txns).
		add_hdr_uint(nil, "replica_id", REPLICA_ID)
		add_hdr_uint(nil, "lsn", LSN)
		add_hdr_uint(nil, "tsn", TSN)
		add_hdr_uint(nil, "flags", FLAGS)
		add_opt(subtree, header_range, "timestamp", header_data[TIMESTAMP])
		add_hdr_uint(nil, "group_id", GROUP_ID)
		add_hdr_uint(nil, "thread_id", THREAD_ID)
		add_hdr_uint(nil, "vclock_sync", VCLOCK_SYNC)

		local body_range = (body_len > 0) and tvb(body_off, body_len) or tvb(offset, total)
		local decoder = command.decoder or parser_not_implemented
		decoder(body_data or {}, body_range, subtree)
	end)
	if not rendered then
		subtree:add(tvb(offset, total), "malformed or non-conforming body")
	end

	pinfo.cols.info:append(command.name .. " ")
	return total
end

return { dissect = dissect_modern }
