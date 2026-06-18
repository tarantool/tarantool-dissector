-- Shared dissector core: the Proto, header fields, port/enabled preferences,
-- greeting, the main-loop factory and registration. The modern/legacy decoders
-- and the entry point build on this.
--
-- The Proto is created by M.init(slug, desc), which the entry point calls (with
-- name "tarantool") BEFORE requiring the decoder modules -- they capture
-- M.proto/M.pf at load time. The parameter is kept generic so alternate entry
-- points could register the core under a different name.

local M = {}

-- Set by M.init; the closures below capture these names as upvalues, so they
-- see the values init assigns.
local proto
local pf

-- Request reassembly: returns nil so the caller stops and TCP redelivers more.
local function need_more(pinfo, offset, more)
	if pinfo.can_desegment > 0 then
		pinfo.desegment_offset = offset
		pinfo.desegment_len = more
	end
	return nil
end
M.need_more = need_more

local GREETING_SIZE = 128
local GREETING_SALT_OFFSET = 64
local GREETING_SALT_SIZE = 44

local function dissect_greeting(tvb, pinfo, tree, offset)
	local available = tvb:len() - offset
	if available < GREETING_SIZE then
		return need_more(pinfo, offset, GREETING_SIZE - available)
	end
	pinfo.cols.info:append("Greeting ")
	local subtree = tree:add(proto, tvb(offset, GREETING_SIZE), "Tarantool greeting")
	subtree:add(tvb(offset, GREETING_SALT_OFFSET), "Server version: " .. tvb(offset, GREETING_SALT_OFFSET):string())
	subtree:add(
		tvb(offset + GREETING_SALT_OFFSET, GREETING_SALT_SIZE),
		"Salt: " .. tvb(offset + GREETING_SALT_OFFSET, GREETING_SALT_SIZE):string()
	)
	subtree:add(
		tvb(
			offset + GREETING_SALT_OFFSET + GREETING_SALT_SIZE,
			GREETING_SIZE - GREETING_SALT_OFFSET - GREETING_SALT_SIZE
		),
		"Reserved"
	)
	return GREETING_SIZE
end
M.dissect_greeting = dissect_greeting

-- `dispatch_pdu` decodes one non-greeting PDU (returns bytes consumed, nil for
-- reassembly, or false for "not ours"); which one is wired in distinguishes the
-- modern-only, legacy-only and combined builds.
function M.make_dissector(dispatch_pdu)
	return function(tvb, pinfo, tree)
		pinfo.cols.protocol = "Tarantool"
		pinfo.cols.info:clear()
		local n = tvb:len()
		local offset = 0
		while offset < n do
			local consumed
			if n - offset >= 9 and tvb(offset, 9):string() == "Tarantool" then
				consumed = dissect_greeting(tvb, pinfo, tree, offset)
			else
				consumed = dispatch_pdu(tvb, pinfo, tree, offset)
			end
			if consumed == nil then
				return -- reassembly requested
			elseif not consumed then
				break
			end -- not decodable as our protocol
			offset = offset + consumed
		end
		return offset
	end
end

local tcp_port_table = DissectorTable.get("tcp.port")
local registered_ports
local server_ports = {}

-- Parse a Wireshark port range ("3301,3311-3313") into a lookup set, so the
-- legacy decoder can tell a server-side port from a client port for direction.
local function parse_ports(spec)
	local set = {}
	for part in tostring(spec):gmatch("[^,]+") do
		local a, b = part:match("^%s*(%d+)%s*%-%s*(%d+)%s*$")
		if a then
			for p = tonumber(a), tonumber(b) do
				set[p] = true
			end
		else
			local n = part:match("^%s*(%d+)%s*$")
			if n then
				set[tonumber(n)] = true
			end
		end
	end
	return set
end

-- True if `port` is one of the configured Tarantool server ports.
function M.is_server_port(port)
	return server_ports[port] == true
end

-- Sync the tcp.port registration with the current `enabled`/`ports` preferences.
-- `ports` is a range (e.g. "3301,3311-3313"); drop the previously registered
-- range and add the current one -- Wireshark expands the range and binds each
-- port. Idempotent: safe to call on every prefs change.
function M.register()
	if registered_ports ~= nil then
		tcp_port_table:remove(registered_ports, proto)
		registered_ports = nil
	end
	server_ports = {}
	if not proto.prefs.enabled then
		return
	end
	tcp_port_table:add(proto.prefs.ports, proto)
	registered_ports = proto.prefs.ports
	server_ports = parse_ports(proto.prefs.ports)
end

-- Create the protocol under `slug` (display name `desc`), register its header
-- fields and preferences, and wire prefs_changed. `default_port` seeds the
-- "TCP ports" range preference (3301 for modern; legacy <=1.5 used 33013) -- a
-- distinct default keeps co-loaded builds off the same port, since Wireshark's
-- tcp.port table binds one dissector per port. The user can widen it to a range
-- (e.g. "3301,3311-3313") to decode a whole cluster. Call once, before
-- requiring the decoder modules.
function M.init(slug, desc, default_port)
	proto = Proto(slug, desc)
	M.proto = proto

	-- Header fields, also usable as display filters (e.g. `tnt.type == 0x01`).
	pf = {
		type = ProtoField.uint16("tnt.type", "Request type", base.HEX),
		request = ProtoField.string("tnt.request", "Request name"),
		sync = ProtoField.uint64("tnt.sync", "Sync", base.DEC),
		schema = ProtoField.uint64("tnt.schema_version", "Schema version", base.DEC),
		stream = ProtoField.uint64("tnt.stream_id", "Stream id", base.DEC),
		is_resp = ProtoField.bool("tnt.response", "Is response"),
	}
	M.pf = pf
	proto.fields = { pf.type, pf.request, pf.sync, pf.schema, pf.stream, pf.is_resp }

	proto.prefs.enabled = Pref.bool("Dissector enabled", true, "Whether the Tarantool dissector is enabled")
	proto.prefs.ports = Pref.range(
		"TCP ports",
		tostring(default_port or 3301),
		"Ports to decode as Tarantool, e.g. 3301,3311-3313",
		65535
	)

	function proto.prefs_changed()
		M.register()
	end

	return M
end

return M
