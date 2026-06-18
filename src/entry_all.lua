-- Entry point: all versions. Modern PDUs start with the 0xce length prefix;
-- anything else is tried as legacy framing (the two are unambiguous).

-- core.init must run before requiring the decoders: they capture core.proto at
-- load time.
local core = require("core")
core.init("tarantool", "Tarantool")

local modern = require("modern")
local legacy = require("legacy")

local function dispatch(tvb, pinfo, tree, offset)
	if tvb(offset, 1):uint() == 0xce then
		return modern.dissect(tvb, pinfo, tree, offset)
	end
	return legacy.dissect(tvb, pinfo, tree, offset)
end

core.proto.dissector = core.make_dissector(dispatch)
core.register()
