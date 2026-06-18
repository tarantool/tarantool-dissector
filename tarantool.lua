-- Modular loader for the Tarantool protocol dissector.
--
-- Runs the dissector straight from the src/ modules, with no amalgamation step.
-- Use it for development, or to install the modular form (see INSTALLATION.md):
--
--   tshark    -X lua_script:/path/to/tarantool.lua -r capture.pcap
--   wireshark -X lua_script:/path/to/tarantool.lua
--
-- It locates its own directory and loads the modules from there. src/ and the
-- bundled MessagePack.lua must sit next to this file. The single combined entry
-- point (modern + legacy) is loaded -- the same code the released single-file
-- build amalgamates.
--
-- The modules are loaded into a PRIVATE registry, not the process-global
-- package.loaded / package.path: their generic names (MessagePack, core, modern,
-- legacy, msgpack_ext, entry_all) never leak out and cannot be shadowed by, or
-- clobber, another co-loaded Wireshark Lua plugin (e.g. one bundling its own
-- lua-MessagePack). This mirrors amalgamate.sh's private require shim. Each module
-- is loaded with a per-module environment whose `require` is our private resolver
-- but whose other globals fall through to the real ones (Proto, ProtoField, ...),
-- so nothing global is mutated.

local here = debug.getinfo(1, "S").source:match("^@(.*)[/\\]") or "."
local dirs = { here .. "/src/", here .. "/" }
local ours = {
	MessagePack = true,
	core = true,
	modern = true,
	legacy = true,
	msgpack_ext = true,
	entry_all = true,
}

local real_require = require
local registry = {}
local function scoped_require(name)
	if not ours[name] then
		return real_require(name) -- stdlib etc.: defer to the real loader
	end
	if registry[name] ~= nil then
		return registry[name]
	end
	for _, dir in ipairs(dirs) do
		-- Wireshark's loadfile raises on a missing file rather than returning nil,
		-- so probe under pcall (a module may live in src/ or beside this file). A
		-- present-but-uncompilable file returns (nil, syntaxerr) instead of raising,
		-- so surface that rather than letting the probe fall through to a misleading
		-- "module not found".
		local loaded, chunk, lerr = pcall(loadfile, dir .. name .. ".lua")
		if loaded and not chunk and lerr and not lerr:match("[Nn]o such file") and not lerr:match("cannot open") then
			error(lerr) -- present but failed to compile: surface it, don't fall through
		end
		if loaded and chunk then
			-- Run the module with our require visible (so its own require(...)
			-- calls resolve privately) but the real Wireshark globals (Proto,
			-- ProtoField, ...) available. loadfile gives the chunk its own _ENV, so
			-- swapping the global `require` would not reach it -- inject per module.
			local env = setmetatable({ require = scoped_require }, { __index = _G, __newindex = _G })
			if setfenv then
				setfenv(chunk, env) -- Lua 5.1 / LuaJIT
			elseif debug and debug.setupvalue then
				debug.setupvalue(chunk, 1, env) -- Lua 5.2+: _ENV is the first upvalue
			end
			local result = chunk()
			registry[name] = (result == nil) or result
			return registry[name]
		end
	end
	return real_require(name)
end

local ok, err = pcall(scoped_require, "entry_all")
if not ok then
	error(err)
end
