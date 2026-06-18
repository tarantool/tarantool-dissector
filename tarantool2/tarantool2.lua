local msgpack = require('MessagePack')

-- constants
-- packet codes
local OK         = 0x00
local SELECT     = 0x01
local INSERT     = 0x02
local REPLACE    = 0x03
local UPDATE     = 0x04
local DELETE     = 0x05
local CALL_16    = 0x06
local AUTH       = 0x07
local EVAL       = 0x08
local UPSERT     = 0x09
local CALL       = 0x0a
local EXECUTE    = 0x0b
local NOP        = 0x0c
local PREPARE    = 0x0d
local CONFIRM    = 0x28
local ROLLBACK   = 0x29
local PING       = 0x40
local JOIN       = 0x41
local SUBSCRIBE  = 0x42
local VOTE_DEPRECATED = 0x43
local VOTE            = 0x44
local FETCH_SNAPSHOT  = 0x45
local REGISTER        = 0x46

-- packet keys
local TYPE          = 0x00
local SYNC          = 0x01
local REPLICA_ID    = 0x02
local LSN           = 0x03
local SPACE_ID      = 0x10
local INDEX_ID      = 0x11
local LIMIT         = 0x12
local OFFSET        = 0x13
local ITERATOR      = 0x14
local KEY           = 0x20
local TUPLE         = 0x21
local FUNCTION_NAME = 0x22
local USER_NAME     = 0x23
local INSTANCE_UUID = 0x24
local VCLOCK        = 0x26
local EXPRESSION    = 0x27
local DATA          = 0x30

local SQL_TEXT      = 0x40
local SQL_BIND      = 0x41
local STMT_ID       = 0x43
local ERROR         = 0x52

-- A table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    enabled      = true, -- whether this dissector is enabled or not
    port         = 3303, -- default TCP port number
}

-- declare the protocol
local tarantool_proto = Proto("tarantool2","Tarantool 2")

-- extracts bytes from the buffer
local function binary_string(buffer)
    local result = {}
    for i=0,buffer:len() - 1 do
        table.insert(result, string.char(buffer(i, 1):le_uint()))
    end
    return table.concat(result, '')
end


local function map(tbl, callback)
    local result = {}
    for k,v in pairs(tbl) do
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
            table.insert(result, k .. ' = ' .. v)
        end
    end
    return table.concat(result, sep)
end

local function escape_call_arg(a)
    if type(a) == 'number' then
        return a
    elseif type(a) == 'string' then
        return '"' .. a .. '"'
    elseif type(a) == 'table' then
        return '{' .. table_kv_concat(map(a, escape_call_arg), ', ') .. '}'
    else
        return a
    end
end

local function parse_call(tbl, buffer, subtree)
    local name = tbl[FUNCTION_NAME]
    local tuple = tbl[TUPLE]

    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')

    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

-- TODO: why do we need "tuple" in `eval' command?
local function parse_eval(tbl, buffer, subtree)
    local expression = tbl[EXPRESSION]
    local tuple = tbl[TUPLE]

    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')

    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

local function parse_select(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID] -- int
    local index_id = tbl[INDEX_ID] -- int
    local limit    = tbl[LIMIT]    -- int
    local offset   = tbl[OFFSET]   -- int
    local iterator = tbl[ITERATOR] -- int
    local key      = tbl[KEY]      -- array

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    local descr = string.format(
        'SELECT FROM space %d WHERE index(%d) = (%s) LIMIT %d OFFSET %d ITERATOR %s',
        space_id,
        index_id,
        key_string,
        limit,
        offset,
        iterator or ('null')
    )
    subtree:add(buffer, descr)
end

local function parse_insert(tbl, buffer, subtree)
    local tuple    = tbl[TUPLE]
    local space_id = tbl[SPACE_ID]

    subtree:add(buffer, 'space_id: ' .. space_id)
    local tuple_tree = subtree:add(buffer, 'tuple')
    local tuple_str = table.concat(map(tuple, escape_call_arg), ', ')

    tuple_tree:add(buffer, tuple_str)
end

local function parse_delete(tbl, buffer, subtree)
    local key      = tbl[KEY]
    local space_id = tbl[SPACE_ID]
    local index_id = tbl[INDEX_ID]

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    local descr = string.format(
        'DELETE FROM space(%d) WHERE index(%d) = (%s)',
        space_id,
        index_id,
        key_string
    )
    subtree:add(buffer, descr)
end

local function parse_upsert(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID]     -- int
    local index_base = tbl[INDEX_BASE] -- int
    local ops = tbl[OPS]               -- int
    local tuple = tbl[TUPLE]           -- array

    subtree:add(buffer, 'space_id: ' .. space_id)
    local tuple_tree = subtree:add(buffer, 'tuple')
    local tuple_str = table.concat(map(tuple, escape_call_arg), ', ')

    tuple_tree:add(buffer, tuple_str)
end

local function parse_auth(tbl, buffer, subtree)
    local user_name = tbl[USER_NAME]     -- str
    local tuple = tbl[TUPLE]             -- array

    -- chap-sha1 is the only supported mechanism (v. 2.10).
    local proto = tuple[1]
    local scramble = tuple[2]

    local descr = string.format(
       'Authentication with username "%s", protocol %s and scramble "%s"',
       user_name,
       proto,
       scramble
    )
    subtree:add(buffer, descr)
end

local function parse_update(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID]     -- int
    local index_id = tbl[INDEX_ID]     -- int
    local key = tbl[KEY]               -- array
    local tuple = tbl[TUPLE]           -- array

    subtree:add(buffer, 'space_id: ' .. space_id)
    local tuple_tree = subtree:add(buffer, 'tuple')
    local tuple_str = table.concat(map(tuple, escape_call_arg), ', ')

    tuple_tree:add(buffer, tuple_str)
    local key_string = table.concat(map(key, escape_call_arg), ', ')
    subtree:add(buffer, 'key: ' .. key_string)
end

local function parse_execute(tbl, buffer, subtree)
    local stmt_id = tbl[STMT_ID]     -- int
    local sql_text = tbl[SQL_TEXT]   -- str
    local sql_bind = tbl[SQL_BIND]   -- array

    local sql_bind_str = table.concat(map(sql_bind, escape_call_arg), ', ')
    if sql_bind_str ~= '' then
        sql_bind_str = string.format(', with parameter values "%s"', sql_bind_str)
    end

    if stmt_id ~= nil then
        local descr = string.format(
           'executing a prepared statement with id %d%s',
           stmt_id,
           sql_bind_str
        )
        subtree:add(buffer, descr)
    else
        local descr = string.format(
           'executing an SQL string "%s"%s',
           sql_text,
           sql_bind_str
        )
        subtree:add(buffer, descr)
    end
end

local function parse_prepare(tbl, buffer, subtree)
    local stmt_id = tbl[STMT_ID]     -- int
    local sql_text = tbl[SQL_TEXT]   -- str

    if stmt_id ~= nil then
        local descr = string.format(
           'prepare a statement with id %d',
           stmt_id
        )
        subtree:add(buffer, descr)
    else
        local descr = string.format(
           'preparing an SQL string "%s"',
           sql_text
        )
        subtree:add(buffer, descr)
    end
end

local function parse_confirm(tbl, buffer, subtree)
    local replica_id = tbl[REPLICA_ID]     -- int
    local lsn = tbl[LSN]                   -- int

    local descr = string.format(
       [[transactions originated from the instance with id = "%d"
        have achieved quorum and can be committed, up to and including lsn "%d".]],
       replica_id,
       lsn
    )
    subtree:add(buffer, descr)
end

local function parse_rollback(tbl, buffer, subtree)
    local replica_id = tbl[REPLICA_ID]     -- int
    local lsn = tbl[LSN]                   -- int

    local descr = string.format(
       [[transactions originated from the instance with id = "%d"
       couldn't achieve quorum for some reason and should be rolled back,
       down to lsn = "%d" and including it.]],
       replica_id,
       lsn
    )
    subtree:add(buffer, descr)
end

local function parse_subscribe(tbl, buffer, subtree)
    local vclock = tbl[VCLOCK]

    local srv_id = vclock[1]
    local srv_lsn = vclock[2]

    local descr = string.format(
       'Subscribe to server with id "%d" and lsn "%d"',
       srv_id,
       srv_lsn
    )
    subtree:add(buffer, descr)
end

local function parse_join(tbl, buffer, subtree)
    local uuid = tbl[INSTANCE_UUID]

    local descr = string.format(
       'Initial join request with uuid = "%s"',
       uuid
    )
    subtree:add(buffer, descr)
end

local function parse_error_response(tbl, buffer, subtree)
    local data = tbl[ERROR]
    if not data then
        subtree:add(buffer, '(empty response body)')
    else
        subtree:add(buffer, data)
    end
end

local function parse_response(tbl, buffer, subtree)
    local data = tbl[DATA]
     if not data then
         subtree:add(buffer, '(empty response body)')
     else
        local value = map(data, escape_call_arg)
        local arguments_tree = subtree:add(buffer, 'tuple')
        for k, v in pairs(value) do
            arguments_tree:add(buffer, v)
        end
    end
end

local function parse_nop(tbl, buffer, subtree)
    subtree:add(buffer, 'NOP (No Operation')
end

local function parser_not_implemented(tbl, buffer, subtree)
    subtree:add(buffer, 'parser not yet implemented (or unknown packet?)')
end

local function code_to_command(code)

    local codes = {
        [SELECT]  = {name = 'select', decoder = parse_select},
        [INSERT]  = {name = 'insert', decoder = parse_insert},
        [REPLACE] = {name = 'replace', decoder = parse_insert},
        [UPDATE]  = {name = 'update', decoder = parse_update},
        [DELETE]  = {name = 'delete', decoder = parse_delete},
        [CALL]    = {name = 'call', decoder = parse_call},
        [CALL_16] = {name = 'call_16', decoder = parser_not_implemented}, -- Deprecated.
        [AUTH]    = {name = 'auth', decoder = parse_auth},
        [EVAL]    = {name = 'eval', decoder = parse_eval},
        [UPSERT]  = {name = 'upsert', decoder = parse_upsert},
        [EXECUTE] = {name = 'execute', decoder = parse_execute},
        [NOP]     = {name = 'nop', decoder = parse_nop},
        [PREPARE] = {name = 'prepare', decoder = parse_prepare},
        [CONFIRM] = {name = 'confirm', decoder = parse_confirm},
        [ROLLBACK] = {name = 'rollback', decoder = parse_rollback},
        [JOIN]    = {name = 'join', decoder = parse_join},
        [VOTE]    = {name = 'vote', decoder = parser_not_implemented},
        [VOTE_DEPRECATED] = {name = 'vote_deprecated', decoder = parser_not_implemented},
        [SUBSCRIBE] = {name = 'subscribe', decoder = parse_subscribe},
        [FETCH_SNAPSHOT] = {name = 'fetch_snapshot', decoder = parser_not_implemented},
        [REGISTER] = {name = 'register', decoder = parser_not_implemented},

        -- Admin command codes
        [PING] = {name = 'ping', decoder = parser_not_implemented},

        -- Value for <code> key in response can be:
        [OK]   = {name = 'OK', is_response = true, decoder = parse_response},
        --[0x8XXX] = {name = 'ERROR', is_response = true},
    };
    if code >= 0x8000 then
        return {name = 'ERROR', is_response = true, decoder = parse_error_response}
    end

    local unknown_code = {name = 'UNKNOWN', decoder = parser_not_implemented}

    return (codes[code] or unknown_code)
end


-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tarantool"

    if buffer(0, 9):string() == "Tarantool" then
        pinfo.cols.info = 'Greeting packet. ' .. tostring(pinfo.cols.info)

        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool greeting packet")
        subtree:add(buffer(0, 64), "Server version: " .. buffer(0, 64):string())
        subtree:add(buffer(64, 44), "Salt: " .. buffer(64, 44):string())
        subtree:add(buffer(108), "Reserved space")
        return buffer(0, 9):len()
    end

    local iterator = msgpack.unpacker(binary_string(buffer))
    local _, packet_length = iterator()

    -- TODO: check bytes available

    local size_length, header_data = iterator()
    size_length = size_length - 1;

    local packet_buffer = buffer(size_length)

    local request_length = packet_length + size_length

    if (buffer:len() < request_length) then
        pinfo.desegment_len = request_length - buffer:len()
        pinfo.desegment_offset = 0
        return DESEGMENT_ONE_MORE_SEGMENT
    end

    local command = code_to_command(header_data[TYPE])

    local header_length, body_data = iterator()
    header_length = header_length - size_length - 1
    local body_buffer = packet_buffer(size_length + header_length)


    if not command.is_response then
        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool protocol data")
        -- subtree:add(tnt_field_sync, header_data[0x01])
        local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[TYPE], command.name, header_data[SYNC])
        subtree:add(packet_buffer(0, header_length), header_descr)

        local decoder = command.decoder or parser_not_implemented

        decoder(body_data, body_buffer, subtree)

        pinfo.cols.info = command.name:gsub("^%l", string.upper) .. ' request. ' .. tostring(pinfo.cols.info)
    else
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data (response)")
        local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[TYPE], command.name, header_data[SYNC])
        subtree:add(packet_buffer(0, header_length), header_descr)
        command.decoder(body_data, body_buffer, subtree)
        pinfo.cols.info = 'Response. ' .. tostring(pinfo.cols.info)
    end

    return request_length

end

--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(default_settings.port, tarantool_proto)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, tarantool_proto)
end

----------------------------------------
-- register our preferences
tarantool_proto.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the tarantool dissector is enabled or not")

tarantool_proto.prefs.port        = Pref.uint("Port number", default_settings.port,
                                        "The TCP port number for Tarantool")

----------------------------------------
-- the function for handling preferences being changed
function tarantool_proto.prefs_changed()
    local need_reload = false

    if default_settings.enabled ~= tarantool_proto.prefs.enabled then
        default_settings.enabled = tarantool_proto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end

        need_reload = true
    end

    if default_settings.port ~= tarantool_proto.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            disableDissector()
        end
        -- set our new default
        default_settings.port = tarantool_proto.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            enableDissector()
        end

        need_reload = true
    end

    -- have to reload the capture file for this type of change
    if need_reload then
        reload()
    end
end
