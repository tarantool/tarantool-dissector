-- A table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug  = true,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 33013, -- default TCP port number
}

local debug = function(...) end
local function resetDebugLevel()
    if default_settings.debug then
        debug = function(...)
            print(table.concat({"Lua: ", ...}," "))
        end
    else
        debug = function(...) end
    end
end
-- call it now
resetDebugLevel()

-- declare the protocol
local tarantool_proto = Proto("tarantool15", "Tarantool 1.5")

local function leb128Unpack(buffer, offset)
-- see http://en.wikipedia.org/wiki/LEB128#Decode_unsigned_integer
    debug('-- leb128Unpack --')
    local result = 0
    local shift = 0
    local used = 1

    while true do

        local byte = buffer(offset, 1):le_uint();
        debug('byte: ' .. byte .. ' ' .. string.format('%04X', byte))
        local bit7 = buffer(offset, 1):bitfield(0, 1)
        offset = offset + 1

        local tmp = (bit7 == 0) and byte or (byte - 128) -- reset 7th bit (byte & 0x80)

        result = result * 128 + tmp  -- result |= (low order 7 bits of byte << shift);

        if ( bit7 == 0) then
            break
        end
        shift = shift + 7
        used = used + 1
    end

    return result, used
end

local function add_one_tuple(buffer, subtree, num)
    debug('-- add_one_tuple --')
    --[[
        <tuple> ::= <cardinality><field>+
        <cardinality> ::= <int32>
        <field> ::= <int32_varint><data>
        <data> ::= <int8>+
        <int32_varint> ::= <int8>+
    ]]
    local data_length = 4 -- for cardinality
    local cardinality = buffer(0,4):le_uint()

    local array = {}

    for i=1,cardinality do
        debug('offset:'.. data_length)
        local field_length, used = leb128Unpack(buffer, data_length)
        debug('f,u:'.. field_length .. ' '..used)
        array[i] = {
                ['start']  = data_length + used,
                ['length'] = field_length,
                ['title']  = "Data (length: " .. field_length .. ')'
            }

        data_length = data_length + field_length + used
    end

    local tree =  subtree:add( tarantool_proto, buffer(0, data_length),"Tuple #" .. num .. " (cardinality: "..cardinality..')')
    for i,v in ipairs(array) do
        tree:add(buffer(v.start, v.length), v.title)
    end

    return data_length
end

local function add_tuples(buffer, subtree, name, count)
    -- local count  = count_buffer(0,4):le_uint()
    local tuples = subtree:add( tarantool_proto, buffer(), "Tuples")

    -- tuples:add( count_buffer(0,4), "Count: " .. count )

    local offset = 0
    for i=1,count do
        offset = offset + add_one_tuple( buffer(offset), tuples, i )
    end
end

local function add_fqtuple(buffer, subtree, name, count)
    local tuples = subtree:add( tarantool_proto, buffer(), "fq_tuples (count: " .. count ..')' )

    local offset = 0
    for i=1,count do
        local size = buffer(0,4):le_uint()
        tuples:add( buffer(offset,4), 'tuple size: ' .. size )
        offset = offset + add_one_tuple( buffer(offset + 4), tuples, i )
        offset = offset + 4
    end
end


local function select_request_body(buffer, subtree)
    --[[ 
        <select_request_body> ::= <namespace_no><index_no>
                              <offset><limit><count><tuple>+
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Select body")

    local namespace_no = buffer(0,4):le_uint()
    local index_no = buffer(4, 4):le_uint()
    local offset   = buffer(8, 4):le_uint()
    local limit    = buffer(12,4):le_uint()
    local count    = buffer(16,4):le_uint()
    if (limit == 4294967295) then
        limit = limit .. ' (no limit)'
    end
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )
    tree:add( buffer(4, 4), "Index # " .. index_no )
    tree:add( buffer(8, 4), "Offset # " .. offset )
    tree:add( buffer(12,4), "Limit # " .. limit )

    tree:add( buffer(16,4), "Tuples count: " .. count )
    add_tuples(buffer(20, buffer:len() - 20), tree, 'tuple', count)
end

local function requestName(reqid)
    local requests = {
            [13] = "INSERT",
            [17] = "SELECT",
            [19] = "UPDATE",
            [20] = "DELETE(obsolete)",
            [21] = "DELETE",
            [22] = "CALL",
            [65280] = "PING",
    }
    return requests[reqid] or 'UNKNOWN'
end



local function decodeErrorCode(buf)
    local completion_status = buf(0,1):le_uint()
    local error_code = buf(1):le_uint()

    local result = "Code " .. completion_status

    if ( completion_status == 0 ) then
        return "0 (Ok)"
    elseif ( completion_status == 1 ) then -- try again
        return "1 (Try again) " .. 'code: ' .. error_code
    elseif ( completion_status == 2 ) then
        return "2 (Error)"
    else
        return completion_status .. " (Unknown error code) " .. ' code: ' .. error_code
    end
end

local function insert_request_body(buffer, subtree)
    --[[
        <insert_request_body> ::= <space_no><flags><tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Insert body")

    local namespace_no = buffer(0,4):le_uint()
    local flags    = buffer(4, 4):le_uint()
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )
    tree:add( buffer(4, 4), "Flags # " .. flags )

    add_one_tuple(buffer(8), tree, 0)
end

local function update_request_body(buffer, subtree)
    subtree:add( buffer,"Update data" )
end

local function deletev13_request_body(buffer, subtree)
    --[[
        <delete_request_body> ::= <namespace_no><tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Delete body (v1.3)")

    local namespace_no = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )

    add_one_tuple(buffer(4), tree, 1)
end

local function delete_request_body(buffer, subtree)
    subtree:add( buffer,"Delete data" )
end

local function call_request_body(buffer, subtree)
    --[[
        <call_request_body> ::= <flags><proc_name><tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer,"Call data" )

    local flags = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Namespace # " .. flags )

    local field_length, used = leb128Unpack(buffer, 4)
    local name = buffer(5, field_length):string()
    tree:add( buffer(5, field_length), "name " .. name )

    add_one_tuple(buffer(4 + 1 + field_length), tree, 0)
end

local function ping_request_body(buffer, subtree)
    subtree:add( buffer,"ping data" )
end

local function unknown_request_body(buffer, subtree)
    subtree:add( buffer,"Unknown command data" )
end

local function unknown_response_body(buffer, subtree)
    subtree:add( buffer,"Unknown response data" )
end

local function insert_response_body(buffer, subtree)
    --[[
        <insert_response_body> ::= <count> | <count><fq_tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Insert response")
    local count = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Affected rows " .. count )

    if ( buffer:len() > 4 ) then
        -- subtree:add( buffer(4),"Insert response data" )
        add_fqtuple( buffer(4), subtree, "Select tuples", count)
    end
end

local function select_response_body(buffer, subtree)
    --[[
        <select_response_body> ::= <count><fq_tuple>*
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Select response")
    local count = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Count: " .. count )

    if ( buffer:len() > 4 ) then
        add_fqtuple( buffer(4), subtree, "Select tuples", count)
    end
end

local function call_reponse_body(buffer, subtree)
    --[[
        <call_response_body> ::= <select_response_body>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Call response")
    local count = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Count: " .. count )

    if ( buffer:len() > 4 ) then
        add_fqtuple( buffer(4), subtree, "Call tuples", count)
    end
end

local function requestfunction(reqid)
    local requests = {
            [13] = insert_request_body,
            [17] = select_request_body,
            [19] = update_request_body,
            [20] = deletev13_request_body, -- old delete
            [21] = delete_request_body,
            [22] = call_request_body,
            [65280] = ping_request_body,
    }
    if (requests[reqid] == nil) then
        return unknown_request_body
    else
        return requests[reqid]
    end
end

local function responsefunction(reqid)
    local requests = {
            [13] = insert_response_body,
            [17] = select_response_body,
            [19] = unknown_response_body,
            [20] = unknown_response_body, -- old delete
            [21] = unknown_response_body,
            [22] = call_reponse_body,
            [65280] = unknown_response_body,
    }
    if (requests[reqid] == nil) then
        return unknown_request_body
    else
        return requests[reqid]
    end
end

local function readHeader(buffer, subtree)
    --[[
        <header> ::= <type><body_length><request_id>
    ]]
    local req_type = buffer(0,4):le_uint()
    local length   = buffer(4,4):le_uint()
    local req_id   = buffer(8,4):le_uint()

    local header =  subtree:add( tarantool_proto, buffer(),"Header")
    header:add( buffer(0,4),"Request Type: " .. req_type .. ' (' .. requestName(req_type) .. ')' )
    header:add( buffer(4,4),"Body length: " .. length )
    header:add( buffer(8,4),"Request ID: " .. req_id .. '[' .. string.format('%08X', req_id) .. ']' )

    return buffer(12, buffer:len() - 12)
end

local function request(buffer, subtree)
    --[[
    <request> ::= <header><request_body>
    ]]
    local req_type = buffer(0,4):le_uint()

    buffer = readHeader(buffer, subtree)

    local requestfunction = requestfunction(req_type)
    requestfunction(buffer, subtree)
end

local function response(buffer, subtree)
    --[[
    <response> ::= <header><return_code>{<response_body>
    ]]
    local req_type = buffer(0,4):le_uint()

    buffer = readHeader(buffer, subtree)
    if ( buffer:len() > 0 ) then

        local code = buffer(0,4):le_uint()
        if (code == 0) then
            subtree:add( buffer(0,4),"Return code: " .. decodeErrorCode(buffer(0,4)) )

            local requestfunction = responsefunction(req_type)

            -- subtree:add( buffer(4),"Data" )
            requestfunction(buffer(4), subtree)
        else
            subtree:add( buffer(0,4),"Return code: " .. decodeErrorCode(buffer(0,4)) )
        end
    end

end

-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TARANTOOL"

    local body_length    = buffer(4,4):le_uint()
    local request_length = body_length + 12 -- 12 - header length

    if (pinfo.src_port == default_settings.port) then
        -- answer, should have a response code
        -- request_length = request_length + 4
    end

    -- debug('buffer: ' .. buffer:len())
    -- debug('length: ' .. body_length)
    if (buffer:len() < request_length) then
        -- debug('reassemble required: ' .. (request_length - buffer:len()) )
        pinfo.desegment_len = request_length - buffer:len()
        pinfo.desegment_offset = 0
        return 0
    end
    if (pinfo.src_port ~= default_settings.port) then
        -- debug('parsing')
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data")

        -- subtree:add( buffer(0,4),"Request Type: " .. buffer(0,4):le_uint() .. ' ' .. requestName(buffer(0,4):le_uint()) )
        request(buffer, subtree)
    else
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data (response)")
        response(buffer, subtree)
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

tarantool_proto.prefs.debug       = Pref.bool("Debug enabled", default_settings.debug,
                                        "The debug printing is enabled or not")

----------------------------------------
-- the function for handling preferences being changed
function tarantool_proto.prefs_changed()
    debug("prefs_changed called")

    default_settings.debug = tarantool_proto.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= tarantool_proto.prefs.enabled then
        default_settings.enabled = tarantool_proto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end
