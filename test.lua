#!/usr/bin/env tarantool

-- Lua script that uses Tarantool Lua API and produce
-- IProto network packets for testing Wireshark dissector.
--
-- IProto protocol description:
-- https://www.tarantool.io/en/doc/latest/reference/internals/box_protocol/
--
-- How to run: tarantool test.lua

-- Only run under a Tarantool runtime; loading this file from plain Lua tooling
-- (linters, require) is a no-op.
if _TARANTOOL == nil then
    return
end

local netbox = require('net.box')
local popen = require('popen')
local fiber = require('fiber')
local log = require('log')

local addr = '127.0.0.1:3301'
local space_name = 'testspace'
local test_dir = './test.data'
local test_dir_replica = './test.data/replica'

-- Removing test_dir also drops the replica's data in test_dir_replica.
os.execute('rm -rf ' .. test_dir)
os.execute('mkdir ' .. test_dir)

box.cfg{
    listen = addr,
    log_level = 6,
    read_only = false,
    replication = 'replicator:password@localhost:3301',
    work_dir = test_dir,
    replication_synchro_quorum = 1,
    -- Required for interactive (stream) transactions that yield, e.g. when
    -- committing into a synchronous space.
    memtx_use_mvcc_engine = true,
}

local s = box.schema.space.create(space_name, {
    if_not_exists = true,
    is_sync = true,
})

box.ctl.promote()

s:create_index('pk', {
    type = 'hash',
    parts = {1, 'unsigned'},
    if_not_exists = true,
})

box.schema.user.grant('guest', 'read, write, execute', 'universe')
box.schema.user.create('replicator', {
    password = 'password'
})
box.schema.user.grant('replicator', 'replication')

os.execute('mkdir -p ' .. test_dir_replica)
local cmd = {
    arg[-1],
    '-e',
    [[
    box.cfg {
        read_only = true,
        log_level = 6,
        replication = 'replicator:password@localhost:3301',
        listen = 3302,]] ..
        'work_dir = \'' .. test_dir_replica .. '\'' ..
    '}'
}

local replica, err = popen.new(cmd, {
    stdin = 'devnull',
    stdout = 'devnull',
    stderr = 'devnull',
})

if not replica then
    os.exit()
end

-- Wait for replica to connect.
while #box.info.replication < 2 do
    fiber.sleep(0.1)
end

local conn = netbox.connect(addr)
conn:ping()

local space = conn.space[space_name]

space:insert({1, 10})
space:insert({2, 20})
space:insert({3, 30})

space:get(1)

space:select()

space:replace({5, 6, 7, 8})

space:update({1}, {{'=', 2, 5}})

space:upsert({12, 'c'}, {{'=', 3, 'a'}, {'=', 4, 'b'}})

space:delete({1})
space:delete({2})
space:delete({3})

conn:eval('function f5() return 5 + 5 end; return f5();')
conn:eval('return ...', {1, 2, {3, 'x'}})

conn:eval('function f1() return 5 + 5 end;')
conn:call('f1')

conn:eval('function f2(x, y) return x, y end;')
conn:call('f2', {1, 'B'})

-- SQL: exercises IPROTO_EXECUTE (0x0b) and IPROTO_PREPARE (0x0d).
conn:execute([[SELECT 1 AS a, 'two' AS b]])
local stmt = conn:prepare([[SELECT ? + ?]])
conn:execute(stmt.stmt_id, {2, 3})
conn:unprepare(stmt.stmt_id)

-- Event watchers: exercises IPROTO_WATCH (0x4a), UNWATCH (0x4b),
-- EVENT (0x4c) and WATCH_ONCE (0x4d).
box.broadcast('test_event', 42)
local watcher = conn:watch('test_event', function(key, value) end)
fiber.sleep(0.1)
watcher:unregister()
conn:watch_once('test_event')

-- Interactive transaction over a stream: exercises IPROTO_BEGIN (0x0e),
-- IPROTO_COMMIT (0x0f), IPROTO_ROLLBACK (0x10) and the IPROTO_STREAM_ID header.
local stream = conn:new_stream()
local stream_space = stream.space[space_name]

stream:begin()
stream_space:insert({100, 'committed'})
stream:commit()

stream:begin()
stream_space:insert({101, 'rolled-back'})
stream:rollback()

-- Tuples carrying MsgPack extension types (MP_DECIMAL, MP_UUID, MP_DATETIME,
-- MP_INTERVAL) so the dissector's ext decoders are exercised over the wire.
local decimal = require('decimal')
local uuid = require('uuid')
local datetime = require('datetime')
space:replace({200, decimal.new('3.14'), uuid.new(), datetime.now()})
space:replace({201, datetime.now() - datetime.new({year = 1})})

conn:close()

-- Teardown replica.
replica:kill()
replica:wait()

log.info("That's all")

os.exit(0)
