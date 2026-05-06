-- filter_check.lua
-- HAProxy Lua hook: checks source IP against blocklist and bans files.
-- Uses file I/O (no socket/yield) so it runs safely in tcp-request content context.

local BLOCKLIST_PATH = "/data/blocklist.txt"
local BANS_PATH      = "/data/bans.txt"
local REFRESH_SEC    = 10  -- reload files at most every 10 seconds

local blocked = {}
local last_load = 0

local function load_file(path, tbl)
    local f = io.open(path, "r")
    if not f then return end
    for line in f:lines() do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and not line:match("^#") then
            tbl[line] = true
        end
    end
    f:close()
end

local function maybe_reload()
    local now = os.time()
    if now - last_load < REFRESH_SEC then return end
    last_load = now
    blocked = {}
    load_file(BLOCKLIST_PATH, blocked)
    load_file(BANS_PATH, blocked)
end

function check_filter(txn)
    maybe_reload()
    local src_ip = txn.f:src()
    local decision = blocked[src_ip] and "DROP" or "ACCEPT"
    txn:set_var("txn.filter_decision", decision)
end

core.register_action("check_filter", {"tcp-req"}, check_filter)
