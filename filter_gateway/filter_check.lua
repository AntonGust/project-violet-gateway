-- filter_check.lua
-- HAProxy Lua hook: checks source IP against Python sidecar filter
-- Communicates via Unix socket at /tmp/filter.sock

local SOCKET_PATH = "/tmp/filter.sock"
local TIMEOUT_MS = 200  -- 200ms timeout for sidecar response

function check_filter(txn)
    local src_ip = txn.f:src()

    -- Default to ACCEPT if sidecar is unreachable
    local decision = "ACCEPT"

    local sock = core.tcp()
    sock:settimeout(TIMEOUT_MS / 1000)

    local ok, err = pcall(function()
        -- Connect to Unix socket
        if sock:connect(SOCKET_PATH) == nil then
            core.Warning("filter_check: cannot connect to sidecar socket")
            return
        end

        -- Send IP and newline
        sock:send(src_ip .. "\n")

        -- Read response
        local response = sock:receive("*l")
        if response then
            response = response:match("^%s*(.-)%s*$")  -- trim whitespace
            if response == "DROP" or response == "ACCEPT" then
                decision = response
            end
        end

        sock:close()
    end)

    if not ok then
        core.Warning("filter_check: error communicating with sidecar: " .. tostring(err))
    end

    txn:set_var("txn.filter_decision", decision)
end

-- Register the Lua action
core.register_action("check_filter", {"tcp-req"}, check_filter)
