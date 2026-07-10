-- ============================================================================
-- ratelimit.lua — 滑动窗口频率限制（对应 Python: src/freq/__init__.py）
--
-- 使用 ngx.shared.freq_counter 共享字典实现分布式计数器
-- key 格式: "freq:<ip>:<timestamp>" → count（按秒粒度计数）
--
-- 与 Python 版逻辑对照：
--   Python: FreqArray(window_size) — 每 IP 一个定长数组，time() % len 索引
--   Lua:    per-second keys in shared dict — 多 worker 共享，无单进程限制
-- ============================================================================

local ratelimit = {}

-- ---------------------------------------------------------------------------
-- check(ip, restrict) → boolean
-- restrict = { window_size = 60, max_requests = 50 }
-- 返回 true = 放行, false = 频率超限
-- ---------------------------------------------------------------------------
function ratelimit.check(ip, restrict)
    if not restrict then return true end

    local dict = ngx.shared.freq_counter
    local now = ngx.time()
    local window = restrict.window_size
    local max_req = restrict.max_requests

    if window < 1 then return true end

    -- 惰性清理：删除刚好滑出窗口的旧 key
    dict:delete("freq:" .. ip .. ":" .. (now - window - 1))

    -- 累计当前窗口 [now - window + 1, now] 内的请求数
    local total = 0
    local cur = dict:get("freq:" .. ip .. ":" .. now) or 0
    total = total + cur

    if total < max_req then
        -- 向后遍历窗口余下的秒（最多 60 次迭代，对个人代理可接受）
        for t = now - 1, now - window + 1, -1 do
            local c = dict:get("freq:" .. ip .. ":" .. t)
            if c then
                total = total + c
                if total >= max_req then
                    break  -- 提前退出
                end
            end
        end
    end

    -- 递增当前秒（在检查之后，超限的请求不纳入计数）
    dict:incr("freq:" .. ip .. ":" .. now, 1, 0)

    if total >= max_req then
        return false
    end
    return true
end

-- ---------------------------------------------------------------------------
-- reset(ip)  — 解封时重置该 IP 的频率计数器（清空所有时间槽）
-- ---------------------------------------------------------------------------
function ratelimit.reset(ip)
    local dict = ngx.shared.freq_counter
    local all_keys = dict:get_keys(0)
    local prefix = "freq:" .. ip .. ":"
    for _, key in ipairs(all_keys) do
        if key:sub(1, #prefix) == prefix then
            dict:delete(key)
        end
    end
end

return ratelimit
