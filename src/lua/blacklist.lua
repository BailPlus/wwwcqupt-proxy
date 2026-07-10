-- ============================================================================
-- blacklist.lua — 黑名单管理（对应 Python: src/blacklist/__init__.py）
--
-- 存储策略：
--   - 运行时：ngx.shared.blacklist 共享字典（O(1) 查询）
--   - 持久化：SQLite（lsqlite3）
--
-- 关键函数：
--   is_banned(ip, domain)      → boolean
--   ban(ip, domain)            → 写入 shared dict + SQLite
--   unban(ip)                  → 从 shared dict + SQLite 移除所有 domain 记录
--   load_all_to_shared()       → 启动时从 SQLite 载入 shared dict
-- ============================================================================

local blacklist = {}

-- ---------------------------------------------------------------------------
-- SQLite 连接（惰性初始化，每 worker 进程各持一个连接）
-- ---------------------------------------------------------------------------
local sqlite3 = require("lsqlite3")
local _db     = nil
local _init   = false

local function get_db()
    if not _db then
        _db = sqlite3.open(require("config").global.blacklist_db)
        -- WAL 模式：读写不互斥，适合多 worker
        _db:exec("PRAGMA journal_mode=WAL")
    end
    return _db
end

-- ---------------------------------------------------------------------------
-- ensure_table() — 确保黑名单表存在（在 init_worker 阶段调用）
--
-- 表结构与 Python 版完全一致，sqlite 文件可互用
-- ---------------------------------------------------------------------------
function blacklist.ensure_table()
    local db = get_db()
    db:exec([[
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            domain TEXT NOT NULL DEFAULT 'GLOBAL',
            created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
        )
    ]])
    _init = true
    ngx.log(ngx.INFO, "[blacklist] SQLite table ensured")
end

-- ---------------------------------------------------------------------------
-- _ban_sqlite(ip, domain) — 同步写入 SQLite
-- ---------------------------------------------------------------------------
function blacklist._ban_sqlite(ip, domain)
    if not _init then
        ngx.log(ngx.WARN, "[blacklist] ensure_table not called, skipping SQLite write")
        return
    end
    local db = get_db()
    local stmt = db:prepare("INSERT OR IGNORE INTO blacklist (ip, domain) VALUES (?, ?)")
    stmt:bind(1, ip)
    stmt:bind(2, domain or "GLOBAL")
    local rc = stmt:step()
    if rc ~= sqlite3.DONE then
        ngx.log(ngx.ERR, "[blacklist] SQLite INSERT failed: ", db:errmsg())
    end
    stmt:finalize()
end

-- ---------------------------------------------------------------------------
-- 运行时查询（shared dict，O(1) 性能）
-- IP 被封禁当且仅当 shared dict 中存在 "ban:ip:GLOBAL" 或 "ban:ip:domain"
-- ---------------------------------------------------------------------------
function blacklist.is_banned(ip, domain)
    local dict = ngx.shared.blacklist
    if dict:get("ban:" .. ip .. ":GLOBAL") then
        return true
    end
    if domain and dict:get("ban:" .. ip .. ":" .. domain) then
        return true
    end
    return false
end

-- ---------------------------------------------------------------------------
-- ban(ip, domain) — 封禁（同步写入 shared dict + SQLite）
-- ---------------------------------------------------------------------------
function blacklist.ban(ip, domain)
    ngx.shared.blacklist:set("ban:" .. ip .. ":" .. (domain or "GLOBAL"), true)
    blacklist._ban_sqlite(ip, domain)
    ngx.log(ngx.INFO, "[blacklist] banned ", ip, " on ", domain or "GLOBAL")
end

-- ---------------------------------------------------------------------------
-- unban(ip) — 解封，从 shared dict 和 SQLite 移除该 IP 所有记录
-- 与 Python 版 blacklist.remove_ip 行为一致（DELETE WHERE ip=?）
-- ---------------------------------------------------------------------------
function blacklist.unban(ip)
    -- 从 shared dict 删除所有该 IP 的 key
    local dict = ngx.shared.blacklist
    local all_keys = dict:get_keys(0)  -- 0 = 返回所有 key
    local prefix = "ban:" .. ip .. ":"
    for _, key in ipairs(all_keys) do
        if key:sub(1, #prefix) == prefix then
            dict:delete(key)
        end
    end

    -- 从 SQLite 删除（所有 domain）
    if _init then
        local db = get_db()
        local stmt = db:prepare("DELETE FROM blacklist WHERE ip = ?")
        stmt:bind(1, ip)
        local rc = stmt:step()
        if rc ~= sqlite3.DONE then
            ngx.log(ngx.ERR, "[blacklist] SQLite DELETE failed: ", db:errmsg())
        end
        stmt:finalize()
    end

    ngx.log(ngx.INFO, "[blacklist] unbanned ", ip)
end

-- ---------------------------------------------------------------------------
-- load_all_to_shared() — 启动时从 SQLite 载入 shared dict
-- 在 init_worker 阶段调用（每个 worker 执行一次）
-- ---------------------------------------------------------------------------
function blacklist.load_all_to_shared()
    if not _init then
        ngx.log(ngx.WARN, "[blacklist] ensure_table not called, skipping load")
        return
    end

    local db = get_db()
    local stmt = db:prepare("SELECT ip, domain FROM blacklist")
    local count = 0
    for row in stmt:nrows() do
        ngx.shared.blacklist:set("ban:" .. row.ip .. ":" .. row.domain, true)
        count = count + 1
    end
    stmt:finalize()
    ngx.log(ngx.INFO, "[blacklist] loaded ", count, " entries from SQLite")
end

return blacklist
