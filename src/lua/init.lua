-- ============================================================================
-- init.lua — OpenResty 初始化（init_by_lua* / init_worker_by_lua*）
--
-- 注意：此代码仅在 nginx 运行时执行，nginx -t 不执行此文件。
-- 如需独立运行验证，见 validate.lua，调用方式：
--   resty -I /app /app/validate.lua
-- ============================================================================

local init = {}

-- ---------------------------------------------------------------------------
-- init_by_lua
-- nginx.conf: init_by_lua_block { require("init").init_by() }
-- ---------------------------------------------------------------------------
function init.init_by()
    ngx.log(ngx.INFO, "[init] OpenResty proxy starting up")

    -- preload 所有模块：模块加载失败会在此阶段报错，阻断 nginx 启动
    local modules = { "config", "blacklist", "router", "response", "ratelimit", "totp" }
    for _, name in ipairs(modules) do
        local ok, err = pcall(require, name)
        if not ok then
            ngx.log(ngx.ERR, "[init] 模块 ", name, " 加载失败: ", err)
            -- error(err)  -- 取消注释可让启动在模块加载失败时中断
        end
    end

    -- 验证关键数据文件
    local cfg = require("config")
    local f, err = io.open(cfg.global.blacklist_db, "r")
    if not f then
        ngx.log(ngx.WARN, "[init] 黑名单数据库未找到（首次启动正常）: ", err)
    else
        f:close()
    end
end

-- ---------------------------------------------------------------------------
-- init_worker_by_lua
-- nginx.conf: init_worker_by_lua_block { require("init").init_worker() }
--
-- 工作进程启动后的钩子：
--   - 从 SQLite 将黑名单加载到共享内存
--   - 启动定时器定期同步
-- ---------------------------------------------------------------------------
function init.init_worker()
    -- 初始化黑名单 SQLite 表结构 + 加载到 shared dict
    local blacklist = require("blacklist")
    blacklist.ensure_table()
    blacklist.load_all_to_shared()

    ngx.log(ngx.INFO, "[init] worker ", ngx.worker.id(), " ready")
end

return init
