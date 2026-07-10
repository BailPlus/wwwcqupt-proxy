-- ============================================================================
-- config.lua — 全局基础设施参数（极少变动的常量）
--
-- 各站点配置已移到 conf/sites-available/*.conf 中的 nginx set 变量，
-- Lua 通过 ngx.var 读取。
-- 这里只保留 Lua 运行时需要的全局基础设施路径和秘密。
-- ============================================================================

local config = {}

config.global = {
    -- 黑名单 SQLite 数据库路径
    blacklist_db     = "/data/blacklist.db",
    -- TOTP 解封码密钥（优先使用环境变量，否则使用默认值）
    -- 设置方式：export UNBAN_CODE_SECRET=... && openresty -g "daemon off;"
    unban_code_secret = os.getenv("UNBAN_CODE_SECRET"),
}

return config
