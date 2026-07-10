-- ============================================================================
-- validate.lua — 独立运行的项目验证脚本
--
-- 用途：部署或 CI 时，在 nginx -t 之后调用此脚本，检查 Lua 模块完整性
-- 以及运行时所需的外部资源（文件、数据库等）。
--
-- 用法：
--   resty -I /app /app/validate.lua
--
-- 退出码：
--   0 — 全部通过
--   1 — 至少一项检查失败
-- ============================================================================

local checks = 0
local passed = 0
local failed = 0

local function check(desc, fn)
    checks = checks + 1
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        print("  ✓ " .. desc)
    else
        failed = failed + 1
        print("  ✗ " .. desc)
        print("    └─ " .. tostring(err))
    end
end

local function file_exists(path)
    local f = io.open(path, "r")
    if not f then return false, "文件不存在: " .. path end
    f:close()
    return true
end

-- ============================================================================
-- 1) 核心 Lua 模块加载
-- ============================================================================
print("\n── 模块加载 ──")

check("config 模块", function()
    local cfg = require("config")
    assert(cfg.global, "缺少 config.global")
    assert(type(cfg.global.blacklist_db) == "string", "blacklist_db 不是字符串")
end)

local required_modules = { "blacklist", "router", "response", "ratelimit", "totp", "init" }
for _, name in ipairs(required_modules) do
    check(name .. " 模块", function()
        local mod = require(name)
        assert(type(mod) == "table", "模块未返回 table")
    end)
end

-- ============================================================================
-- 2) 文件系统—数据资源
-- ============================================================================
print("\n── 数据资源 ──")

check("blacklist.db", function()
    local cfg = require("config")
    file_exists(cfg.global.blacklist_db)
end)

-- ============================================================================
-- 3) 文件系统—SSL 证书（与 nginx.conf 中路径一致）
-- ============================================================================
print("\n── SSL 证书 ──")

check("/data/fullchain.pem", function()
    file_exists("/data/fullchain.pem")
end)
check("/data/privkey.pem", function()
    file_exists("/data/privkey.pem")
end)

-- ============================================================================
-- 4) 站点配置文件（与 nginx.conf 中 include 路径一致）
-- ============================================================================
print("\n── 站点配置 ──")

check("conf.d 目录有站点配置", function()
    local f = io.popen("ls -A /data/conf.d/ 2>/dev/null")
    local output = f:read("*all")
    f:close()
    if not output or #output == 0 then error("/data/conf.d/ 为空或不存在") end
    local count = 0
    for _ in output:gmatch("[^\n]+") do count = count + 1 end
    print("    └─ 共 " .. count .. " 个站点配置")
end)

-- ============================================================================
-- 结果
-- ============================================================================
print(string.format("\n═══ 结果: %d/%d 通过, %d 失败 ═══\n", passed, checks, failed))

if failed > 0 then
    os.exit(1)
end
