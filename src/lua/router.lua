-- ============================================================================
-- router.lua — 请求管线入口
--
-- 路由由 nginx server_name 原生处理（不再需要 config.find_site），
-- 各站点参数通过 ngx.var 读取 nginx set 变量。
--
-- 阶段：
--   access_by_lua*       → route()            —— 解封 / 黑名单 / 频率 / 反伪造
--   header_filter_by_lua → header_filter()    —— 拦截上游 601 / 404+ban404
--   body_filter_by_lua   → body_filter()      —— 覆盖响应体为封禁页
--   log_by_lua*          已移除，改用 nginx 原生 access_log
-- ============================================================================

local blacklist = require "blacklist"
local ratelimit = require "ratelimit"
local response = require "response"
local totp     = require "totp"
local config   = require "config"

local router = {}

-- ---------------------------------------------------------------------------
-- route() — 访问控制（access_by_lua* 阶段）
-- ---------------------------------------------------------------------------
function router.route()
    local ip = ngx.var.remote_addr
    local domain = ngx.var.server_name  -- nginx 已按 server_name 匹配好

    -- 存储上下文，供下游 header_filter / body_filter 阶段使用
    ngx.ctx.client_ip = ip
    ngx.ctx.ban404    = ngx.var.site_ban404 == "true"  -- set $site_ban404

    -- 1) 检查解封
    local unban_code = ngx.req.get_headers()["Unban-Code"]
    if unban_code then
        local secret = config.global.unban_code_secret
        if totp.verify(secret, unban_code) then
            blacklist.unban(ip)
            ngx.log(ngx.INFO, "[router] unbanned ", ip)
        else
            ngx.status = 403
            response.send_ban(ip, domain, "解封码错误")
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    --- 2) 黑名单检查
    if blacklist.is_banned(ip, domain) then
        response.send_ban(ip, domain)
        return
    end

    -- 3) 频率检查（前提：站点的 conf 中定义了 freq_* 变量）
    local freq_window = tonumber(ngx.var.freq_window_size)
    local freq_max    = tonumber(ngx.var.freq_max_requests)
    if freq_window and freq_max then
        local restrict = { window_size = freq_window, max_requests = freq_max }
        if not ratelimit.check(ip, restrict) then
            response.send_ban(ip, domain, "请求频率过高")
            return
        end
    end

    -- 4) 反 X-Real-IP 伪造
    if ngx.req.get_headers()["X-Real-IP"] then
        response.send_ban(ip, domain, "你从哪里来？")
        return
    end
    -- X-Real-IP 注入由各 site conf 中的 proxy_set_header 完成
end

-- ---------------------------------------------------------------------------
-- reject_invalid_host() — 拒绝非法 Host 请求
-- 由 nginx.conf 中 default_server 块的 access_by_lua* 调用
-- ---------------------------------------------------------------------------
function router.reject_invalid_host()
    local ip       = ngx.var.remote_addr
    local host_raw = ngx.var.host or "unknown"
    ngx.log(ngx.WARN, "[router] rejecting unknown host: ", host_raw, " from ", ip)
    response.send_ban(ip, nil, "我实在告诉你们：我不认识你们。——[太25:12]")
end

-- ---------------------------------------------------------------------------
-- header_filter() — 拦截上游返回的特殊状态码（header_filter_by_lua* 阶段）
--
-- 此时原始响应头已收到但**尚未发送给客户端**，可以修改 ngx.status 和
-- ngx.header。修改后的值才是最终发出去的响应头。
-- ---------------------------------------------------------------------------
function router.header_filter()
    local status = ngx.status
    if status ~= 601 then
        local ban404 = ngx.ctx.ban404
        if not (status == 404 and ban404) then
            return  -- 普通响应，不做处理
        end
    end

    -- 601 或 404+ban404 → 拦截，改为 403 封禁
    local msg = (status == 601) and "你在搞什么？" or "页面走丢了捏"

    -- 改状态码和响应头（此时还未发给客户端）
    ngx.status = 403
    ngx.header["Content-Type"] = "text/html; charset=utf-8"

    -- 把封禁信息传给 body_filter 阶段
    ngx.ctx._intercept_msg = msg
end

-- ---------------------------------------------------------------------------
-- body_filter() — 覆盖上游响应体为封禁页（body_filter_by_lua* 阶段）
--
-- 此时状态码和响应头已发出（被 header_filter 改过），我们只能改 body。
-- body_filter 中不能调用 ngx.exit，不能写 ngx.status/ngx.header。
-- ---------------------------------------------------------------------------
function router.body_filter()
    if ngx.arg[2] then return end  -- last_buf，跳过

    local msg = ngx.ctx._intercept_msg
    if not msg then return end  -- 不走拦截

    local ip     = ngx.ctx.client_ip
    local domain = ngx.var.server_name

    -- 封禁该 IP
    blacklist.ban(ip, domain)
    ngx.log(ngx.WARN, "[router] upstream ban intercepted: ", ip, " on ", domain)

    -- 覆盖 body 为封禁页
    ngx.arg[1] = response.ban_page(msg)
    ngx.arg[2] = true  -- last_buf：丢弃上游后续 body 分片
end

return router
