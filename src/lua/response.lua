-- ============================================================================
-- response.lua — 封禁页面生成 + 特殊状态码处理（对应 Python: Blocker.ban + 代理 601/404 处理）
-- ============================================================================

local response = {}

-- ---------------------------------------------------------------------------
-- ban_page(msg) — 生成封禁页面的完整 HTML
-- 直接嵌入 HTML（避免文件 IO），对应 Python 的 Jinja2 模板 banned.html
-- ---------------------------------------------------------------------------
local BANNED_HTML = [[
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1.0,user-scalable=no">
        <title>你已被封禁</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f8f8f8;
                color: #333;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                text-align: center;
            }
            .container {
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                padding: 40px 30px;
                max-width: 400px;
                width: 90%;
                transition: all 0.3s ease-in-out;
            }
            h1 { margin-top: 0; font-size: 28px; color: #d32f2f; }
            p { font-size: 16px; margin-bottom: 25px; }
            .unbanDiv { display: flex; flex-direction: column; gap: 10px; }
            input[type="text"] {
                padding: 10px; font-size: 14px;
                border: 1px solid #ccc; border-radius: 4px;
                width: 100%; box-sizing: border-box;
            }
            button {
                padding: 10px; font-size: 16px;
                background-color: #d32f2f; color: white;
                border: none; border-radius: 4px; cursor: pointer;
                transition: background-color 0.3s ease;
            }
            button:hover { background-color: #a92727; }
            @media (max-width: 500px) { .container { padding: 30px 20px; } }
        </style>
        <script>
            function unban() {
                var unbanCode = document.getElementById("unbanCodeInput").value;
                if (unbanCode) {
                    fetch('/', { headers: { 'Unban-Code': unbanCode } })
                        .then(_ => window.location.reload());
                }
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>你已被封禁</h1>
            <p>__MSG__</p>
            <div class="unbanDiv">
                <input type="text" name="unban_code" id="unbanCodeInput" placeholder="解封码，请向Bail索取">
                <button onclick="unban()">解封</button>
            </div>
        </div>
    </body>
</html>
]]

function response.ban_page(msg)
    msg = msg or "检测到你有违规操作，已禁止访问。如有疑问，请咨询Bail。"
    -- 追加随机 1-10 个空格，防止代理/CDN 响应缓存碰撞（与 Python 版一致）
    local padding = string.rep(" ", math.random(1, 10))
    msg = msg .. padding
    local html = BANNED_HTML:gsub("__MSG__", msg)
    return html
end

-- ---------------------------------------------------------------------------
-- send_ban(ip, domain, msg) — 封禁并返回响应（供 router 调用）
-- 返回 { status, body, headers } 供 ngx.say / ngx.exit 使用
-- ---------------------------------------------------------------------------
function response.send_ban(ip, domain, msg)
    -- 封禁该 IP
    local blacklist = require "blacklist"
    blacklist.ban(ip, domain)

    ngx.status = 403
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(response.ban_page(msg))
    return ngx.exit(ngx.HTTP_FORBIDDEN)  -- ≥200 → 跳过 content 阶段，proxy_pass 不会执行
end

-- ---------------------------------------------------------------------------
-- handle_upstream_ban(ip, domain, msg) — body_filter 阶段专用的封禁处理
-- body_filter 里不能调用 send_ban（ngx.exit 语义不同），应就地拦截上游响应
-- ---------------------------------------------------------------------------
function response.handle_upstream_ban(ip, domain, msg)
    local blacklist = require "blacklist"
    blacklist.ban(ip, domain)

    ngx.status = 403
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.arg[1] = response.ban_page(msg)
    ngx.arg[2] = true  -- last_buf — 丢弃上游后续 body 分片
end

-- ---------------------------------------------------------------------------
-- handle_upstream_status(status, site, ip) — 处理上游返回的特殊状态码
-- 对应 Python 的：
--   resp.status_code == 601 → BanThisIp
--   resp.status_code == 404 and site.ban404 → BanThisIp
-- 返回 true 表示已处理（需要中断），false 表示正常放行
-- ---------------------------------------------------------------------------
function response.handle_upstream_status(status, site, ip)
    if status == 601 then
        response.send_ban(ip, site.domain, "你在搞什么？")
        return true
    end
    if status == 404 and site.ban404 then
        response.send_ban(ip, site.domain, "页面走丢了捏")
        return true
    end
    return false
end

return response
