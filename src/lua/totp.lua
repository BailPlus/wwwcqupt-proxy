-- ============================================================================
-- totp.lua — TOTP（基于时间的一次性密码）实现（替代 Python pyotp）
--
-- 注意：LuaJIT（OpenResty）基于 Lua 5.1，不支持 << >> & | 等 Lua 5.3
-- 位运算符，使用 LuaJIT 内置的 bit 库替代。
--
-- 算法：RFC 6238（HMAC-SHA1 + 30 秒时间窗口）
-- 用于验证 Unban-Code 请求头中的解封码
-- ============================================================================

local totp = {}

-- LuaJIT 位运算库（Lua 5.1 兼容）
local band = bit.band
local bor  = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift

-- 标准 Base32 字母表（RFC 4648）
local B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

-- ---------------------------------------------------------------------------
-- Base32 解码（RFC 4648）
-- 输入：大写 Base32 字符串（去填充 =）
-- 返回：解码后的字节串
-- ---------------------------------------------------------------------------
local function base32_decode(s)
    if not s or #s == 0 then return nil end

    -- 转大写、去填充
    s = s:upper()
    s = s:gsub("=", "")

    local decoded = {}
    local buffer = 0
    local bits   = 0

    for i = 1, #s do
        local char = s:sub(i, i)
        local value = B32_ALPHABET:find(char, 1, true)
        if not value then return nil end  -- 非法字符
        value = value - 1  -- 0-indexed

        buffer = bor(lshift(buffer, 5), value)
        bits = bits + 5

        if bits >= 8 then
            bits = bits - 8
            decoded[#decoded + 1] = string.char(band(rshift(buffer, bits), 0xFF))
            -- 保留低 bits 位，丢弃已提取的高 8 位
            buffer = band(buffer, lshift(1, bits) - 1)
        end
    end

    return table.concat(decoded)
end

-- ---------------------------------------------------------------------------
-- 动态截断（RFC 4226 §5.4）
-- 输入：20 字节的 HMAC-SHA1 结果
-- 返回：6 位数字验证码（0-999999）
-- ---------------------------------------------------------------------------
local function truncate(hs)
    -- 取最后一个字节的低 4 位作为偏移量
    local offset = band(string.byte(hs, #hs), 0x0F)

    -- 取连续 4 字节
    local b1 = band(string.byte(hs, offset + 1), 0x7F)
    local b2 = band(string.byte(hs, offset + 2), 0xFF)
    local b3 = band(string.byte(hs, offset + 3), 0xFF)
    local b4 = band(string.byte(hs, offset + 4), 0xFF)

    local code = bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)
    return code % 1000000
end

-- ---------------------------------------------------------------------------
-- 生成指定时间步的 TOTP 码
-- secret：Base32 编码的密钥字符串
-- counter：时间步（int，通常为 floor(time / 30)）
-- 返回：6 位数字字符串（前置补零）
-- ---------------------------------------------------------------------------
local function totp_at(secret, counter)
    local key = base32_decode(secret)
    if not key then return nil end

    -- 将 counter 编码为 8 字节大端序
    -- 注：bit 库限制 32 位，但 counter（秒数/30）最多 5kw，8 字节足够
    local msg_bytes = {}
    local c = counter
    for i = 8, 1, -1 do
        msg_bytes[i] = string.char(c % 256)
        c = math.floor(c / 256)  -- 用算术右移，避免 32 位截断
    end
    local msg = table.concat(msg_bytes)

    -- HMAC-SHA1
    local hmac = ngx.hmac_sha1(key, msg)

    -- 动态截断
    local otp = truncate(hmac)

    -- 格式化为 6 位数字字符串
    return string.format("%06d", otp)
end

-- ---------------------------------------------------------------------------
-- verify(secret, code) → boolean
-- 验证给定代码在当前时间窗口（±1 个窗口）是否有效
-- 与 pyotp.TOTP(secret).verify(code) 行为一致
-- ---------------------------------------------------------------------------
function totp.verify(secret, code)
    if not secret or #secret == 0 or not code then return false end

    local code_str = tostring(code)
    local now = ngx.time()
    local time_step = 30
    local current = math.floor(now / time_step)

    -- 检查当前、前一个、后一个时间窗口（容忍时钟偏差）
    for delta = -1, 1 do
        local expected = totp_at(secret, current + delta)
        if expected and expected == code_str then
            return true
        end
    end

    return false
end

return totp
