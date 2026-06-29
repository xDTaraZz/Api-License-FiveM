if not LPH_OBFUSCATED then
    local assert = assert
    local type = type
    local setfenv = setfenv

    LPH_ENCNUM = function(toEncrypt, ...)
        assert(type(toEncrypt) == "number" and #{...} == 0, "LPH_ENCNUM only accepts a single constant double or integer as an argument.")
        return toEncrypt
    end
    LPH_NUMENC = LPH_ENCNUM

    LPH_ENCSTR = function(toEncrypt, ...)
        assert(type(toEncrypt) == "string" and #{...} == 0, "LPH_ENCSTR only accepts a single constant string as an argument.")
        return toEncrypt
    end
    LPH_STRENC = LPH_ENCSTR

    LPH_ENCFUNC = function(toEncrypt, encKey, decKey, ...)
        assert(type(toEncrypt) == "function" and type(encKey) == "string" and #{...} == 0, "LPH_ENCFUNC accepts a constant function, constant string, and string variable as arguments.")
        return toEncrypt
    end
    LPH_FUNCENC = LPH_ENCFUNC

    LPH_JIT = function(f, ...)
        assert(type(f) == "function" and #{...} == 0, "LPH_JIT only accepts a single constant function as an argument.")
        return f
    end
    LPH_JIT_MAX = LPH_JIT

    LPH_NO_VIRTUALIZE = function(f, ...)
        assert(type(f) == "function" and #{...} == 0, "LPH_NO_VIRTUALIZE only accepts a single constant function as an argument.")
        return f
    end

    LPH_NO_UPVALUES = function(f, ...)
        assert(type(setfenv) == "function", "LPH_NO_UPVALUES can only be used on Lua versions with getfenv & setfenv")
        assert(type(f) == "function" and #{...} == 0, "LPH_NO_UPVALUES only accepts a single constant function as an argument.")
        return f
    end

    LPH_CRASH = function(...)
        assert(#{...} == 0, "LPH_CRASH does not accept any arguments.")
    end
end

assert(
    pcall(function()
        assert(type(setmetatable) == 'function')
        assert(type(RegisterCommand) == 'function')
        assert(type(RegisterNetEvent) == 'function')
        assert(type(Citizen) == 'table')
    end),
    'Suspicious activity detected'
)

do
    local gi = debug and debug.getinfo
    local ok, tampered = pcall(function()
        if type(debug.gethook) == 'function' and debug.gethook() ~= nil then return true end

        local function isC(fn)
            if type(fn) ~= 'function' then return false end
            local info = gi(fn, 'S')
            return info ~= nil and info.what == 'C'
        end

        local cfns = {
            setmetatable, getmetatable, rawget, rawset, rawequal,
            type, tostring, tonumber, pcall, xpcall,
            pairs, ipairs, next, select, assert,
            error, print, collectgarbage, gi, debug.traceback,
            string.byte, string.char, string.sub, string.format, string.rep,
            string.gsub, table.concat, math.floor,
        }
        for i = 1, #cfns do
            if not isC(cfns[i]) then return true end
        end

        if type(Citizen) ~= 'table' or not isC(Citizen.InvokeNative) then return true end
        if type(msgpack) ~= 'table' or type(msgpack.pack) ~= 'function' then return true end
        if type(json) ~= 'table' or type(promise) ~= 'table' then return true end

        local req = {
            PerformHttpRequest, PerformHttpRequestInternalEx, RegisterCommand,
            RegisterNetEvent, AddEventHandler, TriggerEvent, GetCurrentResourceName,
            GetConvar, StopResource, Citizen.CreateThread, Citizen.Await, Citizen.Wait,
        }
        for i = 1, #req do
            if type(req[i]) ~= 'function' then return true end
        end

        return false
    end)

    if (not ok) or tampered then
        print('[^1' .. GetCurrentResourceName() .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
        while true do end
    end
end

local sha256, hmac_sha256
do
    local K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    }
    local MASK = 0xFFFFFFFF
    local byte, char, format, rep, gsub = string.byte, string.char, string.format, string.rep, string.gsub
    local concat = table.concat

    local function rrot(x, n)
        return ((x >> n) | (x << (32 - n))) & MASK
    end

    local digest = LPH_NO_VIRTUALIZE(function(msg)
        local H0,H1,H2,H3 = 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
        local H4,H5,H6,H7 = 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

        local bitlen = #msg * 8
        msg = msg .. '\128'
        while (#msg % 64) ~= 56 do msg = msg .. '\0' end
        for i = 7, 0, -1 do
            msg = msg .. char((bitlen >> (i * 8)) & 0xFF)
        end

        local w = {}
        for chunk = 1, #msg, 64 do
            for i = 0, 15 do
                local j = chunk + i * 4
                w[i] = ((byte(msg, j) << 24) | (byte(msg, j + 1) << 16)
                      | (byte(msg, j + 2) << 8) | byte(msg, j + 3)) & MASK
            end
            for i = 16, 63 do
                local x15, x2 = w[i - 15], w[i - 2]
                local s0 = rrot(x15, 7) ~ rrot(x15, 18) ~ (x15 >> 3)
                local s1 = rrot(x2, 17) ~ rrot(x2, 19) ~ (x2 >> 10)
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK
            end

            local a,b,c,d,e,f,g,h = H0,H1,H2,H3,H4,H5,H6,H7
            for i = 0, 63 do
                local S1 = rrot(e, 6) ~ rrot(e, 11) ~ rrot(e, 25)
                local ch = (e & f) ~ ((~e & MASK) & g)
                local t1 = (h + S1 + ch + K[i + 1] + w[i]) & MASK
                local S0 = rrot(a, 2) ~ rrot(a, 13) ~ rrot(a, 22)
                local maj = (a & b) ~ (a & c) ~ (b & c)
                local t2 = (S0 + maj) & MASK
                h = g; g = f; f = e; e = (d + t1) & MASK
                d = c; c = b; b = a; a = (t1 + t2) & MASK
            end

            H0 = (H0 + a) & MASK; H1 = (H1 + b) & MASK
            H2 = (H2 + c) & MASK; H3 = (H3 + d) & MASK
            H4 = (H4 + e) & MASK; H5 = (H5 + f) & MASK
            H6 = (H6 + g) & MASK; H7 = (H7 + h) & MASK
        end

        local function w2b(x)
            return char((x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF)
        end
        return w2b(H0)..w2b(H1)..w2b(H2)..w2b(H3)..w2b(H4)..w2b(H5)..w2b(H6)..w2b(H7)
    end)

    local function tohex(bin)
        return (gsub(bin, '.', function(c) return format('%02x', byte(c)) end))
    end

    sha256 = function(msg) return tohex(digest(msg)) end

    hmac_sha256 = LPH_NO_VIRTUALIZE(function(key, msg)
        local BS = 64
        if #key > BS then key = digest(key) end
        if #key < BS then key = key .. rep('\0', BS - #key) end
        local ipad, opad = {}, {}
        for i = 1, BS do
            local b = byte(key, i)
            ipad[i] = char(b ~ 0x36)
            opad[i] = char(b ~ 0x5c)
        end
        local inner = digest(concat(ipad) .. msg)
        return tohex(digest(concat(opad) .. inner))
    end)
end

assert(
    sha256('abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    and hmac_sha256('key', 'The quick brown fox jumps over the lazy dog')
        == 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
    'crypto self-test failed'
)

local ed25519_verify
do
    local floor = math.floor
    local schar, sbyte, concat = string.char, string.byte, table.concat

    local SK = {
        0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
        0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
        0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
        0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
        0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
        0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
        0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
        0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
        0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
        0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
        0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
        0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
        0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
    }
    local function rotr(x, n) return (x >> n) | (x << (64 - n)) end
    local sha512 = LPH_NO_VIRTUALIZE(function(msg)
        local H = {0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
                   0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179}
        local bitlen = #msg * 8
        msg = msg .. '\128'
        while (#msg % 128) ~= 112 do msg = msg .. '\0' end
        for _ = 1, 8 do msg = msg .. '\0' end
        for i = 7, 0, -1 do msg = msg .. schar((bitlen >> (i * 8)) & 0xFF) end
        local w = {}
        for chunk = 1, #msg, 128 do
            for i = 0, 15 do
                local j = chunk + i * 8
                local v = 0
                for k = 0, 7 do v = (v << 8) | sbyte(msg, j + k) end
                w[i] = v
            end
            for i = 16, 79 do
                local x15, x2 = w[i - 15], w[i - 2]
                local s0 = rotr(x15, 1) ~ rotr(x15, 8) ~ (x15 >> 7)
                local s1 = rotr(x2, 19) ~ rotr(x2, 61) ~ (x2 >> 6)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            end
            local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
            for i = 0, 79 do
                local S1 = rotr(e, 14) ~ rotr(e, 18) ~ rotr(e, 41)
                local ch = (e & f) ~ ((~e) & g)
                local t1 = h + S1 + ch + SK[i + 1] + w[i]
                local S0 = rotr(a, 28) ~ rotr(a, 34) ~ rotr(a, 39)
                local maj = (a & b) ~ (a & c) ~ (b & c)
                local t2 = S0 + maj
                h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2
            end
            H[1]=H[1]+a; H[2]=H[2]+b; H[3]=H[3]+c; H[4]=H[4]+d
            H[5]=H[5]+e; H[6]=H[6]+f; H[7]=H[7]+g; H[8]=H[8]+h
        end
        local out = {}
        for i = 1, 8 do
            local v = H[i]
            for k = 7, 0, -1 do out[#out + 1] = schar((v >> (k * 8)) & 0xFF) end
        end
        return concat(out)
    end)

    local function gf(init)
        local r = {}
        for i = 0, 15 do r[i] = init and init[i + 1] or 0 end
        return r
    end
    local gf0 = gf()
    local gf1 = gf({1})
    local Dc  = gf({0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203})
    local D2  = gf({0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406})
    local Xc  = gf({0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169})
    local Yc  = gf({0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666})
    local Ic  = gf({0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43,0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83})

    local function set25519(r, a) for i = 0, 15 do r[i] = a[i] end end
    local function car25519(o)
        for i = 0, 15 do
            o[i] = o[i] + 65536
            local c = o[i] // 65536
            if i < 15 then o[i + 1] = o[i + 1] + c - 1 else o[0] = o[0] + 38 * (c - 1) end
            o[i] = o[i] - c * 65536
        end
    end
    local function Af(o, a, b) for i = 0, 15 do o[i] = a[i] + b[i] end end
    local function Zf(o, a, b) for i = 0, 15 do o[i] = a[i] - b[i] end end
    local Mf = LPH_NO_VIRTUALIZE(function(o, a, b)
        local t = {}
        for i = 0, 30 do t[i] = 0 end
        for i = 0, 15 do
            local ai = a[i]
            for j = 0, 15 do t[i + j] = t[i + j] + ai * b[j] end
        end
        for i = 0, 14 do t[i] = t[i] + 38 * t[i + 16] end
        for i = 0, 15 do o[i] = t[i] end
        car25519(o); car25519(o)
    end)
    local function Sf(o, a) Mf(o, a, a) end
    local function inv25519(o, a)
        local c = gf(); set25519(c, a)
        for i = 253, 0, -1 do
            Sf(c, c)
            if i ~= 2 and i ~= 4 then Mf(c, c, a) end
        end
        set25519(o, c)
    end
    local function sel25519(p, q, b)
        local c = ~(b - 1)
        for i = 0, 15 do
            local t = c & (p[i] ~ q[i])
            p[i] = p[i] ~ t
            q[i] = q[i] ~ t
        end
    end
    local function pack25519(o, n)
        local t = gf(); set25519(t, n)
        car25519(t); car25519(t); car25519(t)
        local m = gf()
        for _ = 1, 2 do
            m[0] = t[0] - 0xffed
            for i = 1, 14 do
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
                m[i - 1] = m[i - 1] & 0xffff
            end
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
            local b = (m[15] >> 16) & 1
            m[14] = m[14] & 0xffff
            sel25519(t, m, 1 - b)
        end
        for i = 0, 15 do
            o[2 * i]     = t[i] & 0xff
            o[2 * i + 1] = t[i] >> 8
        end
    end
    local function neq25519(a, b)
        local c, d = {}, {}
        pack25519(c, a); pack25519(d, b)
        for i = 0, 31 do if c[i] ~= d[i] then return 1 end end
        return 0
    end
    local function par25519(a)
        local d = {}
        pack25519(d, a)
        return d[0] & 1
    end
    local function unpack25519(o, n)
        for i = 0, 15 do o[i] = n[2 * i] + (n[2 * i + 1] << 8) end
        o[15] = o[15] & 0x7fff
    end

    local function newpt() return { gf(), gf(), gf(), gf() } end
    local gadd = LPH_NO_VIRTUALIZE(function(p, q)
        local a,b,c,d,e,f,g,h,t = gf(),gf(),gf(),gf(),gf(),gf(),gf(),gf(),gf()
        Zf(a, p[2], p[1]); Zf(t, q[2], q[1]); Mf(a, a, t)
        Af(b, p[1], p[2]); Af(t, q[1], q[2]); Mf(b, b, t)
        Mf(c, p[4], q[4]); Mf(c, c, D2)
        Mf(d, p[3], q[3]); Af(d, d, d)
        Zf(e, b, a); Zf(f, d, c); Af(g, d, c); Af(h, b, a)
        Mf(p[1], e, f); Mf(p[2], h, g); Mf(p[3], g, f); Mf(p[4], e, h)
    end)
    local function cswap(p, q, b) for i = 1, 4 do sel25519(p[i], q[i], b) end end
    local function packpt(r, p)
        local tx, ty, zi = gf(), gf(), gf()
        inv25519(zi, p[3])
        Mf(tx, p[1], zi)
        Mf(ty, p[2], zi)
        pack25519(r, ty)
        r[31] = r[31] ~ (par25519(tx) << 7)
    end
    local scalarmult = LPH_NO_VIRTUALIZE(function(p, q, s)
        set25519(p[1], gf0); set25519(p[2], gf1); set25519(p[3], gf1); set25519(p[4], gf0)
        for i = 255, 0, -1 do
            local b = (s[i >> 3] >> (i & 7)) & 1
            cswap(p, q, b); gadd(q, p); gadd(p, p); cswap(p, q, b)
        end
    end)
    local function scalarbase(p, s)
        local q = newpt()
        set25519(q[1], Xc); set25519(q[2], Yc); set25519(q[3], gf1); Mf(q[4], Xc, Yc)
        scalarmult(p, q, s)
    end
    local unpackneg = LPH_NO_VIRTUALIZE(function(r, p)
        local t,chk,num,den,den2,den4,den6 = gf(),gf(),gf(),gf(),gf(),gf(),gf()
        set25519(r[3], gf1)
        unpack25519(r[2], p)
        Sf(num, r[2]); Mf(den, num, Dc); Zf(num, num, r[3]); Af(den, r[3], den)
        Sf(den2, den); Sf(den4, den2); Mf(den6, den4, den2)
        Mf(t, den6, num); Mf(t, t, den)
        local pw = gf(); set25519(pw, t)
        for i = 250, 0, -1 do
            Sf(pw, pw)
            if i ~= 1 then Mf(pw, pw, t) end
        end
        set25519(t, pw)
        Mf(t, t, num); Mf(t, t, den); Mf(t, t, den); Mf(r[1], t, den)
        Sf(chk, r[1]); Mf(chk, chk, den)
        if neq25519(chk, num) ~= 0 then Mf(r[1], r[1], Ic) end
        Sf(chk, r[1]); Mf(chk, chk, den)
        if neq25519(chk, num) ~= 0 then return -1 end
        if par25519(r[1]) == (p[31] >> 7) then Zf(r[1], gf0, r[1]) end
        Mf(r[4], r[1], r[2])
        return 0
    end)

    local Lord = {0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
                  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10}
    local function modL(r, x)
        for i = 63, 32, -1 do
            local carry = 0
            local jmin = i - 32
            local jmax = i - 12
            for j = jmin, jmax - 1 do
                x[j] = x[j] + carry - 16 * x[i] * Lord[(j - (i - 32)) + 1]
                carry = (x[j] + 128) // 256
                x[j] = x[j] - carry * 256
            end
            x[jmax] = x[jmax] + carry
            x[i] = 0
        end
        local carry = 0
        local top = x[31] // 16
        for j = 0, 31 do
            x[j] = x[j] + carry - top * Lord[j + 1]
            carry = x[j] // 256
            x[j] = x[j] & 255
        end
        for j = 0, 31 do x[j] = x[j] - carry * Lord[j + 1] end
        for i = 0, 31 do
            x[i + 1] = x[i + 1] + (x[i] // 256)
            r[i] = x[i] & 255
        end
    end

    ed25519_verify = LPH_NO_VIRTUALIZE(function(pub, msg, sig)
        local q = newpt()
        if unpackneg(q, pub) ~= 0 then return false end
        local pre = {}
        for i = 0, 31 do pre[#pre + 1] = schar(sig[i]) end
        for i = 0, 31 do pre[#pre + 1] = schar(pub[i]) end
        local hstr = sha512(concat(pre) .. msg)
        local k64 = {}
        for i = 0, 63 do k64[i] = sbyte(hstr, i + 1) end
        local k = {}
        modL(k, k64)
        local s = {}
        for i = 0, 31 do s[i] = sig[32 + i] end
        local p = newpt()
        scalarmult(p, q, k)
        local sb = newpt()
        scalarbase(sb, s)
        gadd(p, sb)
        local packed = {}
        packpt(packed, p)
        local diff = 0
        for i = 0, 31 do diff = diff | (packed[i] ~ sig[i]) end
        return diff == 0
    end)

    ED_SHA512 = sha512
end

local function HexfromBytes(str)
    return (str:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
end

local function BytesFromHex(h)
    local t = {}
    if type(h) ~= 'string' then return t end
    local n = 0
    for pair in h:gmatch('%x%x') do
        t[n] = tonumber(pair, 16)
        n = n + 1
    end
    return t
end

assert(
    HexfromBytes(ED_SHA512('abc')) ==
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'ed25519 sha512 self-test failed'
)
do
    local tpub = BytesFromHex('1ac28101a158c2ffa29fa18ae9aa95771db3c282f8f1837517b26f7a80000192')
    local tsig = BytesFromHex('485eab958fcd2f08eff21ce26ad8a63bd98a1cc8b85bd79a57f2bf5daa2ef62d11259827c89e475dd059a79ce01d5417522d8ae8ae9431ce8040fc9fb5d44f05')
    local tmsg = '{"ok":true,"code":"ok","nonce":"deadbeef"}'
    local tbad = BytesFromHex('495eab958fcd2f08eff21ce26ad8a63bd98a1cc8b85bd79a57f2bf5daa2ef62d11259827c89e475dd059a79ce01d5417522d8ae8ae9431ce8040fc9fb5d44f05')
    assert(ed25519_verify(tpub, tmsg, tsig) == true
       and ed25519_verify(tpub, tmsg, tbad) == false
       and ed25519_verify(tpub, tmsg .. 'x', tsig) == false,
       'ed25519 verify self-test failed')
end

local function HexEqual(a, b)
    if type(a) ~= 'string' or type(b) ~= 'string' or #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        diff = diff | (string.byte(a, i) ~ string.byte(b, i))
    end
    return diff == 0
end

local nonceCounter = 0
local function MakeNonce()
    nonceCounter = nonceCounter + 1
    return sha256(string.format('%d:%d:%d:%d', os.time(), GetGameTimer(), nonceCounter, math.random(0, 2147483647))):sub(1, 32)
end

local SIG_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
local function wrapSig(realSig)
    local n = math.random(0, 64)
    local junk = {}
    for i = 1, n do
        local idx = math.random(1, #SIG_ALPHABET)
        junk[i] = SIG_ALPHABET:sub(idx, idx)
    end
    return string.format('%02x', n) .. table.concat(junk) .. realSig
end

local Secure = {
    ResourceName    = GetCurrentResourceName(),
    ResourceVersion = LPH_ENCSTR('1.0.0'),
    ApiUrl          = LPH_ENCSTR('http://localhost:3000/api/verify'),
    ProductId       = LPH_ENCSTR('prod_f909f6ed'),
    ProductSecret   = LPH_ENCSTR('f0c15570a1e4cae373fdd325cd2d9f4e458caf3a4f91c2b7d7ec65ef1ed7c505'),
    EdPublicKey     = LPH_ENCSTR('2e7fb1ff49a219e549b5bd47d265f2d6869fdd0685dd109e275fb235df4be2dd'),
    Token           = (Config and Config.Token) or '',

    IpApi           = LPH_ENCSTR('https://api.ipify.org?format=json'),
    authorized      = false,
    booted          = false,
    lastNonce       = nil,
    attemptRequest  = 0,
    inflight        = 0,
    done            = false,
    watchdog        = false,
    isCreatedInternalResponse = false,
    httpDispatch    = {},

    _print          = print,
    _AddEventHandler = AddEventHandler,
    _phr            = PerformHttpRequestInternalEx,
    getinfo         = debug.getinfo,
    strreverse      = string.reverse,

    mappedSources = {
        windows = {
            ['getinfo'] = '=[C]',
            ['string.reverse'] = '=[C]',
            ['PerformHttpRequest'] = '@citizen:/scripting/lua/scheduler.lua',
            ['PerformHttpRequestInternalEx'] = '@PerformHttpRequestInternalEx.lua',
            ['PerformHttpRequestInternal'] = '@PerformHttpRequestInternal.lua',
            ['here'] = 'wait for initializing..',
        },
        linux = {
            ['getinfo'] = '=[C]',
            ['string.reverse'] = '=[C]',
            ['PerformHttpRequest'] = '@citizen:/scripting/lua/scheduler.lua',
            ['PerformHttpRequestInternalEx'] = '@citizen:/scripting/lua/natives_server.lua',
            ['PerformHttpRequestInternal'] = '@citizen:/scripting/lua/natives_server.lua',
            ['here'] = 'wait for initializing..',
        },
    },
}

function Secure:CompareMappedSources(key, value)
    return self.mappedSources.windows[key] == value or self.mappedSources.linux[key] == value
end

function Secure:ValidatePrint()
    local info = self.getinfo(print)
    if not info or info.what ~= 'C' or info.nups ~= 0 or info.short_src ~= '[C]' then
        print = self._print
        self._print('[^1' .. self.ResourceName .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
        self:kill('print_hook')
        return false
    end
    return true
end

function Secure:print(...)
    if self:ValidatePrint() then
        self._print(...)
    end
end

function Secure:PrintVerifyOk()
    local res = GetCurrentResourceName()
    self:print('[^2' .. res .. '^7] license verified by ^2xDTaraZ^7  |  version ^5' .. self.ResourceVersion .. '^7  |  discord ^5xdtaraz_sln^0')
    self:print('[^2' .. res .. '^7] initializing data..^0')
    self:print('[^2' .. res .. '^7] startup complete, this resource is ^2READY ^7to use^0')
end

function Secure:PrintVerifyFail(ipText)
    local res = GetCurrentResourceName()
    self:print('[^1' .. res .. '^7] license could not be verified by ^1xDTaraZ^7  |  ip ^1' .. tostring(ipText or '-') .. '^7  |  discord ^5xdtaraz_sln^0')
    self:print('[^1' .. res .. '^7] this server is not authorized to run this resource^0')
end

function Secure:detect(code)
    self._print('[^1' .. self.ResourceName .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
    self:kill(code)
end

function Secure:srcOf(fn)
    if type(fn) ~= 'function' then return nil end
    local ok, info = pcall(self.getinfo, fn, 'S')
    return (ok and info and info.source) or nil
end

function Secure:isNative(fn)
    if type(fn) ~= 'function' then return false end
    return self:CompareMappedSources('PerformHttpRequestInternalEx', self:srcOf(fn))
end

function Secure:isCFn(fn)
    return self:srcOf(fn) == '=[C]'
end

function Secure:ValidateNative()
    if not self:ValidatePrint() then return false end

    if not self:CompareMappedSources('getinfo', self:srcOf(self.getinfo)) then
        self:detect('VN1'); return false
    end
    if not self:CompareMappedSources('PerformHttpRequest', self:srcOf(PerformHttpRequest)) then
        self:detect('VN2'); return false
    end
    if not self:CompareMappedSources('PerformHttpRequestInternalEx', self:srcOf(PerformHttpRequestInternalEx)) then
        self:detect('VN3'); return false
    end
    if not self:CompareMappedSources('string.reverse', self:srcOf(self.strreverse)) then
        self:detect('VN4'); return false
    end
    if not self:CompareMappedSources('PerformHttpRequestInternal', self:srcOf(PerformHttpRequestInternal)) then
        self:detect('VN6'); return false
    end
    if not self:isCFn(json.encode) or not self:isCFn(json.decode) then
        self:detect('VN7'); return false
    end
    if not self:isCFn(Citizen.InvokeNative) then
        self:detect('VN9'); return false
    end
    if not self:isCFn(msgpack.pack) then
        self:detect('VN10'); return false
    end
    if not self:isCFn(load) then
        self:detect('VN11'); return false
    end

    local here = self:srcOf(self.ValidateNative)
    self.mappedSources.windows['here'] = here
    self.mappedSources.linux['here'] = here
    if not self:CompareMappedSources('here', self:srcOf(self.addEventHandler)) then
        self:detect('VN5'); return false
    end

    return true
end

function Secure:addEventHandler(name, cb)
    if name == '__cfx_internal:httpResponse' then
        if self.isCreatedInternalResponse then
            self._print('[^1' .. self.ResourceName .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
            self:kill('dup_http')
            return
        end
        self.isCreatedInternalResponse = true
        return self._AddEventHandler(name, cb)
    end
    return self._AddEventHandler(name, cb)
end

function Secure:HttpRequest(url, cb, method, data, headers)
    local t = {
        url = url,
        method = method or 'GET',
        data = data or '',
        headers = headers or {},
        followLocation = true,
    }
    local id = self._phr(t)
    if id ~= -1 then
        self.httpDispatch[id] = cb
    else
        cb(0, nil)
    end
end

function Secure:ReportBypassScript(code)
    if type(self._phr) ~= 'function' then return end
    if not self:isNative(PerformHttpRequestInternalEx) then return end
    if not self:isNative(self._phr) then return end
    local url = (self.ApiUrl:gsub('/verify$', '/violation'))
    local body = json.encode({
        token = self.Token,
        product_id = self.ProductId,
        code = code,
        ip = self.lastIp or '',
        ts = os.time(),
        hostname = GetConvar('sv_hostname', ''),
    })
    local sig = hmac_sha256(self.ProductSecret, body)
    self:HttpRequest(url, function() end, 'POST', body,
        { ['Content-Type'] = 'application/json', ['X-Signature'] = wrapSig(sig) })
end

function Secure:kill(code)
    pcall(function() self:ReportBypassScript(code) end)
    if LPH_CRASH then pcall(LPH_CRASH) end
    StopResource(GetCurrentResourceName())
    while true do end
end

local function Rainbow(s)
    local out = {}
    for i = 1, #s do
        out[i] = '^' .. ((i - 1) % 9 + 1) .. s:sub(i, i)
    end
    return table.concat(out)
end

function Secure:Init()
    local evRequest = Rainbow(GetCurrentResourceName() .. ':auth:request')
    local evGrant = Rainbow(GetCurrentResourceName() .. ':auth:grant')
    RegisterNetEvent(evRequest)
    self._AddEventHandler(evRequest, function()
        if self.authorized then
            TriggerClientEvent(evGrant, source, true)
        end
    end)
    StartYourScript()
end

function Secure:Destroy(hide)
    if not hide then
        self:PrintVerifyFail(self.lastIp)
    end
    self.authorized = false
    StopResource(GetCurrentResourceName())
end

function Secure:Listener(status, body)
    if self.done then return end
    self.inflight = self.inflight - 1

    if body == nil or status == 0 then
        if self.attemptRequest < 5 then
            self.attemptRequest = self.attemptRequest + 1
            return CreateThread(function()
                Wait(3000)
                if self.lastIp then self:SendVerify(self.lastIp) else self:login() end
            end)
        end
        if self.inflight > 0 then return end
        self.done = true
        self:print('[^1' .. self.ResourceName .. '^7] verification server unreachable^0')
        return self:Destroy()
    end

    if status ~= 200 then
        if self.inflight > 0 then return end
        self.done = true
        self:print(('[^1' .. self.ResourceName .. '^7] verification server unreachable (%s)^0'):format(tostring(status)))
        return self:Destroy()
    end

    local ok, outer = pcall(json.decode, body)
    if not ok or type(outer) ~= 'table' or type(outer.payload) ~= 'string' then
        self.done = true
        self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
        return self:Destroy()
    end

    local expectedSig = hmac_sha256(self.ProductSecret, outer.payload)
    if not HexEqual(expectedSig, tostring(outer.sig or '')) then
        self.done = true
        self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
        return self:Destroy()
    end

    if self.EdPublicKey and self.EdPublicKey ~= 'PASTE_ED25519_PUBLIC_KEY_HERE' and #self.EdPublicKey == 64 then
        local edOk = false
        local pubBytes = BytesFromHex(self.EdPublicKey)
        local sigBytes = BytesFromHex(tostring(outer.ed or ''))
        if outer.ed and #tostring(outer.ed) == 128 then
            local ok = pcall(function()
                edOk = ed25519_verify(pubBytes, outer.payload, sigBytes)
            end)
            if not ok then edOk = false end
        end
        if not edOk then
            self.done = true
            self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
            return self:Destroy()
        end
    else
        self.done = true
        self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
        return self:Destroy()
    end

    local ok2, state = pcall(json.decode, outer.payload)
    if not ok2 or type(state) ~= 'table' then
        self.done = true
        self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
        return self:Destroy()
    end

    if state.nonce ~= self.lastNonce then
        return
    end

    self.done = true

    if state.ok ~= true then
        self:print(('[^1' .. self.ResourceName .. '^7] ^1License invalid ^7(%s)^0'):format(tostring(state.code or 'denied')))
        return self:Destroy()
    end

    if state.req_hash and state.req_hash ~= sha256(self.lastBody or '') then
        self:print('[^1' .. self.ResourceName .. '^7] ^1Suspicious activity detected^0')
        return self:Destroy()
    end

    self.authorized = true

    if self.booted then return end
    self.booted = true
    self:PrintVerifyOk()

    if state.latest_version and state.latest_version ~= '' and state.latest_version ~= self.ResourceVersion then
        self:print('[^3' .. self.ResourceName .. '^7] ^3UPDATE AVAILABLE^7 current ^3' .. self.ResourceVersion .. '^7 → latest ^2' .. tostring(state.latest_version) .. '^0')
        self:print('[^3' .. self.ResourceName .. '^7] please update this resource to the latest version^0')
    end

    self:Init()
end

function Secure:GetPublicIP(cb)
    self:HttpRequest(self.IpApi, function(status, body)
        local ip = ''
        if status == 200 and body then
            local ok, data = pcall(json.decode, body)
            if ok and type(data) == 'table' and type(data.ip) == 'string' then
                ip = data.ip
            end
        end
        cb(ip)
    end, 'GET', nil, { ['Content-Type'] = 'application/json' })
end

function Secure:SendVerify(ip)
    local nonce = MakeNonce()
    self.lastNonce = nonce
    self.lastIp = ip
    self.inflight = self.inflight + 1

    local body = json.encode({
        token      = self.Token,
        product_id = self.ProductId,
        action     = 'verify',
        nonce      = nonce,
        ts         = os.time(),
        ip         = ip,
        resource   = self.ResourceName,
        version    = self.ResourceVersion,
        hostname   = GetConvar('sv_hostname', ''),
    })
    self.lastBody = body

    local signature = hmac_sha256(self.ProductSecret, body)

    self:HttpRequest(self.ApiUrl, function(status, resp)
        self:Listener(status, resp)
    end, 'POST', body, { ['Content-Type'] = 'application/json', ['X-Signature'] = wrapSig(signature) })
end

function Secure:StartWatchdog()
    if self.watchdog then return end
    self.watchdog = true
    CreateThread(function()
        Wait(20000)
        if not self.done and not self.authorized then
            self.done = true
            self:print('[^1' .. self.ResourceName .. '^7] verification timed out^0')
            self:Destroy()
        end
    end)
end

function Secure:login()
    self:StartWatchdog()
    if not self:ValidateNative() then
        return self:Destroy(true)
    end
    if self.ProductSecret == 'replace-with-the-64-hex-product-secret' or #self.ProductSecret < 16 then
        self:print('[^1' .. self.ResourceName .. '^7] PRODUCT_SECRET is not set^0')
        return self:Destroy()
    end
    if self.Token == 'Exotic-XXXX-XXXX-XXXX-XXXX' or self.Token == '' then
        self:print('[^1' .. self.ResourceName .. '^7] Token is not set^0')
    end

    self:print('[^2' .. self.ResourceName .. '^7] verifying license..^0')
    self:GetPublicIP(function(ip)
        self:SendVerify(ip)
    end)
end

AddEventHandler = function(name, cb)
    return Secure:addEventHandler(name, cb)
end

AddEventHandler('__cfx_internal:httpResponse', function(token, status, body, headers, errorData)
    local cb = Secure.httpDispatch[token]
    if cb then
        Secure.httpDispatch[token] = nil
        cb(status, body, headers, errorData)
    end
end)

CreateThread(function()
    math.randomseed((GetGameTimer() ~ os.time()) & 0x7fffffff)
    Wait(500)
    local ok = pcall(function() Secure:login() end)
    if not ok then
        pcall(function() Secure:ReportBypassScript('VN8') end)
        Secure._print('[^1' .. Secure.ResourceName .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
        if LPH_CRASH then pcall(LPH_CRASH) end
        while true do end
    end
end)


function StartYourScript()
    print('scriptload')

end