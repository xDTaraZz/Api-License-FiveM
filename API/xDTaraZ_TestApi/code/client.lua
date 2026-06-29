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
        assert(type(RegisterNetEvent) == 'function')
        assert(type(TriggerServerEvent) == 'function')
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
            RegisterNetEvent, AddEventHandler, TriggerServerEvent,
            GetCurrentResourceName, Citizen.CreateThread, Citizen.Wait,
        }
        for i = 1, #req do
            if type(req[i]) ~= 'function' then return true end
        end

        return false
    end)

    if (not ok) or tampered then
        print('[^1' .. GetCurrentResourceName() .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
        if LPH_CRASH then pcall(LPH_CRASH) end
        while true do end
    end
end

local _print, _pcall = print, pcall
local _Citizen = Citizen
local _CreateThread = Citizen.CreateThread
local _Wait = Citizen.Wait
local _RegisterNetEvent = RegisterNetEvent
local _AddEventHandler = AddEventHandler
local _TriggerServerEvent = TriggerServerEvent
local _GetCurrentResourceName = GetCurrentResourceName
local _getinfo = debug.getinfo

local function kill(code)
    _print('[^1' .. _GetCurrentResourceName() .. '^7] ^1DETECTED UNAUTHORIZED MODIFY^0')
    if LPH_CRASH then pcall(LPH_CRASH) end
    while true do end
end

local function VaildatePrint()
    local info = _getinfo(print)
    if not info or info.what ~= 'C' or info.nups ~= 0 or info.short_src ~= '[C]' then
        return false
    end
    return true
end

local function VaildateNative()
    if not VaildatePrint() then return false end
    if type(_Citizen.InvokeNative) ~= 'function' then return false end
    local ok, info = _pcall(_getinfo, _Citizen.InvokeNative, 'S')
    if not ok or not info or info.what ~= 'C' then return false end
    return true
end

if not VaildateNative() then kill('hook') end

local granted = nil

local function RainbowEvent(s)
    local out = {}
    for i = 1, #s do
        out[i] = '^' .. ((i - 1) % 9 + 1) .. s:sub(i, i)
    end
    return table.concat(out)
end

local EventGrant = RainbowEvent(_GetCurrentResourceName() .. ':auth:grant')
local EventSendRequest = RainbowEvent(_GetCurrentResourceName() .. ':auth:request')

_RegisterNetEvent(EventGrant)
_AddEventHandler(EventGrant, function(ok)
    if granted == nil then
        granted = ok == true
    end
end)

_CreateThread(function()
    _Wait(1000)
    local tries = 0
    while granted == nil and tries < 60 do
        if not VaildateNative() then kill('hook') end
        _TriggerServerEvent(EventSendRequest)
        _Wait(500)
        tries = tries + 1
    end
    if granted == true then
        local res = _GetCurrentResourceName()
        _print('[^2' .. res .. '^7] client authorized, initializing data..^0')
        _print('[^2' .. res .. '^7] startup complete, client side is ^2READY ^7to use^0')
        ScriptScriptClient()
    else
        _print('[^1' .. _GetCurrentResourceName() .. '^7] client ^1Unverified^7 (no authorization from server)^0')
    end
end)


function ScriptScriptClient()
    print('clientload')

end