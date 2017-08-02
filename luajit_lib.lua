-- This "chunk" of code is loaded and run before the script is.
--
-- To quote https://www.lua.org/manual/5.1/manual.html#2.4.1,
-- "Lua handles a chunk as the body of an anonymous function with a variable
--  number of arguments (see §2.5.9). As such, chunks can define local
--  variables, receive arguments, and return values."
--
-- Thanks to Lua's support for closures, all the local variables defined here
-- will not leak to another chunks (i.e., the script), but all the functions
-- defined here can still access them.
--
-- strace calls this chunk with a single argument: a table with data that should
-- not be exposed to the script, but is needed for some API functions defined
-- here.
--
-- strace expects this chunk to return another function that will be run after
-- the script returns.
--
-- Arguments passed to this chunk are accessible through the "..." vararg
-- expression. The following line uses Lua's "adjust" assignment semantics to
-- assign the first argument to a local variable "priv".
local priv = ...

local ffi = require(priv.ffilibname)
ffi.cdef[[
int strcmp(const char *, const char *);
]]
local bit = require(priv.bitlibname)

local entry_cbs, exit_cbs, at_exit_cb = {}, {}, nil
for p = 0, strace.npersonalities - 1 do
	entry_cbs[p] = {}
	exit_cbs[p] = {}
end

local function chain(f, g)
	if not f then
		return g
	end
	return function(...)
		f(...)
		g(...)
	end
end

local function register_hook(scno, pers, on_entry, on_exit, cb)
	assert(not not strace.C.monitor(scno, pers, on_entry, on_exit))
	scno, pers = tonumber(scno), tonumber(pers)
	if on_entry then
		entry_cbs[pers][scno] = chain(entry_cbs[pers][scno], cb)
	end
	if on_exit then
		exit_cbs[pers][scno] = chain(exit_cbs[pers][scno], cb)
	end
end

-- Convert a cdata C string or a Lua string to a Lua string.
local function mkstring(s)
	return type(s) == 'string' and s or ffi.string(s)
end

local function parse_pers_spec(pers_spec)
	return tonumber(pers_spec) or tonumber(pers_spec.currpers)
end

function strace.entering(tcp)
	return bit.band(tcp.flags, priv.tcb_insyscall) == 0
end

function strace.exiting(tcp)
	return bit.band(tcp.flags, priv.tcb_insyscall) ~= 0
end

local function alter_trace_opt(flagbit, tcp, ...)
	if strace.exiting(tcp) then
		return false
	end
	-- i.e., if ... is empty, or the first element of ... is true
	if select('#', ...) == 0 or select(1, ...) then
		tcp.qual_flg = bit.bor(tcp.qual_flg, flagbit)
	else
		tcp.qual_flg = bit.band(tcp.qual_flg, bit.bnot(flagbit))
	end
	return true
end
for funcname, flagbit in pairs{
	trace	= priv.qual_trace,
	abbrev	= priv.qual_abbrev,
	verbose	= priv.qual_verbose,
	raw	= priv.qual_raw,
} do
	strace[funcname] = function(tcp, ...)
		return alter_trace_opt(flagbit, tcp, ...)
	end
end

function strace.ptr_to_kulong(ptr)
	return ffi.cast('kernel_ulong_t', ffi.cast('unsigned long', ptr))
end

function strace.at_exit(f)
	at_exit_cb = chain(at_exit_cb, f)
end

function strace.get_err_name(err, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	if err < 0 or err > strace.C.nerrnoent_vec[pers] then
		return nil
	end
	local s = strace.C.errnoent_vec[pers][err]
	return s ~= nil and ffi.string(s) or nil
end

function strace.get_sc_name(scno, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	if scno < 0 or scno >= strace.C.nsysent_vec[pers] then
		return nil
	end
	local s = strace.C.sysent_vec[pers][scno].sys_name
	return s ~= nil and ffi.string(s) or nil
end

function strace.get_ioctl_name(code, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	-- we could have provided a definition for stdlib's bsearch() and used
	-- it, but LuaJIT's FFI manual says generated callbacks are a limited
	-- resource and also slow. So implement binary search ourselves.
	local lb, rb = ffi.cast('unsigned int', 0), strace.C.nioctlent_vec[pers]
	if rb == 0 then
		return nil
	end
	local arr = strace.C.ioctlent_vec[pers]
	while rb - lb > 1 do
		local mid = lb + (rb - lb) / 2
		if arr[mid].code <= code then
			lb = mid
		else
			rb = mid
		end
	end
	return arr[lb].code == code and ffi.string(arr[lb].symbol) or nil
end

function strace.get_scno(scname, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	local cstr = ffi.cast('const char *', scname)
	for i = 0, tonumber(strace.C.nsysent_vec[pers]) - 1 do
		local s = strace.C.sysent_vec[pers][i].sys_name
		if s ~= nil and ffi.C.strcmp(s, cstr) == 0 then
			return i
		end
	end
	return nil
end

function strace.get_signo(signame, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	local cstr = ffi.cast('const char *', signame)
	for i = 0, tonumber(strace.C.nsignalent_vec[pers]) - 1 do
		local s = strace.C.signalent_vec[pers][i]
		if s ~= nil and ffi.C.strcmp(s, cstr) == 0 then
			return i
		end
	end
	return nil
end

function strace.get_errno(errname, pers_spec)
	local pers = parse_pers_spec(pers_spec)
	local cstr = ffi.cast('const char *', errname)
	for i = 0, tonumber(strace.C.nerrnoent_vec[pers]) - 1 do
		local s = strace.C.errnoent_vec[pers][i]
		if s ~= nil and ffi.C.strcmp(s, cstr) == 0 then
			return i
		end
	end
	return nil
end

function strace.inject_signal(tcp, sig)
	local signo = sig
	if type(sig) == 'string' or type(sig) == 'cdata' then
		signo = strace.get_signo(sig, tcp)
		if not signo then
			return false
		end
	end
	return not not strace.C.inject_signo(signo)
end

function strace.inject_error(tcp, err)
	local errno = err
	if type(err) == 'string' or type(err) == 'cdata' then
		errno = strace.get_errno(err, tcp)
		if not errno then
			return false
		end
	end
	return errno > 0 and not not strace.C.inject_retval(-errno)
end

local ptr_size = ffi.sizeof('void *')

function strace.read_obj(addr, ct, ...)
	local obj = ffi.new(ct, ...)
	local n = ffi.sizeof(obj)
	-- work around FFI pointer semantics
	if n == ptr_size then
		-- it may be a pointer, and it is cheap to create another copy
		local is_ok, ret = pcall(function()
			local t = ffi.typeof(obj)
			local arr = ffi.typeof('$ [1]', t)()
			return strace.C.umove(addr, n, arr) == 0 and t(arr[0])
				or nil
		end)
		if is_ok then
			return ret
		end
	end
	return strace.C.umove(addr, n, obj) == 0 and obj or nil
end

function strace.read_str(addr, maxsz, bufsz)
	-- convert it to Lua number to prevent underflows
	maxsz = tonumber(maxsz or 4 * 1024 * 1024)
	bufsz = bufsz or 1024
	local t = {}
	local buf = ffi.new('char [?]', bufsz)
	while true do
		local r = strace.C.umove_str(addr, bufsz, buf)
		if r < 0 then
			return nil, 'readerr'
		elseif r == 0 then
			maxsz = maxsz - bufsz
			if maxsz < 0 then
				return nil, 'toolong'
			end
			t[#t + 1] = ffi.string(buf, bufsz)
			addr = addr + bufsz
		else
			local s = ffi.string(buf)
			if #s > maxsz then
				return nil, 'toolong'
			end
			return table.concat(t) .. s
		end
	end
end

function strace.read_path(addr)
	return strace.read_str(addr, strace.path_max, strace.path_max + 1)
end

local function parse_when(when)
	if type(when) == 'table' then
		return unpack(when)
	elseif when == 'entering' then
		return true, false
	elseif when == 'exiting' then
		return false, true
	elseif when == 'both' then
		return true, true
	else
		error('unknown "when" value')
	end
end

local function reduce_or(f, args, ...)
	local ret = false
	for _, arg in ipairs(args) do
		if f(arg, ...) then
			ret = true
		end
	end
	return ret
end

function strace.hook(scname, when, cb)
	local on_entry, on_exit = parse_when(when)
	if type(scname) == 'table' then
		return reduce_or(strace.hook, scname, {on_entry, on_exit}, cb)
	end
	local found = false
	for p = 0, strace.npersonalities - 1 do
		local scno = strace.get_scno(scname, p)
		if scno then
			register_hook(scno, p, on_entry, on_exit, cb)
			found = true
		end
	end
	return found
end

function strace.hook_class(clsname, when, cb)
	local on_entry, on_exit = parse_when(when)
	if type(clsname) == 'table' then
		return reduce_or(strace.hook_class, clsname,
			{on_entry, on_exit}, cb)
	end
	local cstr = ffi.cast('const char *', clsname)
	local flag = nil
	local ptr = strace.C.syscall_classes
	while ptr.name ~= nil do
		if ffi.C.strcmp(ptr.name, cstr) == 0 then
			flag = ptr.value
			break
		end
		ptr = ptr + 1
	end
	if not flag then
		return false
	end
	for p = 0, strace.npersonalities - 1 do
		for i = 0, tonumber(strace.C.nsysent_vec[p]) - 1 do
			if bit.band(strace.C.sysent_vec[p][i].sys_flags, flag)
			   ~= 0
			then
				register_hook(i, p, on_entry, on_exit, cb)
			end
		end
	end
	return true
end

function strace.hook_scno(scno, when, cb, pers_spec)
	local on_entry, on_exit = parse_when(when)
	local pers = parse_pers_spec(pers_spec)
	if type(scno) == 'table' then
		return reduce_or(strace.hook_scno, scno, {on_entry, on_exit},
			cb, pers)
	end
	register_hook(scno, pers, on_entry, on_exit, cb)
end

function strace.path_match(set)
	if type(set) ~= 'table' then
		set = {set}
	end
	local nset = #set
	return not not strace.C.path_match(
		ffi.new('const char *[?]', nset, set), nset)
end

function print(...)
	local sep = ''
	for i = 1, select('#', ...) do
		io.stderr:write(sep .. tostring(select(i, ...)))
		sep = '\t'
	end
	io.stderr:write('\n')
end

return function()
	while true do
		local tcp = strace.C.next_sc()
		if tcp == nil then
			break
		end
		local cb = (strace.entering(tcp) and entry_cbs or exit_cbs)
			[tonumber(tcp.currpers)][tonumber(tcp.scno)]
		if cb then
			cb(tcp)
		end
	end
	if at_exit_cb then
		at_exit_cb()
	end
end
