/*
 * Should only be included from strace.c, so no include guards.
 */

#include <lualib.h>
#include <lauxlib.h>

#define L script_L

static struct tcb *
func_next_sc(void)
{
	static struct timeval tv = {};
	static bool first = true;

#define MAYBE_RESTART(res, sig)						\
	do {								\
		if ((res) >= 0 && ptrace_restart(			\
		    PTRACE_SYSCALL, current_tcp, sig) < 0) {		\
			/* ptrace_restart emitted error message */	\
			exit_code = 1;					\
			goto term;					\
		}							\
	} while (0)

	if (!first) {
		if (!current_tcp)
			return NULL;

		unsigned int sig = 0;
		int res;
		if (entering(current_tcp)) {
			res = syscall_entering_trace(current_tcp, &sig);
			syscall_entering_finish(current_tcp, res);
		} else {
			res = syscall_exiting_trace(current_tcp, tv, 1);
			syscall_exiting_finish(current_tcp);
		}
		MAYBE_RESTART(res, sig);
	}
	first = false;

	while (1) {
		int status;
		siginfo_t si;
		enum trace_event ret = next_event(&status, &si);
		if (ret == TE_SYSCALL_STOP) {
			unsigned int sig = 0;
			int res;
			if (entering(current_tcp)) {
				res = syscall_entering_decode(current_tcp);
				switch (res) {
				case 0:
					break;
				case 1:
					if (!current_tcp->qual_flg)
						filter_syscall(current_tcp);
					if (current_tcp->qual_flg & QUAL_HOOK_ENTRY)
						return current_tcp;
					res = syscall_entering_trace(current_tcp, &sig);
					/* fall through */
				default:
					syscall_entering_finish(current_tcp, res);
				}
			} else {
				res = syscall_exiting_decode(current_tcp, &tv);
				switch (res) {
				case 0:
					break;
				case 1:
					if (current_tcp->qual_flg & QUAL_HOOK_EXIT)
						return current_tcp;
					/* fall through */
				default:
					res = syscall_exiting_trace(current_tcp, tv, res);
				}
				syscall_exiting_finish(current_tcp);
			}
			MAYBE_RESTART(res, sig);
		} else {
			if (!dispatch_event(ret, &status, &si))
				goto term;
		}
	}
#undef MAYBE_RESTART
term:
	current_tcp = NULL;
	return NULL;
}

static bool
func_monitor(unsigned int scno, unsigned int pers, bool entry_hook,
	     bool exit_hook)
{
	if (pers >= SUPPORTED_PERSONALITIES)
		return false;
	set_hook_qual(scno, pers, entry_hook, exit_hook);
	return true;
}

static void
prepare_ad_hoc_inject(void)
{
	struct inject_opts *opts = current_tcp->ad_hoc_inject_opts;
	if (!opts) {
		opts = current_tcp->ad_hoc_inject_opts = xmalloc(sizeof(*opts));
		opts->first = 1;
		opts->step = 1;
	}
	if (!(current_tcp->flags & TCB_AD_HOC_INJECT)) {
		opts->signo = 0;
		opts->rval = INJECT_OPTS_RVAL_DEFAULT;
		current_tcp->qual_flg |= QUAL_INJECT;
		current_tcp->flags |= TCB_AD_HOC_INJECT;
	}
}

static bool
func_inject_signo(int signo)
{
	if (!current_tcp || exiting(current_tcp))
		/* Too late! */
		return false;
	if (signo <= 0 || signo > SIGRTMAX)
		return false;
	prepare_ad_hoc_inject();
	current_tcp->ad_hoc_inject_opts->signo = signo;
	return true;
}

static bool
func_inject_retval(int retval)
{
	if (!current_tcp || exiting(current_tcp))
		/* Too late! */
		return false;
	if (retval < -MAX_ERRNO_VALUE)
		return false;
	prepare_ad_hoc_inject();
	current_tcp->ad_hoc_inject_opts->rval = retval;
	return true;
}

static int
func_umove(kernel_ulong_t addr, size_t len, void *laddr)
{
	return current_tcp ? umoven(current_tcp, addr, len, laddr) : -1;
}

static int
func_umove_str(kernel_ulong_t addr, size_t len, char *laddr)
{
	return current_tcp ? umovestr(current_tcp, addr, len, laddr) : -1;
}

static bool
func_path_match(const char **set, size_t nset)
{
	if (!current_tcp)
		return false;
	struct path_set s = {set, nset};
	return pathtrace_match_set(current_tcp, &s);
}

static const char *
get_lua_msg(void)
{
	const char *msg = lua_tostring(L, -1);
	return msg ? msg : "(error object can't be converted to string)";
}

static void
assert_lua_impl(int ret, const char *expr, const char *file, int line)
{
	if (ret == 0)
		return;
	error_msg_and_die("assert_lua(%s) failed at %s:%d: %s", expr, file,
		line, get_lua_msg());
}

#define assert_lua(expr) assert_lua_impl(expr, #expr, __FILE__, __LINE__)

static void
check_lua(int ret)
{
	if (ret == 0)
		return;
	error_msg_and_die("lua: %s", get_lua_msg());
}

#ifdef LUA_FFILIBNAME
# define FFILIBNAME LUA_FFILIBNAME
#else
/* non-LuaJIT */
# define FFILIBNAME "ffi"
#endif

#ifdef LUA_BITLIBNAME
# define BITLIBNAME LUA_BITLIBNAME
#else
/* Lua <= 5.1 (non-LuaJIT) */
# define BITLIBNAME "bit"
#endif

static void
init_luajit(const char *scriptfile)
{
	if (L)
		/* already initialized? */
		error_msg_and_help("multiple -l arguments");

	if (!(L = luaL_newstate()))
		error_msg_and_die("luaL_newstate failed (out of memory?)");

	luaL_openlibs(L);

	lua_getglobal(L, "require"); /* L: require */
	lua_pushstring(L, FFILIBNAME); /* L: require str */
	assert_lua(lua_pcall(L, 1, 1, 0)); /* L: ffi */
	lua_getfield(L, -1, "cdef"); /* L: ffi cdef */
	luaL_Buffer b;
	luaL_buffinit(L, &b); /* L: ffi cdef ? */
	{
		char buf[128];
		snprintf(buf, sizeof(buf),
			"typedef int%d_t kernel_long_t;"
			"typedef uint%d_t kernel_ulong_t;",
			(int) sizeof(kernel_long_t) * 8,
			(int) sizeof(kernel_ulong_t) * 8);
		luaL_addstring(&b, buf); /* L: ffi cdef ? */
	}
	const char *defs =
#define FFI_CDEF
#include "sysent.h"
#include "defs_shared.h"
#undef FFI_CDEF
	;
	luaL_addstring(&b, defs); /* L: ffi cdef ? */
	luaL_pushresult(&b); /* L: ffi cdef str */
	assert_lua(lua_pcall(L, 1, 0, 0)); /* L: ffi */

	lua_newtable(L); /* L: ffi strace */
	lua_newtable(L); /* L: ffi strace C */

	lua_getfield(L, 1, "cast"); /* L: ffi strace C cast */
	lua_remove(L, 1); /* L: strace C cast */

#define EXPOSE_FUNC(rettype, ptr, name, ...)				\
	do {								\
		rettype (*fptr_)(__VA_ARGS__) = ptr;			\
		lua_pushvalue(L, -1); /* L: strace C cast cast */	\
		lua_pushstring(L, #rettype " (*)(" #__VA_ARGS__ ")");	\
		/* L: strace C cast cast str */				\
		lua_pushlightuserdata(L, * (void **) (&fptr_));		\
		/* L: strace C cast cast str ptr */			\
		assert_lua(lua_pcall(L, 2, 1, 0));			\
		/* L: strace C cast value */				\
		lua_setfield(L, -3, name); /* L: strace C cast */	\
	} while (0)

	EXPOSE_FUNC(bool, func_monitor, "monitor",
		unsigned int, unsigned int, bool, bool);
	EXPOSE_FUNC(void, set_hook_qual_all, "monitor_all",
		bool, bool);
	EXPOSE_FUNC(struct tcb *, func_next_sc, "next_sc",
		void);
	EXPOSE_FUNC(bool, func_inject_signo, "inject_signo",
		int);
	EXPOSE_FUNC(bool, func_inject_retval, "inject_retval",
		int);
	EXPOSE_FUNC(int, func_umove, "umove",
		kernel_ulong_t, size_t, void *);
	EXPOSE_FUNC(int, func_umove_str, "umove_str",
		kernel_ulong_t, size_t, char *);
	EXPOSE_FUNC(bool, func_path_match, "path_match",
		const char **, size_t);

#undef EXPOSE_FUNC

#define EXPOSE(type, ptr, name)						\
	do {								\
		/* Get a compilation error/warning on type mismatch */	\
		type tmp_ = ptr;					\
		(void) tmp_;						\
		lua_pushvalue(L, -1); /* L: strace C cast cast */	\
		lua_pushstring(L, #type);				\
		/* L: strace C cast cast str */				\
		lua_pushlightuserdata(L, (void *) ptr);			\
		/* L: strace C cast cast str ptr */			\
		assert_lua(lua_pcall(L, 2, 1, 0));			\
		/* L: strace C cast value */				\
		lua_setfield(L, -3, name); /* L: strace C cast */	\
	} while (0)

	EXPOSE(const struct_sysent *const *, sysent_vec, "sysent_vec");
	EXPOSE(const char *const **, errnoent_vec, "errnoent_vec");
	EXPOSE(const char *const **, signalent_vec, "signalent_vec");
	EXPOSE(const struct_ioctlent *const *, ioctlent_vec, "ioctlent_vec");

	EXPOSE(const unsigned int *, nsyscall_vec, /*(!)*/ "nsysent_vec");
	EXPOSE(const unsigned int *, nerrnoent_vec, "nerrnoent_vec");
	EXPOSE(const unsigned int *, nsignalent_vec, "nsignalent_vec");
	EXPOSE(const unsigned int *, nioctlent_vec, "nioctlent_vec");

	EXPOSE(const struct syscall_class *, syscall_classes,
		"syscall_classes");

#if SUPPORTED_PERSONALITIES == 1
	static const char *const personality_names[] = {"default"};
#endif
	EXPOSE(const char *const *, personality_names, "pers_names");
	EXPOSE(const int *, personality_wordsize, "pers_wordsize");
	EXPOSE(const int *, personality_klongsize, "pers_klongsize");

#undef EXPOSE

	lua_pop(L, 1); /* L: strace C */
	lua_setfield(L, -2, "C"); /* L: strace */

	lua_pushinteger(L, SUPPORTED_PERSONALITIES); /* L: strace int */
	lua_setfield(L, -2, "npersonalities"); /* L: strace */

	lua_pushinteger(L, MAX_ARGS); /* L: strace int */
	lua_setfield(L, -2, "max_args"); /* L: strace */

	lua_pushinteger(L, PATH_MAX); /* L: strace int */
	lua_setfield(L, -2, "path_max"); /* L: strace */

	lua_setglobal(L, "strace"); /* L: - */

	const char *code =
#include "luajit_lib.h"
	;
	assert_lua(luaL_loadstring(L, code)); /* L: chunk */

	lua_newtable(L); /* L: chunk table */

	lua_pushstring(L, FFILIBNAME); /* L: chunk table str */
	lua_setfield(L, -2, "ffilibname"); /* L: chunk table */
	lua_pushstring(L, BITLIBNAME); /* L: chunk table str */
	lua_setfield(L, -2, "bitlibname"); /* L: chunk table */
	lua_pushinteger(L, TCB_INSYSCALL); /* L: chunk table int */
	lua_setfield(L, -2, "tcb_insyscall"); /* L: chunk table */
	lua_pushinteger(L, QUAL_TRACE); /* L: chunk table int */
	lua_setfield(L, -2, "qual_trace"); /* L: chunk table */
	lua_pushinteger(L, QUAL_ABBREV); /* L: chunk table int */
	lua_setfield(L, -2, "qual_abbrev"); /* L: chunk table */
	lua_pushinteger(L, QUAL_VERBOSE); /* L: chunk table int */
	lua_setfield(L, -2, "qual_verbose"); /* L: chunk table */
	lua_pushinteger(L, QUAL_RAW); /* L: chunk table int */
	lua_setfield(L, -2, "qual_raw"); /* L: chunk table */

	assert_lua(lua_pcall(L, 1, 1, 0)); /* L: func */

	check_lua(luaL_loadfile(L, scriptfile)); /* L: func chunk */
}

static void ATTRIBUTE_NORETURN
run_luajit(void)
{
	/* L: func chunk */
	check_lua(lua_pcall(L, 0, 0, 0)); /* L: func */
	check_lua(lua_pcall(L, 0, 0, 0)); /* L: - */
	terminate();
}

#undef FFILIBNAME
#undef BITLIBNAME
#undef assert_lua
#undef L
