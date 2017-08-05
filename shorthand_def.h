#ifdef DEFINE_SHORTHAND
#define TD TRACE_DESC
#define TF TRACE_FILE
#define TI TRACE_IPC
#define TN TRACE_NETWORK
#define TP TRACE_PROCESS
#define TS TRACE_SIGNAL
#define TM TRACE_MEMORY
#define TST TRACE_STAT
#define TLST TRACE_LSTAT
#define TFST TRACE_FSTAT
#define TSTA TRACE_STAT_LIKE
#define TSF TRACE_STATFS
#define TFSF TRACE_FSTATFS
#define TSFA TRACE_STATFS_LIKE
#define NF SYSCALL_NEVER_FAILS
#define MA MAX_ARGS
#define SI STACKTRACE_INVALIDATE_CACHE
#define SE STACKTRACE_CAPTURE_ON_ENTER
#define CST COMPAT_SYSCALL_TYPES
#else
#undef SEN
#undef TD
#undef TF
#undef TI
#undef TN
#undef TP
#undef TS
#undef TM
#undef TST
#undef TLST
#undef TFST
#undef TSTA
#undef TSF
#undef TFSF
#undef TSFA
#undef NF
#undef MA
#undef SI
#undef SE
#undef CST
#endif
