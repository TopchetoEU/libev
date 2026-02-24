local ffi = require "ffi";

local libc = ffi.C;
ffi.cdef [[
	typedef int64_t off_t;
	typedef int ev_code_t;

	void *malloc(size_t n);
	void free(void *ptr);
	// int printf(const char *fmt, ...);
]];

if jit.os ~= "Windows" then
	ffi.cdef [[
		int printf(const char *fmt, ...);
	]];
end

local libev = ffi.load(jit.os == "Windows" and "./bin/Windows/libev.dll" or "./bin/Linux/libev.so");
ffi.cdef [[
#line 13


typedef struct ev *ev_t;

// Used to deploy a sync workload in an ev-managed thread
typedef int (*ev_worker_t)(void *pargs);

typedef struct ev_hnd *ev_handle_t;
typedef struct ev_server *ev_server_t;
typedef struct ev_dir *ev_dir_t;
typedef struct ev_proc *ev_proc_t;

typedef enum {
	// The file will be usable only for statting (by default allowed)
	EV_OPEN_STAT = 0,
	// Opens the file in read mode
	EV_OPEN_READ = 1,
	// Opens the file in write mode
	EV_OPEN_WRITE = 2,
	// Opens the file in append mode (implies WRITE)
	EV_OPEN_APPEND = 4,

	// Creates the file if it doesn't exist
	EV_OPEN_CREATE = 8,
	// Empties the contents of the file if it exists
	EV_OPEN_TRUNC = 16,
	// Opens the file in direct mode
	EV_OPEN_DIRECT = 32,
	// Keeps the file open after an exec() call
	// By default, all files, not marked with this, are closed
	EV_OPEN_SHARED = 64,
} ev_open_flags_t;

typedef enum {
	// Use parent's stdio handle (default)
	EV_SPAWN_STD_INHERIT,
	// Use file descriptor, stored in the ev_fd_t* argument
	EV_SPAWN_STD_DUP,
	// Create a dummy file descriptor (pipe), store it in the ev_fd_t* argument and use that for the stdio handle
	EV_SPAWN_STD_PIPE,
} ev_spawn_stdio_flags_t;

typedef enum {
	EV_PATH_HOME,
	EV_PATH_CONFIG,
	EV_PATH_DATA,
	EV_PATH_CACHE,
	EV_PATH_RUNTIME,
	EV_PATH_CWD,
} ev_path_type_t;

typedef enum {
	EV_ADDR_IPV4,
	EV_ADDR_IPV6,
	// TODO: bluetooth maybe?
} ev_addr_type_t;
typedef struct {
	ev_addr_type_t type;
	union {
		uint8_t v4[4];
		uint16_t v6[8];
	};
} ev_addr_t;

typedef struct {
	size_t n;
	ev_addr_t addr[];
} *ev_addrinfo_t;
typedef enum {
	// Resolves only ipv4 (if neither this nor EV_AI_IPV6 are specified, resolves both)
	EV_AI_IPV4 = 1,
	// Resolves only ipv6 (this is mutually-exclusive with IPV4, and this will override IPV4)
	EV_AI_IPV6 = 2,
	// If no IPV6 address was found, but an IPV4 address was, resolves as an ipv6 mapping of the ipv4 address
	EV_AI_IPV4_MAPPED = 4,
	// Resolves to a bindable address - mostly applicable when name is NULL (equivalent to AI_PASSIVE)
	EV_AI_BIND = 8,
	// Resolves only IP addresses - does not make DNS requests (equivalent to AI_NUMERICHOST)
	EV_AI_NODNS = 16,
} ev_addrinfo_flags_t;

typedef enum {
	EV_PROTO_TCP,
	EV_PROTO_UDP,
} ev_proto_t;

typedef enum {
	EV_STAT_REG,
	EV_STAT_DIR,
	EV_STAT_LINK,
	EV_STAT_SOCK,
	EV_STAT_FIFO,
	EV_STAT_CHAR,
	EV_STAT_BLK,
} ev_stat_type_t;

typedef struct {
	int64_t sec;
	uint32_t nsec;
} ev_time_t;

typedef struct {
	ev_stat_type_t type;
	uint32_t mode;
	uint32_t gid;
	uint32_t uid;

	ev_time_t atime, mtime, ctime;

	uint64_t size;
	uint32_t blksize;

	uint64_t inode;
	uint32_t links;
} ev_stat_t;

typedef enum {
	EV_POLL_OK,
	EV_POLL_EMPTY = -1,
	EV_POLL_TIMEOUT = -2,
} ev_poll_res_t;

// Gets the time, elapsed since the unix epoch (CLOCK_REALTIME)
int ev_realtime(ev_time_t *pres);
// Gets a reliably and monotonically ticking time, unaffected by the system time (CLOCK_MONOTONIC)
// You should use this instead of `ev_realtime` when dealing with ev_poll's timeouts, and in general,
// when you care about time offsets more than the actual current time, which is almost always the case
int ev_monotime(ev_time_t *pres);

// Adds the two times together
ev_time_t ev_timeadd(ev_time_t a, ev_time_t b);
// Subtracts the two times
ev_time_t ev_timesub(ev_time_t a, ev_time_t b);
// Converts the time to a millisecond count
int64_t ev_timems(ev_time_t time);

// Parses the string to an IP address (ipv4/6 auto-detected)
bool ev_parse_ip(const char *str, ev_addr_t *pres);
// Returns true if both addresses are equal
bool ev_cmpaddr(ev_addr_t a, ev_addr_t b);

// Converts the error code to a human-readable string
const char *ev_strerr(ev_code_t code);

// Creates an ev instance. Combines a queue and a thread pool
ev_t ev_init();
// Cancels all filesystem operations, waits for all worker threads to finish and frees all resources of the loop
// Safe(ish) to call in GCs
void ev_free(ev_t ev);

// Checks if ev still has pending operations
bool ev_busy(ev_t ev);

// Signals to ev that a task has begun. Used to track `ev_busy`
void ev_begin(ev_t ev);
// Pushes a result to the message queue
// NOTE: using the same udata twice is UB
ev_code_t ev_push(ev_t ev, void *udata, ev_code_t err);
// Calls worker with pargs in a ev-managed thread and returns a new ticket to it
// Internally, this is used as a fallback for ops, not supported by AIO
// sync - if true, will side-step the thread pool and will instead call the worker immediately
ev_code_t ev_exec(ev_t ev, void *udata, ev_worker_t worker, void *pargs, bool sync);

// Gets the next message in the message queue
// If the queue is empty:
//     If the loop is closed, returns EV_POLL_EMPTY and frees the loop
//     If block is false, returns EV_POLL_EMPTY
//     If block is true, blocks until a message is available and returns it
// If ptimeout is not NULL and is reached, EV_POLL_TIMEOUT is returned. ptimeout is relative to the monotonic clock
ev_poll_res_t ev_poll(ev_t ev, bool block, const ev_time_t *ptimeout, void **pudata, int *perr);

// Returns a reference to the stdin stream
ev_handle_t ev_stdin(ev_t ev);
// Returns a reference to the stdout stream
ev_handle_t ev_stdout(ev_t ev);
// Returns a reference to the stderr stream
ev_handle_t ev_stderr(ev_t ev);

// Equivalent to posix's read
ev_code_t ev_read(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn);
// Equivalent to posix's write
ev_code_t ev_write(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn);
// Unlike all other functions, close will complete synchronously, and will never error out
// Equivalent to posix's close
void ev_close(ev_t ev, ev_handle_t fd);

// These are the I/O wrapper functions - they will return 0 on success and a negative errno code on error
// All the other arguments are self-explanatory. All of these functions return their results in a pointer, provided by the callee

// Exceptions to the model are the ev_close and ev_closedir functions, which are synchronous - this makes them fit to be called in a GC

// Equivalent to posix's open
ev_code_t ev_file_open(ev_t ev, void *udata, ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode);
// Equivalent to posix's pread
ev_code_t ev_file_read(ev_t ev, void *udata, ev_handle_t fd, const char *buff, size_t *pn, size_t offset);
// Equivalent to posix's pwrite
ev_code_t ev_file_write(ev_t ev, void *udata, ev_handle_t fd, char *buff, size_t *pn, size_t offset);
// Equivalent to posix's sync
ev_code_t ev_file_sync(ev_t ev, void *udata, ev_handle_t fd);
// Equivalent to posix's stat
ev_code_t ev_file_stat(ev_t ev, void *udata, ev_handle_t fd, ev_stat_t *buff);

// Equivalent to posix's mkdir
ev_code_t ev_dir_create(ev_t ev, void *udata, const char *path, int mode);
// Equivalent to posix's opendir
ev_code_t ev_dir_open(ev_t ev, void *udata, ev_dir_t *pres, const char *path);
// Equivalent to posix's readdir
ev_code_t ev_dir_next(ev_t ev, void *udata, ev_dir_t fd, char **pname);
// Equivalent to posix's closedir
void ev_dir_close(ev_t ev, ev_dir_t fd);

// Equivalent to socket() + bind()
ev_code_t ev_server_bind(ev_t ev, void *udata, ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n);
// Equivalent to posix's accept
ev_code_t ev_server_accept(ev_t ev, void *udata, ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server);
void ev_server_close(ev_t ev, ev_server_t server);

// Equivalent to socket() + connect()
ev_code_t ev_socket_connect(ev_t ev, void *udata, ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);

// Equivalent to posix's fork then exec
ev_code_t ev_proc_spawn(
	ev_t ev, void *udata, ev_proc_t *pres,
	const char **argv, const char **env,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_handle_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_handle_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_handle_t *perr
);
// Equivalent to posix's waitpid
// psig is set to the signal that terminated the child, or -1 if not terminated by a signal
// pcode is set to the exit code of the app, or -1 if child did not exit with a code
ev_code_t ev_proc_wait(ev_t ev, void *udata, ev_proc_t proc, int *psig, int *pcode);

// Equivalent to posix's getaddrinfo (with a few simplifications)
ev_code_t ev_getaddrinfo(ev_t ev, void *udata, ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags);
// Gets a malloc'd string, representing the requested path
ev_code_t ev_getpath(ev_t ev, void *udata, char **pres, ev_path_type_t type);
]];

local libev_dyn = ffi.load(jit.os == "Windows" and "./bin/Windows/libev-dyn.dll" or "./bin/Linux/libev-dyn.so");
ffi.cdef [[
// A simple wrapper around libffi, so that ev_exec can be used by dynamic languages

typedef struct ev_dyn_sig *ev_dyn_sig_t;
typedef struct ev_dyn_args *ev_dyn_args_t;

// Creates a signature, that can then be used in ev_dyn_args_t
// First type is the return type, the rest are the arguments, no variadic args allowed
// Return EINVAL if sig's syntax is invalid
//
// Types:
//     v -> void (may not be used as a standalone argument)
//     c -> char
//     is -> int
//     i -> int
//     il -> long int
//     ill -> long long int
//     f -> float
//     d -> double
//     dl -> long double
//     i8 -> int8_t
//     i16 -> int16_t
//     i32 -> int32_t
//     i64 -> int64_t
//     * -> a pointer
//     (...types) -> structure of the given types
//
// Example: struct { int a; int b; }* (int a, int b, my_ptr_t *c) -> (ii)ii*
ev_code_t ev_dyn_sig_new(void *func, const char *sig, ev_dyn_sig_t *pres);
// Releases all resources, used by this signature
// It goes without saying that this must be called after all callbacks, depending on these have begun execution
void ev_dyn_sig_free(ev_dyn_sig_t sig);

// Creates arguments for ev_dyn_cb. Freeing the structure is handled by ev_dyn_cb
// Returns NULL when out of memory (aka EV_ENOMEM is implied)
ev_dyn_args_t ev_dyn_args_new(ev_dyn_sig_t sig, void *pret, void **args);

// A callback, usable in ev_exec. Always will report EV_OK
// Must be passed a ev_dyn_args_t
//
// Example usage:
//     ev_dyn_sig_t sig;
//     ev_dyn_mksig(printf, "i*ii", &sig);
//
//     int res;
//
//     const char *fmt = "A = %d, B = %d\n";
//     int a = 10;
//     int b = 5;
//     ev_exec(ev_dyn_cb, ev_dyn_mkargs(sig, &res, (void[]) { &fmt, &a, &b }));
int ev_dyn_cb(void *pargs);
]];

local curr_tag = 0;
local tasks = {};
local handles = {};
local sleeps = {};

local loop = libev.ev_init();

local function realtime()
	local pres = ffi.new "ev_time_t[1]";
	assert(libev.ev_realtime(pres) == 0, "couldn't get realtime");
	return assert(tonumber(pres[0].sec)) + assert(tonumber(pres[0].nsec)) / 1000000000;
end
local function monotime()
	local pres = ffi.new "ev_time_t[1]";
	assert(libev.ev_monotime(pres) == 0, "couldn't get realtime");
	return assert(tonumber(pres[0].sec)) + assert(tonumber(pres[0].nsec)) / 1000000000;
end

local ev = {};

local function call_wrap(func, cb, ...)
	curr_tag = curr_tag + 1;
	local tag = curr_tag;
	local code = func(loop, ffi.cast("void*", tag), ...);
	if code ~= 0 then return nil, ffi.string(libev.ev_strerr(code)), code end
	handles[tag] = cb;
	return true;
end

local function parse_ip(str)
	local pres = ffi.new "ev_addr_t[1]";

	if not libev.ev_parse_ip(str, pres) then
		error "invalid IP";
	end

	return pres[0];
end

local function pinvoke(handle, ...)
	if type(handle) == "thread" then
		return coroutine.resume(handle, ...);
	elseif type(handle) == "function" then
		return pcall(handle, ...);
	elseif handle == nil then
		return true, "invalid handle";
	else
		return false, "invalid handle";
	end
end
local function invoke(handle, ...)
	local ok, err = pinvoke(handle, ...);
	if not ok then return error(err, 0) end
end

function ev.rawread(cb, sock, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_read, handle, sock, ptr, pn);
end
function ev.rawwrite(cb, sock, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_write, handle, sock, ptr, pn);
end
function ev.read(cb, sock, n)
	local buff = ffi.new("char[?]", n);

	return ev.rawread(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, ffi.string(ptr, n));
	end, sock, n, buff);
end
function ev.write(cb, sock, str)
	local buff = ffi.new("char[?]", #str);
	ffi.copy(buff, str, #str);

	return ev.rawwrite(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, n);
	end, sock, #str, buff);
end
function ev.close(fd)
	return libev.ev_close(loop, fd);
end

function ev.file_open(cb, path, flags, mode)
	local pres = ffi.new "ev_handle_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_file_open, handle, pres, path, flags, assert(tonumber(mode, 8)));
end
function ev.file_rawread(cb, fd, offset, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_file_read, handle, fd, ptr, pn, offset);
end
function ev.file_rawwrite(cb, fd, offset, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_file_write, handle, fd, ptr, pn, offset);
end
function ev.file_read(cb, fd, offset, n)
	local buff = ffi.new("char[?]", n);

	return ev.file_rawread(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, ffi.string(ptr, n));
	end, fd, offset, n, buff);
end
function ev.file_write(cb, fd, offset, str)
	local buff = ffi.new("char[?]", #str);
	ffi.copy(buff, str, #str);

	return ev.file_rawwrite(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, n);
	end, fd, offset, #str, buff);
end
function ev.file_stat(cb, fd)
	local pbuff = ffi.new "ev_stat_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pbuff[0]);
	end

	return call_wrap(libev.ev_file_stat, handle, fd, pbuff);
end

function ev.proc_spawn(cb, opts)
	local pres = ffi.new "ev_proc_t[1]";

	local function fix_stdfd(fd)
		if fd == "inherit" then
			return 0, nil;
		elseif fd == "pipe" then
			return 2, ffi.new "ev_handle_t[1]";
		else
			return 1, ffi.new("ev_handle_t[1]", fd);
		end
	end

	local in_flags, pin = fix_stdfd(opts.stdin);
	local out_flags, pout = fix_stdfd(opts.stdout);
	local err_flags, perr = fix_stdfd(opts.stderr);

	local function stddup(str)
		local res = libc.malloc(#str + 1);
		ffi.copy(res, str);
		return res;
	end

	local argv = ffi.cast("const char**", libc.malloc(ffi.sizeof("const char**", #opts.argv + 1)));
	for i = 1, #opts.argv do
		argv[i - 1] = stddup(opts.argv[i]);
	end
	argv[#opts.argv] = nil;

	local env_key_n = 0;

	for _ in pairs(opts.env) do
		env_key_n = env_key_n + 1;
	end

	local env = ffi.cast("const char**", libc.malloc(ffi.sizeof("const char**", #opts.env + env_key_n + 1)));

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end

		local stdin, stdout, stderr;

		if in_flags == 2 and pin then stdin = pin[0] end
		if out_flags == 2 and pout then stdout = pout[0] end
		if err_flags == 2 and perr then stderr = perr[0] end

		return invoke(cb, pres[0], stdin, stdout, stderr);
	end

	for i = 1, #opts.env do
		env[i - 1] = stddup(opts.env[i][1] .. "=" .. opts.env[i][2]);
	end

	local i = 0;
	for k, v in pairs(opts.env) do
		env[#opts.env + i] = stddup(k .. v);
		i = i + 1;
	end

	env[#opts.env + env_key_n] = nil;

	return call_wrap(libev.ev_proc_spawn, handle, pres, argv, env, opts.cwd, in_flags, pin, out_flags, pout, err_flags, perr);
end
function ev.proc_wait(cb, proc)
	local pcode = ffi.new "int[1]";
	local psig = ffi.new "int[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, tonumber(pcode[0]), tonumber(psig[0]));
	end

	return call_wrap(libev.ev_proc_wait, handle, proc, pcode, psig);
end

function ev.dir_new(cb, path, mode)
	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, true);
	end

	return call_wrap(libev.ev_dir_new, handle, path, assert(tonumber(mode or 777, 8)));
end
function ev.dir_open(cb, path)
	local pres = ffi.new "ev_dir_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_dir_open, handle, pres, path);
end
function ev.dir_next(cb, dir)
	local pname = ffi.new "char*[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pname[0]);
	end

	return call_wrap(libev.ev_dir_next, handle, dir, pname);
end
function ev.dir_close(dir)
	libev.ev_dir_close(loop, dir);
end

function ev.socket_connect(cb, addr, port, type)
	local itype;
	local pres = ffi.new "ev_handle_t[1]";

	if type == "tcp" then
		itype = 0;
	elseif type == "udp" then
		itype = 1;
	else
		error "invalid type";
	end

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_socket_connect, handle, pres, itype, parse_ip(addr), port);
end
function ev.server_bind(cb, addr, port, type)
	local itype;
	local pres = ffi.new "ev_server_t[1]";

	if type == "tcp" then
		itype = 0;
	elseif type == "udp" then
		itype = 1;
	else
		error "invalid type";
	end

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_server_bind, handle, pres, parse_ip(addr), port, itype);
end
function ev.server_accept(cb, server)
	local pres = ffi.new "ev_handle_t[1]";
	local paddr = ffi.new "ev_addr_t[1]";
	local pport = ffi.new "uint16_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0], paddr[0], pport[0]);
	end

	return call_wrap(libev.ev_server_accept, handle, pres, paddr, pport, server);
end
function ev.server_close(dir)
	libev.ev_server_close(loop, dir);
end

function ev.getaddrinfo(cb, name, flags)
	local pres = ffi.new "ev_addrinfo_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end

		local res = {};

		for i = 1, tonumber(pres[0].n) do
			local addr = pres[0].addr[i - 1];

			if addr.type == 0 then
				table.insert(res, ("%d.%d.%d.%d"):format(addr.v4[0], addr.v4[1], addr.v4[2], addr.v4[3]));
			else
				table.insert(res, ("%x:%x:%x:%x:%x:%x:%x:%x"):format(
					addr.v6[0], addr.v6[1],
					addr.v6[2], addr.v6[3],
					addr.v6[4], addr.v6[5],
					addr.v6[6], addr.v6[7]
				));
			end
		end

		return invoke(cb, res);
	end

	return call_wrap(libev.ev_getaddrinfo, handle, pres, name, flags);
end
function ev.getpath(cb, type)
	local pres = ffi.new "char*[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		local res = ffi.string(pres[0]);
		libc.free(pres[0]);
		return invoke(cb, res);
	end

	return call_wrap(libev.ev_getpath, handle, pres, type);
end

--- @param str string
function ev.mksignature(func, str)
	local pres = ffi.new "ev_dyn_sig_t[1]";
	local code = libev_dyn.ev_dyn_sig_new(func, str, pres);
	if code ~= 0 then return nil, ffi.string(libev.ev_strerr(code)) end
	return function (cb, pret, ...)
		local args = ffi.new("void*[?]", select("#", ...) + 1);
		args[select("#", ...)] = nil;

		for i = 1, select("#", ...) do
			local arg = select(i, ...);
			if type(arg) == "string" then
				arg = ffi.cast("char*", arg);
			end

			local arg_type = ffi.typeof(arg);
			local slot = ffi.typeof("$[1]", arg_type)();
			slot[0] = ffi.cast(arg_type, arg);
			-- slot[0] = arg;
			args[i - 1] = slot;
		end

		local pargs = libev_dyn.ev_dyn_args_new(pres[0], pret, args);
		return call_wrap(libev.ev_exec, cb, libev_dyn.ev_dyn_cb, pargs, false);
	end
end

local function syncify(func)
	return function (...)
		local ok, err = func(coroutine.running(), ...);
		if not ok then return nil, err end
		return coroutine.yield();
	end
end

local evs = {
	read = syncify(ev.read),
	write = syncify(ev.write),
	close = ev.close,

	file_open = syncify(ev.file_open),
	file_rawread = syncify(ev.file_rawread),
	file_rawwrite = syncify(ev.file_rawwrite),
	file_read = syncify(ev.file_read),
	file_write = syncify(ev.file_write),
	file_stat = syncify(ev.file_stat),

	dir_new = syncify(ev.dir_new),
	dir_open = syncify(ev.dir_open),
	dir_read = syncify(ev.dir_next),
	dir_close = ev.dir_close,

	socket_connect = syncify(ev.socket_connect),
	server_bind = syncify(ev.server_bind),
	server_accept = syncify(ev.server_accept),
	server_close = ev.server_close,

	proc_spawn = syncify(ev.proc_spawn),
	proc_wait = syncify(ev.proc_wait),

	getaddrinfo = syncify(ev.getaddrinfo),
	getpath = syncify(ev.getpath),
};

local function run()
	while true do
		local curr = monotime();

		-- NOTE: this can be implemented as a sorted list, which would be MUCH faster for lots of concurrent sleeps, this is just the simplest logic
		for i = #sleeps, 1, -1 do
			if sleeps[i].time <= curr then
				table.insert(tasks, sleeps[i].task);
				table.remove(sleeps, i);
			end
		end

		while true do
			local task = table.remove(tasks, 1);
			if not task then break end

			local ok, err = pinvoke(task);
			if not ok then return nil, err end
		end

		local timeout;
		for i = #sleeps, 1, -1 do
			if not timeout or timeout > sleeps[i].time then
				timeout = sleeps[i].time;
			end
		end

		if not timeout and not libev.ev_busy(loop) then return true end

		local ptimeout = nil;
		if timeout then
			ptimeout = ffi.new "ev_time_t[1]";
			ptimeout[0].sec = timeout - timeout % 1;
			ptimeout[0].nsec = (timeout % 1) * 1000000000;
		end

		local pudata = ffi.new "void*[1]";
		local perr = ffi.new "int[1]";
		local code = assert(tonumber(libev.ev_poll(loop, true, ptimeout, pudata, perr)));
		if code == 0 then
			local ticket = assert(tonumber(ffi.cast("size_t", pudata[0])), "invalid ticket");
			local handle = handles[ticket];
			handles[ticket] = nil;

			local ok, err = pinvoke(handle, perr[0]);
			if not ok then return nil, err end
		end
	end
end

local function sleep_until(time)
	local cb = coroutine.running();
	table.insert(sleeps, { time = time, task = cb });

	return coroutine.yield();
end
local function sleep(secs)
	return sleep_until(secs + monotime());
end

--- @param func fun(...)
local function fork(func, ...)
	local thread = coroutine.create(function (...)
		local ok, err = xpcall(func, debug.traceback, ...);
		if not ok then error(err, 0) end
	end);

	local ok, err = coroutine.resume(thread, ...);
	if not ok then error(err, 0) end
end

local function interrupt()
	table.insert(tasks, (coroutine.running()));
	return coroutine.yield();
end

local function open_tcp(name, port)
	local err;
	for _, data in ipairs(assert(evs.getaddrinfo(name, 0))) do
		local res;
		res, err = evs.socket_connect(data, port, "tcp");
		if res then return res end
	end

	return nil, err or "host unreachable";
end

local stderr = libev.ev_stderr(loop);

local function netcat(url)
	local sock = assert(open_tcp(url, 80));

	assert(evs.write(sock, "GET / HTTP/1.1\r\nHost: " .. url .. "\r\nUser-Agent: example/0.1\r\nConnection: close\r\n\r\n"));
	while true do
		local res = assert(evs.read(sock, 100));
		if #res == 0 then break end

		-- io.stderr:write(res);
		assert(evs.write(stderr, res));
	end
	evs.close(sock);
end

fork(netcat, "www.google.com");
fork(netcat, "www.topcheto.eu");
fork(netcat, "www.dir.bg");


if jit.os ~= "Windows" then
	local sig_printf = assert(ev.mksig(libc.printf, "i*ii"));

	fork(function ()
		sig_printf(coroutine.running(), ffi.new "int[1]", "A = %d, B = %d\n", ffi.new("int", 10), ffi.new("int", 5));
		coroutine.yield();
		sig_printf(coroutine.running(), ffi.new "int[1]", "Hello, world!\n", ffi.new("int", 10), ffi.new("int", 5));
		coroutine.yield();
	end);
end

fork(function ()
	local base = monotime();

	for i = 1, 20 do
		sleep_until(base + i * .01);
		print("====================> MS " .. i * 10);
	end
end);

fork(function ()
	local proc, proc_in, proc_out = assert(evs.proc_spawn {
		stdin = "pipe",
		-- stdin = "inherit",
		stdout = "pipe",
		-- stdout = "inherit",
		stderr = "inherit",
		argv = ffi.os == "Windows" and { "./cat.exe", "-" } or { "/bin/sort" },
		env = {},
	});

	print(proc_in, proc_out)

	fork(function ()
		assert(evs.write(proc_in, "The quick brown fox jumped over the red dog\n"));
		assert(evs.write(proc_in, "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"));
		assert(evs.write(proc_in, "Integer consectetur mi a feugiat tempor.\n"));
		assert(evs.write(proc_in, "Cras tincidunt diam at libero lacinia, ac fringilla metus malesuada.\n"));
		evs.close(proc_in);
	end);

	fork(function ()
		while true do
			local buff = assert(evs.read(proc_out, 1024));
			if #buff == 0 then break end
			io.stderr:write(buff);
		end
		evs.close(proc_out);

		print("EXIT CODE", assert(evs.proc_wait(proc)));
	end);
end);

assert(run());
libev.ev_free(loop);
