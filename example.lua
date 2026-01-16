local ffi = require "ffi";

local libc = ffi.C;
ffi.cdef [[
	typedef int64_t off_t;
	typedef int ev_code_t;

	void free(void *ptr);
	int printf(const char *fmt, ...);
]];

local libev = ffi.load "./bin/libev.so";
ffi.cdef [[
#line 13

typedef struct ev *ev_t;

// Used to deploy a sync workload in an ev-managed thread
typedef int (*ev_worker_t)(void *pargs);

typedef struct ev_fd *ev_fd_t;
typedef struct ev_socket *ev_socket_t;
typedef struct ev_dir *ev_dir_t;

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
} ev_open_flags_t;

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

// Returns a reference to the stdin FD
ev_fd_t ev_stdin(ev_t ev);
// Returns a reference to the stdout FD
ev_fd_t ev_stdout(ev_t ev);
// Returns a reference to the stderr FD
ev_fd_t ev_stderr(ev_t ev);

// These are the I/O wrapper functions - they will return 0 on success and a negative errno code on error
// All the other arguments are self-explanatory. All of these functions return their results in a pointer, provided by the callee

// Exceptions to the model are the ev_close and ev_closedir functions, which are synchronous - this makes them fit to be called in a GC

// Equivalent to posix's open
ev_code_t ev_open(ev_t ev, void *udata, ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode);
// Equivalent to posix's pread
ev_code_t ev_read(ev_t ev, void *udata, ev_fd_t fd, const char *buff, size_t *n, size_t offset);
// Equivalent to posix's pwrite
ev_code_t ev_write(ev_t ev, void *udata, ev_fd_t fd, char *buff, size_t *n, size_t offset);
// Equivalent to posix's stat
ev_code_t ev_stat(ev_t ev, void *udata, ev_fd_t fd, ev_stat_t *buff);
// Equivalent to posix's fstat
ev_code_t ev_fstat(ev_t ev, void *udata, ev_fd_t fd, ev_stat_t *buff);
// Unlike all other functions, close will complete synchronously, and will never error out
// Equivalent to posix's close
void ev_close(ev_t ev, ev_fd_t fd);

// Equivalent to posix's mkdir
ev_code_t ev_mkdir(ev_t ev, void *udata, const char *path, int mode);
// Equivalent to posix's opendir
ev_code_t ev_opendir(ev_t ev, void *udata, ev_dir_t *pres, const char *path);
// Equivalent to posix's readdir
ev_code_t ev_readdir(ev_t ev, void *udata, ev_dir_t fd, char **pname);
// Equivalent to posix's closedir
void ev_closedir(ev_t ev, ev_dir_t fd);

// Equivalent to socket() + bind()
ev_code_t ev_bind(ev_t ev, void *udata, ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);
// Equivalent to socket() + connect()
ev_code_t ev_connect(ev_t ev, void *udata, ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);
// Equivalent to posix's accept
ev_code_t ev_accept(ev_t ev, void *udata, ev_socket_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_socket_t server);
// Equivalent to posix's recv
ev_code_t ev_recv(ev_t ev, void *udata, ev_socket_t sock, char *buff, size_t *pn);
// Equivalent to posix's send
ev_code_t ev_send(ev_t ev, void *udata, ev_socket_t sock, char *buff, size_t *pn);
// Equivalent to posix's close (but for sockets)
void ev_closesock(ev_t ev, ev_socket_t sock);

// Equivalent to posix's getaddrinfo (with a few simplifications)
ev_code_t ev_getaddrinfo(ev_t ev, void *udata, ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags);
// Gets a malloc'd string, representing the requested path
ev_code_t ev_getpath(ev_t ev, void *udata, char **pres, ev_path_type_t type);
]];

local libev_dyn = ffi.load "./bin/libev-dyn.so";
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

function ev.open(cb, path, flags, mode)
	local pres = ffi.new "ev_fd_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_open, handle, pres, path, flags, assert(tonumber(mode, 8)));
end
function ev.close(fd)
	return libev.ev_close(loop, fd);
end
function ev.rawread(cb, fd, offset, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_read, handle, fd, ptr, pn, offset);
end
function ev.rawwrite(cb, fd, offset, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_write, handle, fd, ptr, pn, offset);
end
function ev.read(cb, fd, offset, n)
	local buff = ffi.new("char[?]", n);

	return ev.rawread(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, ffi.string(ptr, n));
	end, fd, offset, n, buff);
end
function ev.write(cb, fd, offset, str)
	local buff = ffi.new("char[?]", #str);
	ffi.copy(buff, str, #str);

	return ev.rawwrite(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, n);
	end, fd, offset, #str, buff);
end
function ev.stat(cb, fd)
	local pbuff = ffi.new "ev_stat_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pbuff[0]);
	end

	return call_wrap(libev.ev_stat, handle, fd, pbuff);
end

function ev.mkdir(cb, path, mode)
	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, true);
	end

	return call_wrap(libev.ev_mkdir, handle, path, assert(tonumber(mode or 777, 8)));
end
function ev.opendir(cb, path)
	local pres = ffi.new "ev_dir_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0]);
	end

	return call_wrap(libev.ev_opendir, handle, pres, path);
end
function ev.closedir(dir)
	libev.ev_closedir(loop, dir);
end
function ev.readdir(cb, dir)
	local pname = ffi.new "char*[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pname[0]);
	end

	return call_wrap(libev.ev_readdir, handle, dir, pname);
end

function ev.connect(cb, addr, port, type)
	local itype;
	local pres = ffi.new "ev_socket_t[1]";

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

	return call_wrap(libev.ev_connect, handle, pres, itype, parse_ip(addr), port);
end
function ev.bind(cb, addr, port, type)
	local itype;
	local pres = ffi.new "ev_socket_t[1]";

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

	return call_wrap(libev.ev_bind, handle, pres, parse_ip(addr), port, itype);
end
function ev.accept(cb, server)
	local pres = ffi.new "ev_socket_t[1]";
	local paddr = ffi.new "ev_addr_t[1]";
	local pport = ffi.new "uint16_t[1]";

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pres[0], paddr[0], pport[0]);
	end

	return call_wrap(libev.ev_accept, handle, pres, paddr, pport, server);
end
function ev.rawrecv(cb, sock, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_recv, handle, sock, ptr, pn);
end
function ev.rawsend(cb, sock, n, ptr)
	local pn = ffi.new("size_t[1]", n);

	local function handle(code)
		if code ~= 0 then return invoke(cb, nil, ffi.string(libev.ev_strerr(code)), code) end
		return invoke(cb, pn[0], ptr);
	end

	return call_wrap(libev.ev_send, handle, sock, ptr, pn);
end
function ev.recv(cb, sock, n)
	local buff = ffi.new("char[?]", n);

	return ev.rawrecv(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, ffi.string(ptr, n));
	end, sock, n, buff);
end
function ev.send(cb, sock, str)
	local buff = ffi.new("char[?]", #str);
	ffi.copy(buff, str, #str);

	return ev.rawsend(function (n, ptr)
		if not n then return invoke(cb, n, ptr) end
		return invoke(cb, n);
	end, sock, #str, buff);
end
function ev.closesock(dir)
	libev.ev_closesock(loop, dir);
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
function ev.mksig(func, str)
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

local function hnd(...)
	return ...;
end

local function syncify(func)
	return function (...)
		local ok, err = func(coroutine.running(), ...);
		if not ok then return nil, err end
		return hnd(coroutine.yield());
	end
end

local evs = {
	open = syncify(ev.open),
	rawread = syncify(ev.rawread),
	rawwrite = syncify(ev.rawwrite),
	read = syncify(ev.read),
	write = syncify(ev.write),
	stat = syncify(ev.stat),
	close = ev.close,

	mkdir = syncify(ev.mkdir),
	opendir = syncify(ev.opendir),
	readdir = syncify(ev.readdir),
	closedir = ev.closedir,

	connect = syncify(ev.connect),
	bind = syncify(ev.bind),
	accept = syncify(ev.accept),
	recv = syncify(ev.recv),
	send = syncify(ev.send),
	closesock = ev.closesock,

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
		res, err = evs.connect(data, port, "tcp");
		if res then return res end
	end

	return nil, err or "host unreachable";
end

local stderr = libev.ev_stderr(loop);

local function netcat(url)
	local sock = assert(open_tcp(url, 80));

	assert(evs.send(sock, "GET / HTTP/1.1\r\nHost: " .. url .. "\r\nUser-Agent: example/0.1\r\nConnection: close\r\n\r\n"));
	while true do
		local res = assert(evs.recv(sock, 100));
		if #res == 0 then break end

		-- io.stderr:write(res);
		assert(evs.write(stderr, 0, res));
	end
	evs.closesock(sock);
end

fork(netcat, "www.google.com");
fork(netcat, "www.topcheto.eu");
fork(netcat, "www.dir.bg");

-- fork(function ()
-- 	netcat "www.topcheto.eu";
-- 	netcat "www.google.com";
-- 	netcat "dir.bg";
-- end)

local sig_printf = assert(ev.mksig(libc.printf, "i*ii"));

fork(function ()
	sig_printf(coroutine.running(), ffi.new "int[1]", "A = %d, B = %d\n", ffi.new("int", 10), ffi.new("int", 5));
	coroutine.yield();
	sig_printf(coroutine.running(), ffi.new "int[1]", "Hello, world!\n", ffi.new("int", 10), ffi.new("int", 5));
	coroutine.yield();
end);

fork(function ()
	local base = monotime();

	for i = 1, 50 do
		sleep_until(base + i * .01);
		print("====================> MS " .. i * 10);
	end
end);

assert(run());
libev.ev_free(loop);
