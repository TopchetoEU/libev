// Due to how this project is structured, some functions are erroneously marked as "unused"
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ev/conf.h"
#include "ev.h"
#include "ev/errno.h"
#include "multithread.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef EV_USE_UNIX
	#include "./unix/core.c"
#elif defined EV_USE_WIN32
	#include "./win/core.c"
#else
	#error Either unix or windows must be enabled
#endif

#ifdef EV_USE_URING
	#include "./unix/uring.c"
#endif

typedef struct ev_msg {
	struct ev_msg *next;
	void *udata;
	int err;
} *ev_msg_t;

struct ev {
	size_t active_n;

	#ifdef EV_USE_MULTITHREAD
		ev_mutex_t lock;
		ev_cond_t has_msg_cond;
	#endif

	ev_msg_t next_msg;

	ev_fd_t in, out, err;

	#ifdef EV_USE_MULTITHREAD
		struct ev_pool_worker *next_worker;
	#endif

	#ifdef EV_USE_URING
		struct ev_uring uring[1];
	#endif
};

// ADDRESS UTILITY FUNCS

static bool ev_parse_ipv4(const char *str, ev_addr_t *pres) {
	ev_addr_t res;
	res.type = EV_ADDR_IPV4;

	const char *it = str;

	for (int i = 0; i < 4; i++) {
		uint64_t part = 0;

		if (!isdigit(*it)) return false;

		while (isdigit(*it)) {
			if (part > 100) return false;
			part = part * 10 + *it - '0';
			it++;
		}

		if (part > 255) return false;

		if (*it == '.') {
			if (i == 3) return false;
			it++;
		}
		if (*it == '\0' && i != 3) return false;

		res.v4[i] = part;
	}

	if (*it != '\0') return false;

	if (pres) *pres = res;
	return true;
}
static bool ev_parse_ipv6(const char *str, ev_addr_t *pres) {
	ev_addr_t res = { 0 };
	res.type = EV_ADDR_IPV6;

	const char *it = str;
	int zeroes_i = -1;
	int i = 0;

	if (it[0] == ':' && it[1] == ':') {
		it += 2;
		zeroes_i = 0;

		if (*it == '\0') {
			*pres = res;
			return true;
		}
	}

	for (i = 0; i < 8; i++) {
		if (!isxdigit(*it)) return false;

		for (int j = 0; j < 4; j++) {
			if (!isxdigit(*it)) break;

			res.v6[i] <<= 4;
			if (isdigit(*it)) res.v6[i] |= *it - '0';
			if (islower(*it)) res.v6[i] |= *it - 'a' + 10;
			if (isupper(*it)) res.v6[i] |= *it - 'A' + 10;
			it++;
		}

		if (*it == ':') {
			it++;
			continue;
		}

		if (it[0] == ':' && it[1] == ':') {
			if (zeroes_i != -1) return false;
			zeroes_i = i;
			it += 2;
		}

		if (*it == '\0') break;
	}

	if (*it != '\0') return false;

	if (zeroes_i > 0) {
		int trailing_n = i - zeroes_i;
		memmove(res.v6 + (16 - trailing_n), res.v6 + zeroes_i, sizeof *res.v6 * trailing_n);
	}

	if (pres) *pres = res;
	return true;
}

bool ev_parse_ip(const char *str, ev_addr_t *pres) {
	if (ev_parse_ipv4(str, pres)) return true;
	if (ev_parse_ipv6(str, pres)) return true;
	return false;
}
bool ev_cmpaddr(ev_addr_t a, ev_addr_t b) {
	if (a.type != b.type) return false;
	if (a.type == EV_ADDR_IPV4) {
		return !memcmp(a.v4, b.v4, sizeof a.v4);
	}
	else {
		return !memcmp(a.v6, b.v6, sizeof a.v6);
	}
}

// TIMESTAMP UTILITY FUNCS

ev_time_t ev_timeadd(ev_time_t a, ev_time_t b) {
	ev_time_t res = { .sec = a.sec + b.sec, .nsec = a.nsec + b.nsec };
	if (res.nsec > 1000000000) {
		res.nsec -= 1000000000;
		res.sec += 1;
	}
	return res;
}
ev_time_t ev_timesub(ev_time_t a, ev_time_t b) {
	if (a.nsec < b.nsec) {
		a.nsec += 1000000000;
		a.sec -= 1;
	}

	ev_time_t res = { .sec = a.sec - b.sec, .nsec = a.nsec - b.nsec };
	if (res.nsec > 1000000000) {
		res.sec += 1;
		res.nsec -= 1000000000;
	}

	return res;
}
int64_t ev_timems(ev_time_t time) {
	return time.sec * 1000 + (time.nsec + 999999) / 1000000;
}

// EV CORE FUNCS

static ev_code_t evi_push(ev_t ev, void *udata, ev_code_t err) {
	ev_msg_t msg = malloc(sizeof *msg);
	if (!msg) return EV_ENOMEM;

	msg->next = ev->next_msg;
	msg->udata = udata;
	msg->err = err;
	ev->next_msg = msg;

	#ifdef EV_USE_MULTITHREAD
		ev_cond_broadcast(ev->has_msg_cond);
	#endif

	return EV_OK;
}

#ifdef EV_USE_MULTITHREAD
	typedef struct ev_pool_worker {
		struct ev_pool_worker *next;
		ev_t ev;
		ev_cond_t cond;

		ev_thread_t thread;

		ev_worker_t worker;
		void *udata;
		void *args;

		bool kys;
	} *ev_pool_worker_t;
	typedef struct {
		ev_pool_worker_t worker;
		ev_t sync;
	} *ev_sync_args_t;

	static void evi_pool_worker_entry(void *pargs) {
		ev_pool_worker_t worker = (ev_pool_worker_t)pargs;
		ev_t ev = worker->ev;

		ev_mutex_lock(ev->lock);

		while (true) {
			while (worker->worker && !worker->kys) {
				void *udata = worker->udata;
				ev_worker_t cb = worker->worker;
				void *args = worker->args;
				worker->worker = NULL;
				worker->args = NULL;
				worker->udata = NULL;

				ev_mutex_unlock(ev->lock);
				ev_code_t code = cb(args);
				ev_mutex_lock(ev->lock);
				evi_push(ev, udata, code);
			}
			if (worker->kys) break;

			ev_cond_wait(worker->cond, ev->lock);
		}

		ev_mutex_unlock(ev->lock);
	}
#endif

const char *ev_strerr(ev_code_t code) {
	switch (code) {
		case EV_EPERM: return "operation not permitted";
		case EV_ENOENT: return "no such file or directory";
		case EV_ESRCH: return "no such process";
		case EV_EINTR: return "interrupted system call";
		case EV_EIO: return "i/o error";
		case EV_ENXIO: return "no such device or address";
		case EV_E2BIG: return "argument list too long";
		case EV_ENOEXEC: return "exec format error";
		case EV_EBADF: return "bad file descriptor";
		case EV_ECHILD: return "no child processes";
		case EV_EAGAIN: return "resource temporarily unavailable";
		case EV_ENOMEM: return "not enough memory";
		case EV_EACCES: return "permission denied";
		case EV_EFAULT: return "bad address in system call argument";
		case EV_EBUSY: return "resource busy or locked";
		case EV_EEXIST: return "file already exists";
		case EV_EXDEV: return "cross-device link not permitted";
		case EV_ENODEV: return "no such device";
		case EV_ENOTDIR: return "not a directory";
		case EV_EISDIR: return "illegal operation on a directory";
		case EV_EINVAL: return "invalid argument";
		case EV_ENFILE: return "file table overflow";
		case EV_EMFILE: return "too many open files";
		case EV_ENOTTY: return "inappropriate ioctl for device";
		case EV_ETXTBSY: return "text file is busy";
		case EV_EFBIG: return "file too large";
		case EV_ENOSPC: return "no space left on device";
		case EV_ESPIPE: return "invalid seek";
		case EV_EROFS: return "read-only file system";
		case EV_EMLINK: return "too many links";
		case EV_EPIPE: return "broken pipe";
		case EV_ERANGE: return "result too large";
		case EV_EDEADLK: return "resource deadlock avoided";
		case EV_ENAMETOOLONG: return "name too long";
		case EV_ENOLCK: return "no locks available";
		case EV_ENOSYS: return "function not implemented";
		case EV_ENOTEMPTY: return "directory not empty";
		case EV_ELOOP: return "too many symbolic links encountered";
		case EV_EUNATCH: return "protocol driver not attached";
		case EV_ENODATA: return "no data available";
		case EV_ENONET: return "machine is not on the network";
		case EV_ECOMM: return "communication error on send";
		case EV_EPROTO: return "protocol error";
		case EV_EOVERFLOW: return "value too large for defined data type";
		case EV_ENOTUNIQ: return "Name not unique on network";
		case EV_ELIBBAD: return "accessing a corrupted shared library";
		case EV_EILSEQ: return "illegal byte sequence";
		case EV_ENOTSOCK: return "socket operation on non-socket";
		case EV_EDESTADDRREQ: return "destination address required";
		case EV_EMSGSIZE: return "message too long";
		case EV_EPROTOTYPE: return "protocol wrong type for socket";
		case EV_ENOPROTOOPT: return "protocol not available";
		case EV_EPROTONOSUPPORT: return "protocol not supported";
		case EV_ESOCKTNOSUPPORT: return "socket type not supported";
		case EV_ENOTSUP: return "operation not supported on socket";
		case EV_EPFNOSUPPORT: return "operation not supported on socket";
		case EV_EAFNOSUPPORT: return "address family not supported";
		case EV_EADDRINUSE: return "address already in use";
		case EV_EADDRNOTAVAIL: return "address not available";
		case EV_ENETDOWN: return "network is down";
		case EV_ENETUNREACH: return "network is unreachable";
		case EV_ECONNABORTED: return "software caused connection abort";
		case EV_ECONNRESET: return "connection reset by peer";
		case EV_ENOBUFS: return "no buffer space available";
		case EV_EISCONN: return "socket is already connected";
		case EV_ENOTCONN: return "socket is not connected";
		case EV_ESHUTDOWN: return "cannot send after transport endpoint shutdown";
		case EV_ETIMEDOUT: return "connection timed out";
		case EV_ECONNREFUSED: return "connection refused";
		case EV_EHOSTDOWN: return "host is down";
		case EV_EHOSTUNREACH: return "host is unreachable";
		case EV_EALREADY: return "connection already in progress";
		case EV_EREMOTEIO: return "remote I/O error";
		case EV_ENOMEDIUM: return "no medium found";
		case EV_ECANCELED: return "operation canceled";
		case EV_EAI_BADFLAGS: return "bad ai_flags value";
		case EV_EAI_NONAME: return "unknown node or service";
		case EV_EAI_AGAIN: return "temporary failure";
		case EV_EAI_FAIL: return "permanent failure";
		case EV_EAI_NODATA: return "no address";
		case EV_EAI_FAMILY: return "ai_family not supported";
		case EV_EAI_SOCKTYPE: return "socket type not supported";
		case EV_EAI_SERVICE: return "service not available for socket type";
		case EV_EAI_ADDRFAMILY: return "address family not supported";
		case EV_EAI_MEMORY: return "out of memory";
		case EV_EAI_OVERFLOW: return "argument buffer overflow";
		case EV_EAI_CANCELED: return "request canceled";
		case EV_ECHARSET: return "invalid Unicode character";
		default: return "unknown OS-specific error";
	}
}

ev_t ev_init() {
	ev_t ev = malloc(sizeof *ev);
	if (!ev) return NULL;

	ev->active_n = 0;

	ev->next_msg = NULL;

	if (evi_stdio_init(&ev->in, &ev->out, &ev->err) < 0) goto fail_stdio;

	#ifdef EV_USE_MULTITHREAD
		ev_mutex_new(ev->lock);
		ev_cond_new(ev->has_msg_cond);

		ev->next_worker = NULL;
	#endif

	#ifdef EV_USE_URING
		if (evi_uring_init(ev, ev->uring) < 0) goto fail_async;
	#elif defined EV_USE_WIN32
		if (evi_win_init() < 0) goto fail_async;
	#endif

	return ev;
fail_async:
	#ifdef EV_USE_MULTITHREAD
		ev_cond_free(ev->has_msg_cond);
		ev_mutex_free(ev->lock);
	#endif
	evi_stdio_free(ev->in, ev->out, ev->err);
fail_stdio:
	free(ev);
	return NULL;
}
void ev_free(ev_t ev) {
	ev_mutex_lock(ev->lock);

	evi_stdio_free(ev->in, ev->out, ev->err);

	#ifdef EV_USE_URING
		evi_uring_free(ev->uring);
	#elif defined EV_USE_WIN32
		evi_win_free();
	#endif

	#ifdef EV_USE_MULTITHREAD
		while (ev->next_worker) {
			ev_pool_worker_t curr = ev->next_worker;
			ev->next_worker = curr->next;

			curr->kys = true;
			ev_thread_cancel(curr->thread);
			ev_cond_broadcast(curr->cond);

			ev_mutex_unlock(ev->lock);
			ev_thread_free_join(curr->thread);
			ev_mutex_lock(ev->lock);
			ev_cond_free(curr->cond);
			free(curr);
		}

		ev->next_worker = NULL;

		ev_cond_broadcast(ev->has_msg_cond);

		ev_mutex_unlock(ev->lock);
		ev_mutex_free(ev->lock);
	#endif
}

bool ev_busy(ev_t ev) {
	ev_mutex_lock(ev->lock);
	bool res = ev->active_n > 0;
	ev_mutex_unlock(ev->lock);
	return res;
}

void ev_begin(ev_t ev) {
	ev_mutex_lock(ev->lock);
	ev->active_n++;
	ev_mutex_unlock(ev->lock);
}
ev_code_t ev_push(ev_t ev, void *udata, ev_code_t err) {
	ev_mutex_lock(ev->lock);
	ev_code_t code = evi_push(ev, udata, err);
	ev_mutex_unlock(ev->lock);

	return code;
}
ev_code_t ev_exec(ev_t ev, void *udata, ev_worker_t worker, void *pargs, bool sync) {
	ev_mutex_lock(ev->lock);
	(void)sync;

	#ifdef EV_USE_MULTITHREAD
		if (!sync) {
			for (ev_pool_worker_t it = ev->next_worker; it; it = it->next) {
				if (!it->worker) {
					it->worker = worker;
					it->args = pargs;
					it->udata = udata;
					ev_cond_signal(it->cond);
					ev->active_n++;
					ev_mutex_unlock(ev->lock);
					return EV_OK;
				}
			}

			ev_pool_worker_t pool_worker = malloc(sizeof *pool_worker);
			// TODO: should we fallback to the sync behavior, or should we return -ENOMEM?
			if (!pool_worker) goto fallback;

			ev_cond_new(pool_worker->cond);

			pool_worker->ev = ev;
			pool_worker->kys = false;

			pool_worker->worker = worker;
			pool_worker->args = pargs;
			pool_worker->udata = udata;

			pool_worker->next = ev->next_worker;
			ev->next_worker = pool_worker;

			if (ev_thread_new(pool_worker->thread, evi_pool_worker_entry, pool_worker) < 0) {
				ev_cond_free(pool_worker->cond);
				free(pool_worker);
				goto fallback;
			}

			ev->active_n++;
			ev_mutex_unlock(ev->lock);
			return EV_OK;
		}
		else fallback: {
	#endif
			ev->active_n++;
			int code = worker(pargs);
			if (code == EV_ECANCELED) return EV_ECANCELED;

			int errcode = evi_push(ev, udata, code);

			ev_mutex_unlock(ev->lock);
			return errcode;
	#ifdef EV_USE_MULTITHREAD
		}
	#endif
}
ev_poll_res_t ev_poll(ev_t ev, bool wait, const ev_time_t *ptimeout, void **pudata, int *perr) {
	ev_mutex_lock(ev->lock);

	while (!ev->next_msg && wait) {
		#ifdef EV_USE_MULTITHREAD
			if (ptimeout) {
				if (ev_cond_timewait(ev->has_msg_cond, ev->lock, *ptimeout) == EV_ETIMEDOUT) {
					ev_mutex_unlock(ev->lock);
					return EV_POLL_TIMEOUT;
				}
			}
			else {
				ev_cond_wait(ev->has_msg_cond, ev->lock);
			}
		#else
			if (ptimeout) {
				evi_sleep(*ptimeout);
			}
			else {
				// In non-threaded mode, it is impossible for us to get a message while we're blocked
				// So we disobey the user and return empty instead
				return EV_POLL_EMPTY;
			}
		#endif
	}

	ev_msg_t msg = ev->next_msg;
	if (msg) ev->next_msg = msg->next;

	*pudata = msg->udata;
	*perr = msg->err;

	free(msg);

	ev->active_n--;
	ev_mutex_unlock(ev->lock);

	return EV_POLL_OK;
}

// IO OPS

typedef struct { ev_fd_t *pres; const char *path; ev_open_flags_t flags; int mode; } evi_open_args_t;
typedef struct { ev_fd_t fd; char *buff; size_t *n; size_t offset; } evi_rw_args_t;
typedef struct { ev_fd_t fd; } evi_sync_args_t;
typedef struct { ev_fd_t fd; ev_stat_t *buff; } evi_stat_args_t;

typedef struct { const char *path; int mode; } evi_mkdir_args_t;
typedef struct { ev_dir_t *pres; const char *path; } evi_opendir_args_t;
typedef struct { ev_dir_t dir; char **pname; } evi_readdir_args_t;

typedef struct { ev_socket_t *pres; ev_proto_t proto; ev_addr_t addr; uint16_t port; size_t max_n; } evi_sock_args_t;
typedef struct { ev_socket_t *pres; ev_addr_t *paddr; uint16_t *pport; ev_socket_t server; } evi_accept_args_t;
typedef struct { ev_socket_t sock; char *buff; size_t *pn; } evi_sock_rw_args_t;
typedef struct { ev_addrinfo_t *pres; const char *name; ev_addrinfo_flags_t flags; } evi_getaddrinfo_args_t;

typedef struct { char **pres; ev_path_type_t type; } evi_getpath_args_t;

typedef struct {
	ev_proc_t *pres;
	const char **argv;
	const char **env;
	const char *cwd;
	ev_spawn_stdio_flags_t in_flags, out_flags, err_flags;
	ev_fd_t *pin, *pout, *perr;
} evi_spawn_args_t;
typedef struct { int *psig; int *pcode; ev_proc_t proc; } evi_wait_args_t;
typedef struct { ev_proc_t proc; } evi_disown_args_t;

static int evi_open_worker(void *pargs) {
	evi_open_args_t args = *(evi_open_args_t*)pargs;
	free(pargs);
	return evi_sync_open(args.pres, args.path, args.flags, args.mode);
}
static int evi_read_worker(void *pargs) {
	evi_rw_args_t args = *(evi_rw_args_t*)pargs;
	free(pargs);
	return evi_sync_read(args.fd, args.buff, args.n, args.offset);
}
static int evi_write_worker(void *pargs) {
	evi_rw_args_t args = *(evi_rw_args_t*)pargs;
	free(pargs);
	return evi_sync_write(args.fd, args.buff, args.n, args.offset);
}
static int evi_sync_worker(void *pargs) {
	evi_sync_args_t args = *(evi_sync_args_t*)pargs;
	free(pargs);
	return evi_sync_sync(args.fd);
}
static int evi_stat_worker(void *pargs) {
	evi_stat_args_t args = *(evi_stat_args_t*)pargs;
	free(pargs);
	return evi_sync_stat(args.fd, args.buff);
}

static int evi_mkdir_worker(void *pargs) {
	evi_mkdir_args_t args = *(evi_mkdir_args_t*)pargs;
	free(pargs);
	return evi_sync_mkdir(args.path, args.mode);
}
static int evi_opendir_worker(void *pargs) {
	evi_opendir_args_t args = *(evi_opendir_args_t*)pargs;
	free(pargs);
	return evi_sync_opendir(args.pres, args.path);
}
static int evi_readdir_worker(void *pargs) {
	evi_readdir_args_t args = *(evi_readdir_args_t*)pargs;
	free(pargs);
	return evi_sync_readdir(args.dir, args.pname);
}

static int evi_connect_worker(void *pargs) {
	evi_sock_args_t args = *(evi_sock_args_t*)pargs;
	free(pargs);
	return evi_sync_connect(args.pres, args.proto, args.addr, args.port);
}
static int evi_bind_worker(void *pargs) {
	evi_sock_args_t args = *(evi_sock_args_t*)pargs;
	free(pargs);
	return evi_sync_bind(args.pres, args.proto, args.addr, args.port, args.max_n);
}
static int evi_accept_worker(void *pargs) {
	evi_accept_args_t args = *(evi_accept_args_t*)pargs;
	free(pargs);
	return evi_sync_accept(args.pres, args.paddr, args.pport, args.server);
}
static int evi_recv_worker(void *pargs) {
	evi_sock_rw_args_t args = *(evi_sock_rw_args_t*)pargs;
	free(pargs);
	return evi_sync_recv(args.sock, args.buff, args.pn);
}
static int evi_send_worker(void *pargs) {
	evi_sock_rw_args_t args = *(evi_sock_rw_args_t*)pargs;
	free(pargs);
	return evi_sync_send(args.sock, args.buff, args.pn);
}
static int evi_getaddrinfo_worker(void *pargs) {
	evi_getaddrinfo_args_t args = *(evi_getaddrinfo_args_t*)pargs;
	free(pargs);
	return evi_sync_getaddrinfo(args.pres, args.name, args.flags);
}

static int evi_getpath_worker(void *pargs) {
	evi_getpath_args_t args = *(evi_getpath_args_t*)pargs;
	free(pargs);
	return evi_sync_getpath(args.pres, args.type);
	// return 0;
}

static int evi_spawn_worker(void *pargs) {
	evi_spawn_args_t args = *(evi_spawn_args_t*)pargs;
	free(pargs);
	return evi_sync_spawn(
		args.pres,
		args.argv,
		args.env,
		args.cwd,
		args.in_flags,
		args.pin,
		args.out_flags,
		args.pout,
		args.err_flags,
		args.perr
	);
}
static int evi_wait_worker(void *pargs) {
	evi_wait_args_t args = *(evi_wait_args_t*)pargs;
	free(pargs);
	return evi_sync_wait(args.proc, args.psig, args.pcode);
}

ev_code_t ev_open(ev_t ev, void *udata, ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_open(ev->uring, udata, pres, path, flags, mode);
	#else
		evi_open_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->pres = pres;
		pargs->path = path;
		pargs->flags = flags;
		pargs->mode = mode;
		return ev_exec(ev, udata, evi_open_worker, pargs, false);
	#endif
}
ev_code_t ev_read(ev_t ev, void *udata, ev_fd_t fd, const char *buff, size_t *n, size_t offset) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_read(ev->uring, udata, fd, (char*)buff, n, offset);
	#else
		evi_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->fd = fd;
		pargs->buff = (char*)buff;
		pargs->n = n;
		pargs->offset = offset;
		return ev_exec(ev, udata, evi_read_worker, pargs, false);
	#endif
}
ev_code_t ev_write(ev_t ev, void *udata, ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_write(ev->uring, udata, fd, buff, n, offset);
	#else
		evi_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->fd = fd;
		pargs->buff = buff;
		pargs->n = n;
		pargs->offset = offset;
		return ev_exec(ev, udata, evi_write_worker, pargs, false);
	#endif
}
ev_code_t ev_sync(ev_t ev, void *udata, ev_fd_t fd) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_sync(ev->uring, udata, fd);
	#else
		evi_sync_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->fd = fd;
		return ev_exec(ev, udata, evi_sync_worker, pargs, false);
	#endif
}
ev_code_t ev_stat(ev_t ev, void *udata, ev_fd_t fd, ev_stat_t *buff) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_stat(ev->uring, udata, fd, buff);
	#else
		evi_stat_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->fd = fd;
		pargs->buff = buff;
		return ev_exec(ev, udata, evi_stat_worker, pargs, false);
	#endif
}

ev_code_t ev_mkdir(ev_t ev, void *udata, const char *path, int mode) {
	evi_mkdir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->path = path;
	pargs->mode = mode;
	return ev_exec(ev, udata, evi_mkdir_worker, pargs, false);
}
ev_code_t ev_opendir(ev_t ev, void *udata, ev_dir_t *pres, const char *path) {
	evi_opendir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->path = path;
	return ev_exec(ev, udata, evi_opendir_worker, pargs, false);
}
ev_code_t ev_readdir(ev_t ev, void *udata, ev_dir_t dir, char **pname) {
	evi_readdir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->dir = dir;
	pargs->pname = pname;
	return ev_exec(ev, udata, evi_readdir_worker, pargs, false);
}

ev_code_t ev_connect(ev_t ev, void *udata, ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	evi_sock_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->proto = proto;
	pargs->addr = addr;
	pargs->port = port;
	return ev_exec(ev, udata, evi_connect_worker, pargs, false);
}
ev_code_t ev_bind(ev_t ev, void *udata, ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
	evi_sock_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->proto = proto;
	pargs->addr = addr;
	pargs->port = port;
	pargs->max_n = max_n;
	return ev_exec(ev, udata, evi_bind_worker, pargs, false);
}
ev_code_t ev_accept(ev_t ev, void *udata, ev_socket_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_socket_t server) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_accept(ev->uring, udata, pres, paddr, pport, server);
	#else
		evi_accept_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->pres = pres;
		pargs->paddr = paddr;
		pargs->pport = pport;
		pargs->server = server;
		return ev_exec(ev, udata, evi_accept_worker, pargs, false);
	#endif
}
ev_code_t ev_recv(ev_t ev, void *udata, ev_socket_t sock, char *buff, size_t *pn) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_recv(ev->uring, udata, sock, buff, pn);
	#else
		evi_sock_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->sock = sock;
		pargs->buff = buff;
		pargs->pn = pn;
		return ev_exec(ev, udata, evi_recv_worker, pargs, false);
	#endif
}
ev_code_t ev_send(ev_t ev, void *udata, ev_socket_t sock, char *buff, size_t *pn) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_send(ev->uring, udata, sock, buff, pn);
	#else
		evi_sock_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->sock = sock;
		pargs->buff = buff;
		pargs->pn = pn;
		return ev_exec(ev, udata, evi_send_worker, pargs, false);
	#endif
}

ev_code_t ev_getaddrinfo(ev_t ev, void *udata, ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
	evi_getaddrinfo_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->name = name;
	pargs->flags = flags;
	return ev_exec(ev, udata, evi_getaddrinfo_worker, pargs, false);
}

ev_code_t ev_getpath(ev_t ev, void *udata, char **pres, ev_path_type_t type) {
	evi_getpath_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->type = type;
	return ev_exec(ev, udata, evi_getpath_worker, pargs, false);
}

ev_code_t ev_spawn(
	ev_t ev, void *udata, ev_proc_t *pres,
	const char **argv, const char **env,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_fd_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_fd_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_fd_t *perr
) {
	evi_spawn_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return EV_ENOMEM;

	pargs->pres = pres;
	pargs->argv = argv;
	pargs->env = env;
	pargs->cwd = cwd;
	pargs->in_flags = in_flags;
	pargs->out_flags = out_flags;
	pargs->err_flags = err_flags;
	pargs->pin = pin;
	pargs->pout = pout;
	pargs->perr = perr;
	return ev_exec(ev, udata, evi_spawn_worker, pargs, false);
}
ev_code_t ev_wait(ev_t ev, void *udata, ev_proc_t proc, int *psig, int *pcode) {
	#ifdef EV_USE_URING
		ev_begin(ev);
		return evi_uring_wait(ev->uring, udata, proc, psig, pcode);
	#else
		evi_wait_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return EV_ENOMEM;

		pargs->psig = psig;
		pargs->pcode = pcode;
		pargs->proc = proc;
		return ev_exec(ev, udata, evi_wait_worker, pargs, false);
	#endif
}

ev_fd_t ev_stdin(ev_t ev) {
	return ev->in;
}
ev_fd_t ev_stdout(ev_t ev) {
	return ev->out;
}
ev_fd_t ev_stderr(ev_t ev) {
	return ev->err;
}
