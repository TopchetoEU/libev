// Due to how this project is structured, some functions are erroneously marked as "unused"
#pragma GCC diagnostic ignored "-Wunused-function"

#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "./ev.h"
#include "./utils/multithread.h"

// Source files included here for a unity build

// IWYU pragma: begin_exports
#include "./utils/queue.c"
#include "./utils/time.c"
#include "./utils/ip.c"
#include "./impl/async.c"
#include "./impl/sync.c"
// IWYU pragma: begin_exports
#include "./async-fallback.c"

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
		case EV_ENOTBLK: return "block device required";
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
		case EV_ENOTSUP: return "operation not supported";
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

	if (evi_sync_init(ev) < 0) goto fail;
	if (evi_async_init(ev) < 0) goto fail_sync;
	if (evi_queue_init(ev) < 0) goto fail_sync;

	#ifdef EV_USE_MULTITHREAD
		evi_pool_init(ev->pool);
	#endif

	return ev;
fail_sync:
	evi_sync_free(ev);
fail:
	free(ev);
	return NULL;
}
void ev_free(ev_t ev) {
	#ifdef EV_USE_MULTITHREAD
		evi_pool_free(ev->pool);
	#endif

	evi_queue_free(ev);
	evi_sync_free(ev);
	evi_async_free(ev);
}

bool ev_busy(ev_t ev) {
	return ev->active_n > 0;
}

void ev_begin(ev_t ev) {
	ev->active_n++;
}
void ev_end(ev_t ev) {
	ev->active_n++;
}
ev_code_t ev_exec(ev_t ev, void *udata, ev_worker_t worker, void *pargs, bool sync) {
	(void)sync;

	#ifdef EV_USE_MULTITHREAD
		if (!sync) {
			return evi_pool_exec(ev, ev->pool, udata, worker, pargs);
		}
	#endif

	ev_begin(ev);
	int code = worker(pargs);
	if (code == EV_ECANCELED) return EV_ECANCELED;

	return ev_push(ev, udata, code);
}

ev_handle_t ev_stdin(ev_t ev) {
	return ev->in;
}
ev_handle_t ev_stdout(ev_t ev) {
	return ev->out;
}
ev_handle_t ev_stderr(ev_t ev) {
	return ev->err;
}
