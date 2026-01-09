// Due to how this project is structured, some functions are erroneously marked as "unused"
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ev.h"
#include "multithread.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef EV_USE_UNIX
	#include "./unix/core.c"
#elif defined EV_USE_WIN32
	#include "./win/core.c"
#endif

#ifdef EV_USE_URING
	#include "./unix/uring.c"
#endif

typedef struct ev_msg {
	struct ev_msg *next;
	ev_ticket_t ticket;
	int err;
} *ev_msg_t;

struct ev {
	bool closing;
	size_t active_n;

	ev_mutex_t lock;
	ev_cond_t has_msg_cond;

	ev_msg_t next_msg;
	ev_ticket_t next_ticket;

	ev_fd_t in, out, err;

	#ifdef EV_USE_PTHREAD
		struct ev_pool_worker *next_worker;
	#endif

	#ifdef EV_USE_URING
		struct ev_uring uring[1];
	#endif
};

static void evi_push(ev_t ev, ev_ticket_t ticket, int err) {
	ev_msg_t msg = malloc(sizeof *msg); // TODO: propagate OOM error somehow
	msg->next = ev->next_msg;
	msg->ticket = ticket;
	msg->err = err;
	ev->next_msg = msg;

	#ifdef EV_USE_PTHREAD
		ev_cond_broadcast(ev->has_msg_cond);
	#endif
}

#ifdef EV_USE_PTHREAD
	typedef struct ev_pool_worker {
		struct ev_pool_worker *next;
		ev_t ev;
		ev_cond_t cond;

		ev_thread_t thread;

		ev_ticket_t ticket;
		ev_worker_t worker;
		void *args;

		bool kys;
	} *ev_pool_worker_t;
	typedef struct {
		ev_pool_worker_t worker;
		ev_t sync;
	} *ev_sync_args_t;

	static void *evi_pool_worker_entry(void *pargs) {
		ev_pool_worker_t worker = (ev_pool_worker_t)pargs;
		ev_t ev = worker->ev;

		ev_mutex_lock(ev->lock);

		while (true) {

			while (true) {
				if (worker->kys) goto end;
				if (worker->worker) break;

				ev_cond_wait(worker->cond, ev->lock);
			}

			int code = worker->worker(worker->args);
			ev_ticket_t ticket = worker->ticket;

			worker->worker = NULL;
			worker->args = NULL;
			worker->ticket = 0;

			evi_push(ev, ticket, code);
		}

	end:
		ev_mutex_unlock(ev->lock);
		ev_cond_free(worker->cond);
		free(worker);
		return NULL;
	}
#endif


static int evi_finalize(ev_t ev) {
	while (ev->next_worker) {
		ev_pool_worker_t curr = ev->next_worker;
		ev->next_worker = curr->next;

		curr->kys = true;
		ev_cond_broadcast(curr->cond);

		ev_mutex_unlock(ev->lock);
		ev_thread_free_join(curr->thread);
		ev_mutex_lock(ev->lock);
	}

	ev->next_worker = NULL;

	evi_stdio_free(ev->in, ev->out, ev->err);

	#ifdef EV_USE_PTHREAD
		ev_cond_broadcast(ev->has_msg_cond);
	#endif

	#ifdef EV_USE_URING
		if (evi_uring_free(ev->uring) < 0) return -1;
	#endif

	#ifdef EV_USE_WIN32
		if (evi_win_free() < 0) return -1;
	#endif

	ev_mutex_unlock(ev->lock);

	if (ev_mutex_free(ev->lock) < 0) return -1;

	return 0;
}

ev_t ev_init() {
	ev_t ev = malloc(sizeof *ev);
	if (!ev) return NULL;

	ev->active_n = 0;
	ev->closing = false;
	ev->next_ticket = 0;

	ev->next_msg = NULL;

	if (evi_stdio_init(&ev->in, &ev->out, &ev->err) < 0) goto fail;

	#ifdef EV_USE_PTHREAD
		if (ev_mutex_new(ev->lock) < 0) goto fail_stdio;
		if (ev_cond_new(ev->has_msg_cond) < 0) goto fail_mutex;

		ev->next_worker = NULL;
	#endif

	#ifdef EV_USE_URING
		if (evi_uring_init(ev, ev->uring) < 0) goto fail_cond;
	#endif

	#ifdef EV_USE_WIN32
		if (evi_win_init() < 0) goto fail_uring;
	#endif

	return ev;
fail_uring:
	#ifdef EV_USE_URING
		evi_uring_free(ev->uring);
	#endif
fail_cond:
	#ifdef EV_USE_PTHREAD
		ev_cond_free(ev->has_msg_cond);
	#endif
fail_mutex:
	#ifdef EV_USE_PTHREAD
		ev_mutex_free(ev->lock);
	#endif
fail_stdio:
	evi_stdio_free(ev->in, ev->out, ev->err);
fail:
	free(ev);
	return NULL;
}
void ev_free(ev_t ev) {
	ev_mutex_lock(ev->lock);
	ev->closing = true;
	ev_mutex_unlock(ev->lock);
}

bool ev_busy(ev_t ev) {
	ev_mutex_lock(ev->lock);
	bool res = ev->active_n > 0;
	ev_mutex_unlock(ev->lock);
	return res;
}
bool ev_closed(ev_t ev) {
	ev_mutex_lock(ev->lock);
	bool res = ev->closing;
	ev_mutex_unlock(ev->lock);
	return res;
}

ev_ticket_t ev_next(ev_t ev) {
	ev_mutex_lock(ev->lock);
	if (ev->next_ticket == 0) ev->next_ticket++;
	ev_ticket_t res = ev->next_ticket++;
	ev->active_n++;
	ev_mutex_unlock(ev->lock);
	return res;
}
void ev_push(ev_t ev, ev_ticket_t ticket, int err) {
	ev_mutex_lock(ev->lock);
	evi_push(ev, ticket, err);
	ev_mutex_unlock(ev->lock);
}
ev_ticket_t ev_exec(ev_t ev, ev_worker_t worker, void *pargs, bool sync) {
	ev_ticket_t ticket = ev_next(ev);

	ev_mutex_lock(ev->lock);

	#ifdef EV_USE_PTHREAD
		if (!sync) {

			for (ev_pool_worker_t it = ev->next_worker; it; it = it->next) {
				if (!it->worker) {
					it->worker = worker;
					it->args = pargs;
					it->ticket = ticket;
					ev_cond_signal(it->cond);
					ev_mutex_unlock(ev->lock);
					return ticket;
				}
			}

			ev_pool_worker_t pool_worker = malloc(sizeof *pool_worker);
			if (!pool_worker) goto fallback; // is this correct, or should we return 0?

			if (ev_cond_new(pool_worker->cond) < 0) {
				free(pool_worker);
				goto fallback;
			}

			pool_worker->ev = ev;
			pool_worker->kys = false;

			pool_worker->worker = worker;
			pool_worker->args = pargs;
			pool_worker->ticket = ticket;

			pool_worker->next = ev->next_worker;
			ev->next_worker = pool_worker;

			if (ev_thread_new(pool_worker->thread, evi_pool_worker_entry, pool_worker) < 0) {
				ev_cond_free(pool_worker->cond);
				free(pool_worker);
				goto fallback;
			}

			ev_mutex_unlock(ev->lock);
			return ticket;
		}
		else fallback: {
	#endif
			int code = worker(pargs);
			evi_push(ev, ticket, code);
			ev_mutex_unlock(ev->lock);
			return ticket;
	#ifdef EV_USE_PTHREAD
		}
	#endif
}

bool ev_poll(ev_t ev, bool wait, ev_ticket_t *pticket, int *perr) {
	ev_mutex_lock(ev->lock);

	if (!ev->next_msg && wait) {
		while (!ev->next_msg && wait) {
			if (ev->closing && ev->active_n == 0) {
				evi_finalize(ev);
				return false;
			}

			ev_cond_wait(ev->has_msg_cond, ev->lock);
		}
	}

	ev_msg_t msg = ev->next_msg;
	if (msg) ev->next_msg = msg->next;

	if (ev->closing) wait = false;

	ev->active_n--;

	*pticket = msg->ticket;
	*perr = msg->err;

	free(msg);

	ev_mutex_unlock(ev->lock);

	return true;
}

// TODO:Bad bad code, refactor!!

static bool ev_parse_ipv4(const char *str, ev_addr_t *pres) {
	ev_addr_t res;
	res.type = EV_ADDR_IPV4;

	const char *it = str;

	for (int i = 0; i < 4; i++) {
		uint64_t part = 0;
		bool any = false;

		while (*it >= '0' && *it <= '9') {
			part *= 10;
			part += *it - '0';
			it++;
			any = true;
		}

		if (!any) return false;
		if (*it == '.') {
			if (i == 3) return false;
			it++;
		}
		if (*it == '\0' && i != 3) return false;

		if (part > 255) return false;

		res.v4[i] = part;
	}

	if (pres) *pres = res;
	return true;
}
static bool ev_parse_ipv6(const char *str, ev_addr_t *pres) {
	ev_addr_t res = { 0 };
	res.type = EV_ADDR_IPV6;

	const char *it = str;
	int zeroes_i = -1;
	int i = 0;

	for (i = 0; i < 8; i++) {
		if (*it == '\0') {
			if (i == 0) return false;
			break;
		}

		// Kinda shitty code but eh
		if (i == 0 ?
			it[0] == ':' && it[1] == ':' :
			*it == ':'
		) {
			if (zeroes_i >= 0) return false;
			it += i == 0 ? 2 : 1;
			zeroes_i = i;
		}

		uint64_t part = 0;
		bool any = false;

		for (int j = 0; j < 4; j++) {
			if (*it >= '0' && *it <= '9' ) {
				part <<= 4;
				part |= *it - '0';
			}
			else if (*it == 'a' && *it == 'f') {
				part <<= 4;
				part |= *it - 'a' + 10;
			}
			else if (*it == 'A' && *it == 'F') {
				part <<= 4;
				part |= *it - 'a' + 10;
			}
			else break;
			any = true;
		}

		if (!any) return false;

		res.v6[i] = part;
	}

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

// IO OPS

typedef struct { ev_fd_t *pres; const char *path; ev_open_flags_t flags; int mode; } evi_open_args_t;
typedef struct { ev_fd_t fd; char *buff; size_t *n; size_t offset; } evi_rw_args_t;
typedef struct { ev_fd_t fd; ev_stat_t *buff; } evi_stat_args_t;

typedef struct { const char *path; int mode; } evi_mkdir_args_t;
typedef struct { ev_dir_t *pres; const char *path; } evi_opendir_args_t;
typedef struct { ev_dir_t dir; char **pname; } evi_readdir_args_t;

typedef struct { ev_fd_t *pres; ev_proto_t proto; ev_addr_t addr; uint16_t port; } evi_sock_args_t;
typedef struct { ev_fd_t *pres; ev_addr_t *paddr; uint16_t *pport; ev_fd_t server; } evi_accept_args_t;
typedef struct { ev_addrinfo_t *pres; const char *name; ev_addrinfo_flags_t flags; } evi_getaddrinfo_args_t;


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
	return evi_sync_bind(args.pres, args.proto, args.addr, args.port);
}
static int evi_accept_worker(void *pargs) {
	evi_accept_args_t args = *(evi_accept_args_t*)pargs;
	free(pargs);
	return evi_sync_accept(args.pres, args.paddr, args.pport, args.server);
}
static int evi_getaddrinfo_worker(void *pargs) {
	evi_getaddrinfo_args_t args = *(evi_getaddrinfo_args_t*)pargs;
	free(pargs);
	return evi_sync_getaddrinfo(args.pres, args.name, args.flags);
}

ev_ticket_t ev_open(ev_t ev, ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	#ifdef EV_USE_URING
		return evi_uring_open(ev->uring, pres, path, flags, mode);
	#else
		evi_open_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return 0;

		pargs->pres = pres;
		pargs->path = path;
		pargs->flags = flags;
		pargs->mode = mode;
		return ev_exec(ev, evi_open_worker, pargs, false);
	#endif
}
ev_ticket_t ev_read(ev_t ev, ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	#ifdef EV_USE_URING
		return evi_uring_read(ev->uring, fd, buff, n, offset);
	#else
		evi_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return 0;

		pargs->fd = fd;
		pargs->buff = buff;
		pargs->n = n;
		pargs->offset = offset;
		return ev_exec(ev, evi_read_worker, pargs, false);
	#endif
}
ev_ticket_t ev_write(ev_t ev, ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	#ifdef EV_USE_URING
		return evi_uring_write(ev->uring, fd, buff, n, offset);
	#else
		evi_rw_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return 0;

		pargs->fd = fd;
		pargs->buff = buff;
		pargs->n = n;
		pargs->offset = offset;
		return ev_exec(ev, evi_write_worker, pargs, false);
	#endif
}
ev_ticket_t ev_stat(ev_t ev, ev_fd_t fd, ev_stat_t *buff) {
	#ifdef EV_USE_URING
		return evi_uring_stat(ev->uring, fd, buff);
	#else
		evi_stat_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return 0;

		pargs->fd = fd;
		pargs->buff = buff;
		return ev_exec(ev, evi_stat_worker, pargs, false);
	#endif
}

ev_ticket_t ev_mkdir(ev_t ev, const char *path, int mode) {
	evi_mkdir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->path = path;
	pargs->mode = mode;
	return ev_exec(ev, evi_mkdir_worker, pargs, false);
}
ev_ticket_t ev_opendir(ev_t ev, ev_dir_t *pres, const char *path) {
	evi_opendir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->pres = pres;
	pargs->path = path;
	return ev_exec(ev, evi_opendir_worker, pargs, false);
}
ev_ticket_t ev_readdir(ev_t ev, ev_dir_t dir, char **pname) {
	evi_readdir_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->dir = dir;
	pargs->pname = pname;
	return ev_exec(ev, evi_readdir_worker, pargs, false);
}

ev_ticket_t ev_connect(ev_t ev, ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	evi_sock_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->pres = pres;
	pargs->proto = proto;
	pargs->addr = addr;
	pargs->port = port;
	return ev_exec(ev, evi_connect_worker, pargs, false);
}
ev_ticket_t ev_bind(ev_t ev, ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	evi_sock_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->pres = pres;
	pargs->proto = proto;
	pargs->addr = addr;
	pargs->port = port;
	return ev_exec(ev, evi_bind_worker, pargs, false);
}
ev_ticket_t ev_accept(ev_t ev, ev_fd_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_fd_t server) {
	#ifdef EV_USE_URING
		return evi_uring_accept(ev->uring, pres, paddr, pport, server);
	#else
		evi_accept_args_t *pargs = malloc(sizeof *pargs);
		if (!pargs) return 0;

		pargs->pres = pres;
		pargs->paddr = paddr;
		pargs->pport = pport;
		pargs->server = server;
		return ev_exec(ev, evi_accept_worker, pargs, false);
	#endif
}
ev_ticket_t ev_getaddrinfo(ev_t ev, ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
	evi_getaddrinfo_args_t *pargs = malloc(sizeof *pargs);
	if (!pargs) return 0;

	pargs->pres = pres;
	pargs->name = name;
	pargs->flags = flags;
	return ev_exec(ev, evi_getaddrinfo_worker, pargs, false);
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
