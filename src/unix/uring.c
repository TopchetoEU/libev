#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once

#ifdef EVI_ASYNC
	#error "Only one async library may be used"
#endif
#define EVI_ASYNC

#include "ev/conf.h"
#include "ev.h"
#include "ev/errno.h"
#include "../multithread.h"
#include "./common.h"
#include "./utils.h"
#include "./core.c"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <liburing.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>

typedef enum {
	EVI_URING_NONE,
	EVI_URING_OPEN,
	EVI_URING_STAT,
	EVI_URING_RW,
	EVI_URING_ACCEPT,
	EVI_URING_CONNECT,
	EVI_URING_WAIT,

	// Special, used for eventfd signals
	EVI_URING_USR,
	EVI_URING_TIMEOUT,
} ev_async_type_t;

typedef struct {
	void *ticket;
	ev_code_t err;
} ev_async_msg_t;

typedef struct {
	void *ticket;
	ev_async_type_t type;
	union {
		ev_handle_t *phnd;
		size_t *pn;
		struct {
			ev_stat_t *pres;
			struct statx buff;
		} stat;
		struct {
			ev_handle_t *pres;
			ev_server_t *pserv_res;
			ev_addr_t *paddr;
			uint16_t *pport;

			struct sockaddr_storage addr;
			socklen_t len;
		} accept;
		struct {
			int sock;
			ev_handle_t *pres;
		} connect;
		struct {
			int *pcode;
			int *psig;
			siginfo_t buff;
		} wait;
		ev_async_msg_t usr;
	};
} *ev_async_udata_t, ev_async_udata_s;

typedef struct ev_async {
	struct io_uring ctx;
	int usermsg_read, usermsg_write;
	ev_async_udata_s usermsg_read_udata[1];
} *ev_async_t, ev_async_s;

static void evi_unix_conv_statx(ev_stat_t *dst, struct statx *src) {
	evi_unix_conf_stat_mode(src->stx_mode, &dst->type, &dst->mode);
	dst->uid = src->stx_uid;
	dst->gid = src->stx_gid;
	dst->atime = (ev_time_t) { .sec = src->stx_atime.tv_sec, .nsec = src->stx_atime.tv_nsec };
	dst->ctime = (ev_time_t) { .sec = src->stx_ctime.tv_sec, .nsec = src->stx_ctime.tv_nsec };
	dst->mtime = (ev_time_t) { .sec = src->stx_mtime.tv_sec, .nsec = src->stx_mtime.tv_nsec };
	dst->size = src->stx_size;
	dst->inode = src->stx_ino;
	dst->links = src->stx_nlink;
	dst->blksize = src->stx_blksize;
}

static struct io_uring_sqe *evi_uring_get_sqe(ev_async_t async, ev_async_udata_t udata) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&async->ctx);
	if (!sqe) {
		io_uring_submit(&async->ctx);
		sqe = io_uring_get_sqe(&async->ctx);
	}

	sqe->user_data = (uint64_t)udata;
	return sqe;
}
static ev_async_udata_t evi_uring_mkudata(ev_async_type_t type, void *ticket) {
	ev_async_udata_t udata = malloc(sizeof *udata);
	if (!udata) return NULL;

	udata->type = type;
	udata->ticket = ticket;
	return udata;
}

static ev_code_t evi_async_push(ev_async_t async, void *ticket, int err) {
	ev_async_msg_t msg;
	memset(&msg, 0, sizeof msg);
	msg.ticket = ticket;
	msg.err = err;
	if (write(async->usermsg_write, &msg, sizeof msg) < 0) return evi_unix_conv_errno(errno);
	return EV_OK;
}
static void evi_setup_userpoll(ev_async_t async) {
	io_uring_prep_read(
		evi_uring_get_sqe(async, async->usermsg_read_udata),
		async->usermsg_read,
		&async->usermsg_read_udata->usr,
		sizeof async->usermsg_read_udata->usr, -1
	);
	io_uring_submit(&async->ctx);
}
static bool evi_async_poll(ev_async_t async, const ev_time_t *ptimeout, void **pticket, int *perr) {
	ev_async_udata_t timeout_udata = malloc(sizeof *timeout_udata);
	timeout_udata->type = EVI_URING_TIMEOUT;

	if (ptimeout) {
		ev_time_t now;
		// If now is after timeout
		if (evs_monotime(&now) == EV_OK && ev_timecmp(now, *ptimeout) > 0) {
			// TODO: optimize this special case
		}

		struct __kernel_timespec ts[1];
		ts->tv_sec = ptimeout->sec;
		ts->tv_nsec = ptimeout->nsec;
		io_uring_prep_timeout(evi_uring_get_sqe(async, timeout_udata), ts, 0, IORING_TIMEOUT_ABS | IORING_TIMEOUT_ETIME_SUCCESS);
	}

	while (true) {
		struct io_uring_cqe *cqe;

		io_uring_submit(&async->ctx);
		int code = io_uring_wait_cqe(&async->ctx, &cqe);
		if (code == -EINTR) continue;

		ev_async_udata_t udata = (ev_async_udata_t)(size_t)cqe->user_data;
		if (!udata) {
			io_uring_cqe_seen(&async->ctx, cqe);
			continue;
		}

		if (udata->type == EVI_URING_USR) {
			evi_setup_userpoll(async);
			*pticket = udata->usr.ticket;
			*perr = udata->usr.err;
			io_uring_cqe_seen(&async->ctx, cqe);
			return true;
		}
		else if (udata->type == EVI_URING_TIMEOUT) {
			if (udata != timeout_udata) {
				// TODO: what to do if we catch something we shouldn't've
			}

			io_uring_prep_timeout_remove(evi_uring_get_sqe(async, NULL), (uint64_t)(size_t)udata, 0);

			free(udata);
			io_uring_cqe_seen(&async->ctx, cqe);
			return false;
		}
		else if (cqe->res < 0) {
			*pticket = udata->ticket;
			*perr = evi_unix_conv_errno(-cqe->res);

			free(udata);
			io_uring_cqe_seen(&async->ctx, cqe);
			return true;
		}
		else {
			switch (udata->type) {
				case EVI_URING_STAT:
					evi_unix_conv_statx(udata->stat.pres, &udata->stat.buff);
					break;
				case EVI_URING_OPEN:
					*udata->phnd = evi_unix_mkfd(cqe->res);
					break;
				case EVI_URING_RW:
					*udata->pn = cqe->res;
					break;
				case EVI_URING_ACCEPT:
					evi_unix_conv_sockaddr(&udata->accept.addr, udata->accept.paddr, udata->accept.pport);
					*udata->accept.pres = evi_unix_mkfd(cqe->res);
					break;
				case EVI_URING_CONNECT:
					*udata->connect.pres = evi_unix_mkfd(udata->connect.sock);
					break;
				case EVI_URING_WAIT:
					*udata->wait.pcode = -1;
					*udata->wait.psig = -1;
					switch (udata->wait.buff.si_code) {
						case CLD_EXITED:
							*udata->wait.pcode = udata->wait.buff.si_status;
							break;
						case CLD_KILLED:
						case CLD_DUMPED:
						case CLD_STOPPED:
							*udata->wait.psig = udata->wait.buff.si_status;
							break;
						case CLD_TRAPPED:
							*udata->wait.psig = SIGTRAP;
							break;
						case CLD_CONTINUED:
							*udata->wait.psig = SIGCONT;
							break;
					}
					*udata->accept.pres = evi_unix_mkfd(cqe->res);
					break;
				default: break;
			}

			*pticket = udata->ticket;
			*perr = 0;

			free(udata);
			io_uring_cqe_seen(&async->ctx, cqe);
			return true;
		}

	}
}

static ev_code_t evi_async_read(ev_async_t async, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_read(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), buff, *n, -1);
	io_uring_submit(&async->ctx);
	return EV_OK;
}
static ev_code_t evi_async_write(ev_async_t async, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_write(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), buff, *n, -1);
	io_uring_submit(&async->ctx);
	return EV_OK;
}

static ev_code_t evi_async_file_open(ev_async_t async, void *ticket, ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_OPEN, ticket);
	if (!udata) return EV_ENOMEM;
	udata->phnd = pres;

	io_uring_prep_open(evi_uring_get_sqe(async, udata), path, evi_unix_conv_open_flags(flags), mode);
	io_uring_submit(&async->ctx);
	return EV_OK;
}
static ev_code_t evi_async_file_read(ev_async_t async, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_read(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), buff, *n, offset);
	io_uring_submit(&async->ctx);
	return EV_OK;
}
static ev_code_t evi_async_file_write(ev_async_t async, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_write(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), buff, *n, offset);
	io_uring_submit(&async->ctx);
	return EV_OK;
}
static ev_code_t evi_async_sync(ev_async_t async, void *ticket, ev_handle_t fd) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;

	io_uring_prep_fsync(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), 0);
	io_uring_submit(&async->ctx);
	return EV_OK;
}
static ev_code_t evi_async_stat(ev_async_t async, void *ticket, ev_handle_t fd, ev_stat_t *pres) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_STAT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->stat.pres = pres;

	int mask = 0;
	mask |= STATX_MODE | STATX_TYPE;
	mask |= STATX_UID | STATX_GID;
	mask |= STATX_ATIME | STATX_CTIME | STATX_MTIME;
	mask |= STATX_SIZE | STATX_BLOCKS;
	mask |= STATX_INO | STATX_NLINK | STATX_MNT_ID | STATX_MNT_ID_UNIQUE;

	io_uring_prep_statx(evi_uring_get_sqe(async, udata), evi_unix_fd(fd), "", AT_EMPTY_PATH, mask, &udata->stat.buff);
	io_uring_submit(&async->ctx);
	return EV_OK;
}

static ev_code_t evi_async_server_accept(ev_async_t async, void *ticket, ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_ACCEPT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->accept.pres = pres;
	udata->accept.paddr = paddr;
	udata->accept.pport = pport;
	udata->accept.len = sizeof udata->accept.addr;

	io_uring_prep_accept(evi_uring_get_sqe(async, udata), (int)(size_t)server, (void*)&udata->accept.addr, &udata->accept.len, 0);
	io_uring_submit(&async->ctx);
	return EV_OK;
}

static ev_code_t evi_async_socket_connect(ev_async_t async, void *ticket, ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_async_push(async, ticket, evi_unix_conv_errno(errno));

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_CONNECT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->connect.pres = pres;
	udata->connect.sock = sock;

	io_uring_prep_connect(evi_uring_get_sqe(async, udata), sock, (void*)&arg_addr, len);
	io_uring_submit(&async->ctx);
	return EV_OK;
}

static ev_code_t evi_async_proc_wait(ev_async_t async, void *ticket, ev_proc_t proc, int *psig, int *pcode) {
	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_WAIT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->wait.pcode = pcode;
	udata->wait.psig = psig;

	io_uring_prep_waitid(evi_uring_get_sqe(async, udata), P_PID, (pid_t)(size_t)proc, &udata->wait.buff, WEXITED | WSTOPPED | WCONTINUED, 0);
	io_uring_submit(&async->ctx);
	return EV_OK;
}

static ev_code_t evi_async_init(ev_async_t async) {
	int code;
	if ((code = io_uring_queue_init(1024, &async->ctx, 0)) < 0) goto fail;

	int msg_pipe[2];
	if (pipe(msg_pipe) < 0) goto fail_queue;

	async->usermsg_read = msg_pipe[0];
	async->usermsg_write = msg_pipe[1];

	memset(&async->usermsg_read_udata->usr, 0, sizeof async->usermsg_read_udata->usr);
	async->usermsg_read_udata->type = EVI_URING_USR;

	evi_setup_userpoll(async);


	return EV_OK;

fail_queue:
	io_uring_queue_exit(&async->ctx);
fail:
	return evi_unix_conv_errno(errno);
}
static ev_code_t evi_async_free(ev_async_t async) {
	io_uring_queue_exit(&async->ctx);
	close(async->usermsg_read);
	close(async->usermsg_write);
	return EV_OK;
}

#define evi_async_read evi_async_read
#define evi_async_write evi_async_write
#define evi_async_file_open evi_async_file_open
#define evi_async_file_read evi_async_file_read
#define evi_async_file_write evi_async_file_write
#define evi_async_sync evi_async_sync
#define evi_async_stat evi_async_stat
#define evi_async_server_accept evi_async_server_accept
#define evi_async_socket_connect evi_async_socket_connect
#define evi_async_proc_wait evi_async_proc_wait
