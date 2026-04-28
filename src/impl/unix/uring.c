#pragma once

#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

// #include <linux/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>

#include <liburing/io_uring.h>
#include <liburing.h>

#include "../../ev.h"
#include "../../utils/multithread.h"
#include "./uring.h"

#include "../../utils/queue.c"
#include "./utils.c"


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

static struct io_uring_sqe *evi_uring_get_sqe(ev_t ev, ev_async_udata_t udata) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ev->async->ctx);
	if (!sqe) {
		io_uring_submit(&ev->async->ctx);
		sqe = io_uring_get_sqe(&ev->async->ctx);
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

static void evi_setup_userpoll(ev_t ev) {
	io_uring_prep_read(
		evi_uring_get_sqe(ev, ev->async->usermsg_read_udata),
		ev->async->usermsg_fd,
		&ev->async->usermsg_read_udata->usr,
		sizeof ev->async->usermsg_read_udata->usr, -1
	);
	io_uring_submit(&ev->async->ctx);
}

ev_code_t ev_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_read(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), buff, *n, -1);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}
ev_code_t ev_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_write(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), buff, *n, -1);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}

ev_code_t ev_file_open(ev_t ev, void *ticket, ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_OPEN, ticket);
	if (!udata) return EV_ENOMEM;
	udata->phnd = pres;

	io_uring_prep_openat(evi_uring_get_sqe(ev, udata), AT_FDCWD, path, evi_unix_conv_open_flags(flags), mode);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}
ev_code_t ev_file_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_read(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), buff, *n, offset);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}
ev_code_t ev_file_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;
	udata->pn = n;

	io_uring_prep_write(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), buff, *n, offset);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}
ev_code_t ev_sync(ev_t ev, void *ticket, ev_handle_t fd) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return EV_ENOMEM;

	io_uring_prep_fsync(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), 0);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}
ev_code_t ev_stat(ev_t ev, void *ticket, ev_handle_t fd, ev_stat_t *pres) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_STAT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->stat.pres = pres;

	int mask = 0;
	mask |= STATX_MODE | STATX_TYPE;
	mask |= STATX_UID | STATX_GID;
	mask |= STATX_ATIME | STATX_CTIME | STATX_MTIME;
	mask |= STATX_SIZE | STATX_BLOCKS;
	// mask |= STATX_INO | STATX_NLINK | STATX_MNT_ID | STATX_MNT_ID_UNIQUE;
	mask |= STATX_INO | STATX_NLINK;

	io_uring_prep_statx(evi_uring_get_sqe(ev, udata), evi_unix_fd(fd), "", AT_EMPTY_PATH, mask, &udata->stat.buff);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}

ev_code_t ev_server_accept(ev_t ev, void *ticket, ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	ev_begin(ev);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_ACCEPT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->accept.pres = pres;
	udata->accept.paddr = paddr;
	udata->accept.pport = pport;
	udata->accept.len = sizeof udata->accept.addr;

	io_uring_prep_accept(evi_uring_get_sqe(ev, udata), (int)(size_t)server, (void*)&udata->accept.addr, &udata->accept.len, 0);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}

ev_code_t ev_socket_connect(ev_t ev, void *ticket, ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	ev_begin(ev);

	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return ev_push(ev, ticket, evi_unix_conv_errno(errno));

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_CONNECT, ticket);
	if (!udata) return EV_ENOMEM;
	udata->connect.pres = pres;
	udata->connect.sock = sock;

	io_uring_prep_connect(evi_uring_get_sqe(ev, udata), sock, (void*)&arg_addr, len);
	io_uring_submit(&ev->async->ctx);
	return EV_OK;
}

#if IO_URING_VERSION_MINOR > 5
	ev_code_t ev_proc_wait(ev_t ev, void *ticket, ev_proc_t proc, int *psig, int *pcode) {
		ev_begin(ev);

		ev_async_udata_t udata = evi_uring_mkudata(EVI_URING_WAIT, ticket);
		if (!udata) return EV_ENOMEM;
		udata->wait.pcode = pcode;
		udata->wait.psig = psig;

		io_uring_prep_waitid(evi_uring_get_sqe(ev, udata), P_PID, (pid_t)(size_t)proc, &udata->wait.buff, WEXITED | WSTOPPED | WCONTINUED, 0);
		io_uring_submit(&ev->async->ctx);
		return EV_OK;
	}
	#define EVI_ASYNC_PROC_WAIT
#endif

ev_code_t ev_push(ev_t ev, void *ticket, ev_code_t err) {
	ev_code_t code = evi_queue_push(ev, ticket, err);
	if (code != EV_OK) return code;

	write(ev->async->usermsg_fd, &(uint64_t) { 1 }, sizeof(uint64_t));
	return EV_OK;
}
bool ev_poll(ev_t ev, const ev_time_t *ptimeout, void **pticket, int *perr) {
	if (evi_queue_pop(ev, pticket, perr)) {
		ev_end(ev);
		return true;
	}

	ev_async_udata_t timeout_udata = NULL;

	if (ptimeout) {
		ev_time_t now;
		// If now is after timeout
		if (evs_monotime(&now) == EV_OK && ev_timecmp(now, *ptimeout) > 0) {
			// TODO: optimize this special case
		}

		timeout_udata = malloc(sizeof *timeout_udata);
		timeout_udata->type = EVI_URING_TIMEOUT;

		struct __kernel_timespec ts[1];
		ts->tv_sec = ptimeout->sec;
		ts->tv_nsec = ptimeout->nsec;
		io_uring_prep_timeout(evi_uring_get_sqe(ev, timeout_udata), ts, 0, IORING_TIMEOUT_ABS | IORING_TIMEOUT_ETIME_SUCCESS);
	}

	while (true) {
		struct io_uring_cqe *cqe;

		io_uring_submit(&ev->async->ctx);
		int code = io_uring_wait_cqe(&ev->async->ctx, &cqe);
		if (code == -EINTR) continue;

		ev_async_udata_t udata = (ev_async_udata_t)(size_t)cqe->user_data;
		if (!udata) {
			io_uring_cqe_seen(&ev->async->ctx, cqe);
			continue;
		}

		if (udata->type == EVI_URING_USR) {
			evi_setup_userpoll(ev);
			io_uring_cqe_seen(&ev->async->ctx, cqe);

			if (evi_queue_pop(ev, pticket, perr)) {
				ev_end(ev);
				return true;
			}
		}
		else if (udata->type == EVI_URING_TIMEOUT) {
			if (udata != timeout_udata) {
				// TODO: what to do if we catch something we shouldn't've
			}

			io_uring_prep_timeout_remove(evi_uring_get_sqe(ev, NULL), (uint64_t)(size_t)udata, 0);

			free(udata);
			io_uring_cqe_seen(&ev->async->ctx, cqe);
			return false;
		}
		else if (cqe->res < 0) {
			*pticket = udata->ticket;
			*perr = evi_unix_conv_errno(-cqe->res);

			free(udata);
			io_uring_cqe_seen(&ev->async->ctx, cqe);
			ev_end(ev);
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
			io_uring_cqe_seen(&ev->async->ctx, cqe);
			ev_end(ev);
			return true;
		}

	}
}

static ev_code_t evi_async_init(ev_t ev) {
	int code;
	if ((code = io_uring_queue_init(1024, &ev->async->ctx, 0)) < 0) goto fail;

	ev->async->usermsg_fd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (ev->async->usermsg_fd < 0) goto fail_queue;

	memset(&ev->async->usermsg_read_udata->usr, 0, sizeof ev->async->usermsg_read_udata->usr);
	ev->async->usermsg_read_udata->type = EVI_URING_USR;

	evi_setup_userpoll(ev);

	return EV_OK;

fail_queue:
	io_uring_queue_exit(&ev->async->ctx);
fail:
	return evi_unix_conv_errno(errno);
}
static ev_code_t evi_async_free(ev_t ev) {
	io_uring_queue_exit(&ev->async->ctx);
	close(ev->async->usermsg_fd);
	return EV_OK;
}

#define EVI_ASYNC_READ
#define EVI_ASYNC_WRITE
#define EVI_ASYNC_FILE_OPEN
#define EVI_ASYNC_FILE_READ
#define EVI_ASYNC_FILE_WRITE
#define EVI_ASYNC_SYNC
#define EVI_ASYNC_STAT
#define EVI_ASYNC_SERVER_ACCEPT
#define EVI_ASYNC_SOCKET_CONNECT
