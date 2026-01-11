#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once

#include "ev.h"
#include "../multithread.h"
#include "./common.h"
#include "./utils.h"

#include <stdio.h>
#include <stdint.h>
#include <liburing.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef struct ev_uring {
	struct io_uring ctx;
	ev_t ev;

	ev_thread_t worker;

	bool kys;
} *ev_uring_t;

typedef enum {
	EVI_URING_NONE,
	EVI_URING_OPEN,
	EVI_URING_STAT,
	EVI_URING_RW,
	EVI_URING_ACCEPT,
} ev_uring_type_t;

typedef struct {
	void *ticket;
	ev_uring_type_t type;
	union {
		ev_fd_t *phnd;
		size_t *pn;
		struct {
			ev_stat_t *pres;
			struct statx buff;
		} stat;
		struct {
			ev_fd_t *pres;
			ev_addr_t *paddr;
			uint16_t *pport;

			struct sockaddr_storage addr;
			socklen_t len;
		} accept;
	};
} *ev_uring_udata_t;

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

static struct io_uring_sqe *evi_uring_get_sqe(ev_uring_t uring, ev_uring_udata_t udata) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ctx);
	if (!sqe) io_uring_submit(&uring->ctx);

	sqe->user_data = (uint64_t)udata;
	return sqe;
}
static ev_uring_udata_t evi_uring_mkudata(ev_uring_type_t type, void *ticket) {
	ev_uring_udata_t udata = malloc(sizeof *udata);
	if (!udata) return NULL;
	udata->type = type;
	udata->ticket = ticket;
	return udata;
}

static int evi_uring_open(ev_uring_t uring, void *ticket, ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	ev_uring_udata_t udata = evi_uring_mkudata(EVI_URING_OPEN, ticket);
	if (!udata) return -ENOMEM;
	udata->phnd = pres;

	io_uring_prep_open(evi_uring_get_sqe(uring, udata), path, evi_unix_conv_open_flags(flags), mode);
	io_uring_submit(&uring->ctx);
	return 0;
}
static int evi_uring_read(ev_uring_t uring, void *ticket, ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	ev_uring_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return -ENOMEM;
	udata->pn = n;

	io_uring_prep_read(evi_uring_get_sqe(uring, udata), (int)(size_t)fd, buff, *n, offset);
	io_uring_submit(&uring->ctx);
	return 0;
}
static int evi_uring_write(ev_uring_t uring, void *ticket, ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	ev_uring_udata_t udata = evi_uring_mkudata(EVI_URING_RW, ticket);
	if (!udata) return -ENOMEM;
	udata->pn = n;

	io_uring_prep_write(evi_uring_get_sqe(uring, udata), (int)(size_t)fd, buff, *n, offset);
	io_uring_submit(&uring->ctx);
	return 0;
}
static int evi_uring_stat(ev_uring_t uring, void *ticket, ev_fd_t fd, ev_stat_t *pres) {
	ev_uring_udata_t udata = evi_uring_mkudata(EVI_URING_STAT, ticket);
	if (!udata) return -ENOMEM;

	int mask = 0;
	mask |= STATX_MODE | STATX_TYPE;
	mask |= STATX_UID | STATX_GID;
	mask |= STATX_ATIME | STATX_CTIME | STATX_MTIME;
	mask |= STATX_SIZE | STATX_BLOCKS;
	mask |= STATX_INO | STATX_NLINK | STATX_MNT_ID | STATX_MNT_ID_UNIQUE;

	io_uring_prep_statx(evi_uring_get_sqe(uring, udata), (int)(size_t)fd, "", AT_EMPTY_PATH, mask, &udata->stat.buff);
	io_uring_submit(&uring->ctx);
	return 0;
}

static int evi_uring_accept(ev_uring_t uring, void *ticket, ev_fd_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_fd_t server) {
	ev_uring_udata_t udata = evi_uring_mkudata(EVI_URING_OPEN, ticket);
	if (!udata) return -ENOMEM;

	io_uring_prep_accept(evi_uring_get_sqe(uring, udata), (int)(size_t)server, (void*)&udata->accept.addr, &udata->accept.len, 0);
	io_uring_submit(&uring->ctx);
	return 0;
}


static void *evi_uring_worker(void *arg) {
	ev_uring_t uring = (ev_uring_t)arg;

	while (!uring->kys) {
		struct io_uring_cqe *cqe;
		int code = io_uring_wait_cqe(&uring->ctx, &cqe);
		if (code == -EINTR) continue;
		if (!cqe->user_data) break;

		ev_uring_udata_t udata = (ev_uring_udata_t)(size_t)cqe->user_data;

		if (cqe->res < 0) {
			ev_push(uring->ev, udata->ticket, -cqe->res);
		}
		else {
			switch (udata->type) {
				case EVI_URING_STAT:
					evi_unix_conv_statx(udata->stat.pres, &udata->stat.buff);
					break;
				case EVI_URING_OPEN:
					*udata->phnd = (ev_fd_t)(size_t)cqe->res;
					break;
				case EVI_URING_RW:
					*udata->pn = cqe->res;
					break;
				case EVI_URING_ACCEPT:
					evi_unix_conv_sockaddr(&udata->accept.addr, udata->accept.paddr, udata->accept.pport);
					*udata->accept.pres = (ev_fd_t)(size_t)cqe->res;
					break;
				default: break;
			}
			ev_push(uring->ev, udata->ticket, 0);
		}

		io_uring_cqe_seen(&uring->ctx, cqe);
	}

	io_uring_queue_exit(&uring->ctx);
	return NULL;
}


static int evi_uring_init(ev_t ev, ev_uring_t uring) {
	uring->ev = ev;
	uring->kys = false;

	if (io_uring_queue_init(1024, &uring->ctx, 0) < 0) return -1;

	if (ev_thread_new(uring->worker, evi_uring_worker, uring) < 0) return -1;

	return 0;
}
static int evi_uring_free(ev_uring_t uring) {
	uring->kys = true;

	struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ctx);
	io_uring_prep_nop(sqe);
	sqe->user_data = 0;
	if (io_uring_submit(&uring->ctx) < 0) return -1;

	ev_thread_free_join(uring->worker);

	return 0;
}
