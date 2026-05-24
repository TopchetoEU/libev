#pragma once

#include <asm-generic/errno-base.h>
#include <assert.h>
#include <ev/conf.h>
#include <ev/sync.h>
#include <ev/errno.h>

#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>
#include <err.h>

#include "./epoll.h"
#include "./pollish.h"

#include "../async.h"
#include "../../ev.h"
#include "./pollish.c"
#include "ev.h"
#include "utils.c"

static uint64_t evi_async_subms_diff(ev_time_t timeout) {
	ev_time_t now;
	if (evs_monotime(&now) != EV_OK) return 0;

	ev_time_t diff = ev_timesub(now, timeout);
	if (diff.sec != 0) return 0;
	if (diff.nsec > 1000000) return 0;
	return diff.nsec;
}

static int evi_epoll_type_to_mask(ev_pl_type_t type) {
	if (type & 0x10) {
		return EPOLLRDHUP | EPOLLERR | EPOLLHUP | EPOLLOUT;
	}
	else {
		return EPOLLRDHUP | EPOLLERR | EPOLLHUP | EPOLLIN;
	}
}
static int evi_epoll_type_to_unmask(ev_pl_type_t type) {
	if (type & 0x10) {
		return ~EPOLLOUT;
	}
	else {
		return ~EPOLLIN;
	}
}
static int evi_epoll_fd_to_mask(ev_epoll_fd_t fd) {
	int flags = 0;

	if (fd->read) flags |= evi_epoll_type_to_mask(EVI_POLL_READ);
	if (fd->write) flags |= evi_epoll_type_to_mask(EVI_POLL_WRITE);

	return flags;
}

ev_code_t evi_pl_impl_add(ev_t ev, ev_pl_event_t evn) {
	ev_epoll_fd_t fd = malloc(sizeof *fd);
	if (!fd) goto error;
	fd->fd = evn.fd;
	fd->read = 0;
	fd->write = 0;

	ev_epoll_req_t req = malloc(sizeof *req);
	if (!req) goto error_alloc_fd;

	fd->head = req;

	req->next = NULL;
	req->evn = evn;

	if (evn.type & 0x10) fd->write++;
	else fd->read++;

	if (epoll_ctl(ev->async->epoll_fd, EPOLL_CTL_ADD, evn.fd, &(struct epoll_event) {
		.data.ptr = fd,
		.events = evi_epoll_fd_to_mask(fd),
	}) == 0) {
		if (ev->async->head) ev->async->head->slot = &fd->next;
		fd->next = fd;
		fd->slot = &ev->async->head;
		ev->async->head = fd;
		return EV_OK;
	}
	if (errno != EEXIST) goto error_alloc_req;

	for (ev_epoll_fd_t new_fd = ev->async->head; new_fd; new_fd = new_fd->next) {
		if (new_fd->fd == evn.fd) {
			req->next = new_fd->head;
			new_fd->head = req->next;
			new_fd->read += fd->read;
			new_fd->write += fd->write;

			if (epoll_ctl(ev->async->epoll_fd, EPOLL_CTL_MOD, evn.fd, &(struct epoll_event) {
				.data.ptr = new_fd,
				.events = evi_epoll_fd_to_mask(new_fd),
			}) < 0) {
				new_fd->head = req->next;
				goto error_alloc_req;
			}

			free(fd);
			return EV_OK;
		}
	}

	assert(false && "epoll_ctl reports EEXIST, but the fd is not in our set");

error_alloc_req:
	free(req);
error_alloc_fd:
	free(fd);
error:
	return evi_unix_conv_errno(errno);
}

static ev_pl_res_t evi_pl_impl_poll(ev_t ev, const ev_time_t *ptimeout, void **pticket, ev_code_t *perr) {
	struct epoll_event evn = { 0 };
	struct timespec ts_timeout;
	struct timespec *pts_timeout = NULL;

	if (ptimeout) {
		ev_time_t tmp;
		evs_monotime(&tmp);
		tmp = ev_timesub(tmp, *ptimeout);

		if (tmp.sec < 0) {
			ts_timeout.tv_sec = 0;
			ts_timeout.tv_nsec = 0;
		}
		else {
			ts_timeout.tv_sec = tmp.sec;
			ts_timeout.tv_nsec = tmp.nsec;
		}

		pts_timeout = &ts_timeout;
	}

	int n;
	while ((n = epoll_pwait2(ev->async->epoll_fd, &evn, 1, pts_timeout, NULL)) < 0) {
		if (errno != EINTR) err(1, "failed to poll");
	}
	if (n == 0) {
		if (ptimeout) return EV_POLL_TIMEOUT;
		else return EV_POLL_EMPTY;
	}

	ev_epoll_fd_t fd = evn.data.ptr;

	for (ev_epoll_req_t *preq = &fd->head; *preq; preq = &(*preq)->next) {
		ev_epoll_req_t req = *preq;

		if (evn.events & evi_epoll_type_to_mask(req->evn.type)) {
			if (evi_pl_cb(ev, &req->evn, pticket, perr)) {
				if (req->evn.type & 0x10) {
					fd->write--;
				}
				else {
					fd->read--;
				}

				*preq = req->next;
				free(req);

				if (!fd->head) {
					if (fd->next) fd->next->slot = fd->slot;
					*fd->slot = fd->next;

					epoll_ctl(ev->async->epoll_fd, EPOLL_CTL_DEL, fd->fd, NULL);
				}
				else {
					epoll_ctl(ev->async->epoll_fd, EPOLL_CTL_MOD, fd->fd, &(struct epoll_event) {
						.data.ptr = fd,
						.events = evi_epoll_fd_to_mask(fd),
					});
				}

				return EV_POLL_OK;
			}
		}
	}

	if (ptimeout) return EV_POLL_TIMEOUT;
	return EV_POLL_EMPTY;
}

static ev_code_t evi_pl_impl_init(ev_t ev) {
	ev->async->epoll_fd = epoll_create(16);
	ev->async->head = NULL;

	return EV_OK;
}
static ev_code_t evi_pl_impl_free(ev_t ev) {
	(void)ev;
	return EV_OK;
}
