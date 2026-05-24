#pragma once

#include <ev/conf.h>
#include <ev/sync.h>
#include <ev/errno.h>
#include <ev.h>

#include <sys/poll.h>

#include "./poll.h"
#include "./pollish.h"

#include "../async.h"
#include "../../ev.h"
#include "./pollish.c"

static uint64_t evi_async_subms_diff(ev_time_t timeout) {
	ev_time_t now;
	if (evs_monotime(&now) != EV_OK) return 0;

	ev_time_t diff = ev_timesub(now, timeout);
	if (diff.sec != 0) return 0;
	if (diff.nsec > 1000000) return 0;
	return diff.nsec;
}

static bool evi_poll_addfd(ev_async_t async, int fd, bool write, size_t *pn, size_t *ppollfd_i) {
	struct pollfd *target = NULL;
	for (size_t i = 0; i < *pn; i++) {
		if (async->fds[i].fd == fd) {
			target = &async->fds[i];
			break;
		}
	}

	if (!target) {
		if (*pn >= async->fds_cap) {
			async->fds_cap *= 2;
			if (!async->fds_cap) async->fds_cap = 16;

			async->fds = realloc(async->fds, sizeof *async->fds * async->fds_cap);
			if (!async->fds) return false;
		}

		target = &async->fds[*pn];
		(*pn)++;
	}

	memset(&async->fds[*pn], 0 ,sizeof *async->fds);

	if (write) target->events |= POLLOUT;
	else target->events |= POLLIN;

	target->fd = fd;
	*ppollfd_i = target - async->fds;

	return true;
}

static ev_poll_node_t evi_poll_pushreq(ev_t ev) {
	ev_poll_node_t req = malloc(sizeof *req);
	if (!req) return NULL;

	if (ev->async->req_head) ev->async->req_head->slot = &req->next;
	req->next = ev->async->req_head;
	req->slot = &ev->async->req_head;
	ev->async->req_head = req;
	return req;
}

static size_t evi_poll(ev_t ev, size_t fd_n, const ev_time_t *ptimeout) {
	while (true) {
		int code;
		if (ptimeout) {
			ev_time_t now = { 0 };
			evs_monotime(&now);
			ev_time_t diff = ev_timesub(*ptimeout, now);

			#ifdef _GNU_SOURCE
				if (diff.sec < 0) {
					diff.sec = 0;
					diff.nsec = 0;
				}
				code = ppoll(ev->async->fds, fd_n, &(struct timespec) { .tv_sec = diff.sec, .tv_nsec = diff.nsec }, NULL);
			#else
				int64_t diff_ms = ev_timems(diff);
				if (diff_ms < 0) diff_ms = 0;
				code = poll(ev->async->fds, fd_n, diff_ms);
			#endif
		}
		else {
			code = poll(ev->async->fds, fd_n, -1);
		}

		if (code < 0) {
			if (errno == EINTR || errno == EAGAIN) continue;
			assert(false && "poll call failed");
		}

		return code;
	}
}

ev_code_t evi_pl_impl_add(ev_t ev, ev_pl_event_t evn) {
	ev_poll_node_t node = evi_poll_pushreq(ev);
	if (!node) return EV_ENOMEM;

	node->evn = evn;
	return EV_OK;
}

static ev_pl_res_t evi_pl_impl_poll(ev_t ev, const ev_time_t *ptimeout, void **pticket, ev_code_t *perr) {
	size_t fd_n = 0;
	size_t usermsg_pollfd_i;
	if (!evi_poll_addfd(ev->async, ev->async->pl->usermsg_read, false, &fd_n, &usermsg_pollfd_i)) return EV_POLL_TIMEOUT;

	for (ev_poll_node_t it = ev->async->req_head; it; it = it->next) {
		switch (it->evn.type) {
			case EVI_POLL_PREAD:
			case EVI_POLL_READ:
			case EVI_POLL_ACCEPT: {
				if (!evi_poll_addfd(ev->async, it->evn.fd, false, &fd_n, &it->pollfd_i)) return EV_POLL_TIMEOUT;
				break;
			}
			case EVI_POLL_PWRITE:
			case EVI_POLL_WRITE: {
				if (!evi_poll_addfd(ev->async, it->evn.fd, true, &fd_n, &it->pollfd_i)) return EV_POLL_TIMEOUT;
				break;
			}
		}
	}

	evi_poll(ev, fd_n, ptimeout);

	for (ev_poll_node_t it = ev->async->req_head; it; it = it->next) {
		struct pollfd pollfd = ev->async->fds[it->pollfd_i];
		int mask = 0;

		switch (it->evn.type) {
			case EVI_POLL_ACCEPT:
			case EVI_POLL_READ:
			case EVI_POLL_PREAD: mask = POLLIN | POLLERR | POLLHUP; break;

			case EVI_POLL_WRITE:
			case EVI_POLL_PWRITE: mask = POLLOUT | POLLERR | POLLHUP; break;
		}

		if (pollfd.revents & mask) {
			if (evi_pl_cb(ev, &it->evn, pticket, perr)) {
				if (it->next) it->next->slot = it->slot;
				*it->slot = it->next;
				free(it);

				return EV_POLL_OK;
			}
		}
	}

	if (ptimeout) return EV_POLL_TIMEOUT;
	return EV_POLL_EMPTY;
}

static ev_code_t evi_pl_impl_init(ev_t ev) {
	ev->async->fds = NULL;
	ev->async->fds_cap = 0;
	ev->async->req_head = NULL;

	return EV_OK;
}
static ev_code_t evi_pl_impl_free(ev_t ev) {
	(void)ev;
	return EV_OK;
}
