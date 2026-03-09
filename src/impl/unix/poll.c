#pragma once
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/poll.h>
#include <unistd.h>

#include "../../utils/multithread.h"
#include "../../utils/queue.c"
#include "./poll.h"

#include "./utils.c"


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

static ev_poll_req_t evi_poll_pushreq(ev_t ev) {
	ev_poll_req_t req = malloc(sizeof *req);
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
			ev_time_t diff = ev_timesub(now, *ptimeout);

			#ifdef _GNU_SOURCE
				code = ppoll(ev->async->fds, fd_n, &(struct timespec) { .tv_sec = diff.sec, .tv_nsec = diff.nsec }, NULL);
			#else
				int64_t diff_ms = ev_timems(diff);
				if (diff_ms < 0) diff_ms = 0;
				code = poll(ev->async->fds, fd_n, diff_ms);
			#endif
		}
		else {
			code = poll(ev->async->fds, fd_n, 1000);
		}

		if (code < 0) {
			if (errno == EINTR || errno == EAGAIN) continue;
			assert(false && "poll call failed");
		}

		return code;
	}
}

static ev_code_t evi_setres(ev_t ev, void *ticket, ev_code_t err, void **pticket, ev_code_t *perr, bool *set) {
	if (*set) {
		ev_code_t code = evi_queue_push(ev, ticket, err);
		if (code != EV_OK) return code;
	}
	else {
		*pticket = ticket;
		*perr = err;
		*set = true;
		ev_end(ev);
	}

	return EV_OK;
}

ev_code_t ev_push(ev_t ev, void *ticket, ev_code_t err) {
	ev_code_t code = evi_queue_push(ev, ticket, err);
	if (code != EV_OK) return code;

	if (write(ev->async->usermsg_write, &(uint8_t) { 0 }, sizeof(uint8_t)) < 0) {
		if (errno == EWOULDBLOCK) return EV_OK;
		return evi_unix_conv_errno(errno);
	}
	return EV_OK;
}
bool ev_poll(ev_t ev, const ev_time_t *ptimeout, void **pticket, int *perr) {
	while (true) {
		if (evi_queue_pop(ev, pticket, perr)) {
			ev_end(ev);
			return true;
		}

		size_t fd_n = 0;
		size_t usermsg_pollfd_i;
		if (!evi_poll_addfd(ev->async, ev->async->usermsg_read, false, &fd_n, &usermsg_pollfd_i)) return EV_ENOMEM;

		for (ev_poll_req_t it = ev->async->req_head; it; it = it->next) {
			switch (it->type) {
				case EVI_POLL_PREAD:
				case EVI_POLL_READ: {
					if (!evi_poll_addfd(ev->async, it->fd, false, &fd_n, &it->pollfd_i)) return EV_ENOMEM;
					break;
				}
				case EVI_POLL_PWRITE:
				case EVI_POLL_WRITE: {
					if (!evi_poll_addfd(ev->async, it->fd, true, &fd_n, &it->pollfd_i)) return EV_ENOMEM;
					break;
				}
			}
		}

		size_t n = evi_poll(ev, fd_n, ptimeout);
		if (!n) {
			if (ptimeout) return false;
			continue;
		}

		bool set = false;

		for (ev_poll_req_t it = ev->async->req_head; it; ) {
			ev_poll_req_t next = it->next;
			bool work_done = false;
			ssize_t n = 0;

			struct pollfd pollfd = ev->async->fds[it->pollfd_i];

			if (pollfd.revents & POLLHUP) {
				work_done = true;
			}
			else {
				switch (it->type) {
					case EVI_POLL_PREAD: {
						if (pollfd.revents & (POLLIN | POLLERR)) {
							n = pread(it->fd, it->rw.data, *it->rw.pn, it->rw.offset);
							pollfd.revents &= ~POLLIN;
							work_done = true;
						}
						break;
					}
					case EVI_POLL_READ: {
						if (pollfd.revents & (POLLIN | POLLERR)) {
							n = read(it->fd, it->rw.data, *it->rw.pn);
							pollfd.revents &= ~POLLIN;
							work_done = true;
						}
						break;
					}
					case EVI_POLL_PWRITE: {
						if (pollfd.revents & (POLLOUT | POLLERR)) {
							n = pwrite(it->fd, it->rw.data, *it->rw.pn, it->rw.offset);
							pollfd.revents &= ~POLLOUT;
							work_done = true;
						}
						break;
					}
					case EVI_POLL_WRITE: {
						if (pollfd.revents & (POLLOUT | POLLERR)) {
							n = write(it->fd, it->rw.data, *it->rw.pn);
							pollfd.revents &= ~POLLOUT;
							work_done = true;
						}
						break;
					}
				}
			}

			if (work_done) {
				if (n < 0) {
					ev_code_t code = evi_setres(ev, it->ticket, errno, pticket, perr, &set);
					if (code != EV_OK) return code;
				}
				else {
					*it->rw.pn = n;
					ev_code_t code = evi_setres(ev, it->ticket, 0, pticket, perr, &set);
					if (code != EV_OK) return code;
				}

				if (it->next) it->next->slot = it->slot;
				*it->slot = it->next;

				free(it);
			}

			it = next;
		}

		if (ev->async->fds[usermsg_pollfd_i].revents & POLLIN) {
			uint8_t dummy;
			read(ev->async->usermsg_read, &dummy, sizeof dummy);

			void *ticket;
			ev_code_t err;
			if (evi_queue_pop(ev, &ticket, &err)) {
				ev_code_t code = evi_setres(ev, ticket, err, pticket, perr, &set);
				if (code != EV_OK) return code;
			}
		}

		return true;
	}
}

ev_code_t ev_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_poll_req_t req = evi_poll_pushreq(ev);
	if (!req) return EV_ENOMEM;

	ev_begin(ev);
	if (!evi_unix_isfd(fd)) return ev_push(ev, ticket, EV_EBADF);

	req->type = EVI_POLL_READ;
	req->ticket = ticket;
	req->fd = evi_unix_fd(fd);
	req->rw.data = buff;
	req->rw.pn = n;
	return EV_OK;
}
ev_code_t ev_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n) {
	ev_poll_req_t req = evi_poll_pushreq(ev);
	if (!req) return EV_ENOMEM;

	ev_begin(ev);
	if (!evi_unix_isfd(fd)) return ev_push(ev, ticket, EV_EBADF);

	req->type = EVI_POLL_WRITE;
	req->ticket = ticket;
	req->fd = evi_unix_fd(fd);
	req->rw.data = buff;
	req->rw.pn = n;
	return EV_OK;
}
ev_code_t ev_file_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_poll_req_t req = evi_poll_pushreq(ev);
	if (!req) return EV_ENOMEM;

	ev_begin(ev);
	if (!evi_unix_isfd(fd)) return ev_push(ev, ticket, EV_EBADF);

	req->type = EVI_POLL_PREAD;
	req->ticket = ticket;
	req->fd = evi_unix_fd(fd);
	req->rw.data = buff;
	req->rw.pn = n;
	req->rw.offset = offset;
	return EV_OK;
}
ev_code_t ev_file_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	ev_poll_req_t req = evi_poll_pushreq(ev);
	if (!req) return EV_ENOMEM;

	ev_begin(ev);
	if (!evi_unix_isfd(fd)) return ev_push(ev, ticket, EV_EBADF);

	req->type = EVI_POLL_PWRITE;
	req->ticket = ticket;
	req->fd = evi_unix_fd(fd);
	req->rw.data = buff;
	req->rw.pn = n;
	req->rw.offset = offset;
	return EV_OK;
}

static ev_code_t evi_async_init(ev_t ev) {
	int msg_pipe[2];
	if (pipe(msg_pipe) < 0) goto fail;
	if (fcntl(msg_pipe[0], F_SETFD, O_NONBLOCK) < 0) goto fail_pipe;
	if (fcntl(msg_pipe[1], F_SETFD, O_NONBLOCK) < 0) goto fail_pipe;

	ev->async->fds = NULL;
	ev->async->fds_cap = 0;
	ev->async->req_head = NULL;

	ev->async->usermsg_read = msg_pipe[0];
	ev->async->usermsg_write = msg_pipe[1];

	return EV_OK;

fail_pipe:
	close(msg_pipe[0]);
	close(msg_pipe[1]);
fail:
	return evi_unix_conv_errno(errno);
}
static ev_code_t evi_async_free(ev_t ev) {
	close(ev->async->usermsg_read);
	close(ev->async->usermsg_write);
	return EV_OK;
}

#define EVI_ASYNC_READ
#define EVI_ASYNC_WRITE
#define EVI_ASYNC_FILE_READ
#define EVI_ASYNC_FILE_WRITE
