#pragma once

#include <ev/errno.h>
#include <ev.h>
#include <unistd.h>

#include "./pollish.h"

#include "../../utils/queue.c"
#include "./sync.c"
#include "../async.c"
#include "./utils.c"

static bool evi_pl_cb(ev_t ev, const ev_pl_event_t *evn, void **pudata, ev_code_t *perr) {
	if (evn->fd == ev->async->pl->usermsg_read) {
		uint8_t dummy;
		read(ev->async->pl->usermsg_read, &dummy, sizeof dummy);
		return false;
	}

	ev_handle_t fd = evi_unix_mkfd(evn->fd);

	*pudata = evn->ticket;

	switch (evn->type) {
		case EVI_POLL_PREAD:
			*perr = evs_file_read(fd, evn->rw.data, evn->rw.pn, evn->rw.offset);
			break;
		case EVI_POLL_READ:

			*perr = evs_read(fd, evn->rw.data, evn->rw.pn);
			break;
		case EVI_POLL_PWRITE:
			*perr = evs_file_write(fd, evn->rw.data, evn->rw.pn, evn->rw.offset);
			break;
		case EVI_POLL_WRITE:
			*perr = evs_write(fd, evn->rw.data, evn->rw.pn);
			break;
		case EVI_POLL_ACCEPT:
			*perr = evs_server_accept(evn->accept.pres, evn->accept.paddr, evn->accept.pport, (ev_server_t)(size_t)evn->fd);
			break;
	}

	evi_unix_freefd(fd);
	return true;
}

ev_code_t evi_pl_push(ev_t ev, void *udata, ev_code_t err) {
	ev_code_t code = evi_queue_push(ev, udata, err);
	if (code != EV_OK) return code;

	if (write(ev->async->pl->usermsg_write, &(uint8_t) { 0 }, sizeof(uint8_t)) < 0) {
		if (errno == EWOULDBLOCK) return EV_OK;
		return evi_unix_conv_errno(errno);
	}

	return EV_OK;
}

ev_code_t ev_push(ev_t ev, void *ticket, ev_code_t err) {
	ev_code_t code = evi_queue_push(ev, ticket, err);
	if (code != EV_OK) return code;

	if (write(ev->async->pl->usermsg_write, &(uint8_t) { 0 }, sizeof(uint8_t)) < 0) {
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

		switch (evi_pl_impl_poll(ev, ptimeout, pticket, perr)) {
			case EV_POLL_OK:
				ev_end(ev);
				return true;
			case EV_POLL_TIMEOUT:
				return false;
			case EV_POLL_EMPTY:
				break;
		}
	}
}

ev_code_t ev_read(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn) {
	if (!evi_unix_isfd(stream)) return EV_EBADF;

	ev_begin(ev);

	return evi_pl_impl_add(ev, (ev_pl_event_t) {
		.ticket = udata,
		.type = EVI_POLL_READ,
		.fd = evi_unix_fd(stream),
		.rw = { .data = buff, .pn = pn },
	});
}
ev_code_t ev_write(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn) {
	if (!evi_unix_isfd(stream)) return EV_EBADF;

	ev_begin(ev);

	return evi_pl_impl_add(ev, (ev_pl_event_t) {
		.ticket = udata,
		.type = EVI_POLL_WRITE,
		.fd = evi_unix_fd(stream),
		.rw = { .data = buff, .pn = pn },
	});
}
ev_code_t ev_file_read(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn, size_t offset) {
	if (!evi_unix_isfd(stream)) return EV_EBADF;

	ev_begin(ev);

	return evi_pl_impl_add(ev, (ev_pl_event_t) {
		.ticket = udata,
		.type = EVI_POLL_PREAD,
		.fd = evi_unix_fd(stream),
		.rw = { .data = buff, .pn = pn, .offset = offset },
	});
}
ev_code_t ev_file_write(ev_t ev, void *udata, ev_handle_t stream, char *buff, size_t *pn, size_t offset) {
	if (!evi_unix_isfd(stream)) return EV_EBADF;

	ev_begin(ev);

	return evi_pl_impl_add(ev, (ev_pl_event_t) {
		.ticket = udata,
		.type = EVI_POLL_PWRITE,
		.fd = evi_unix_fd(stream),
		.rw = { .data = buff, .pn = pn, .offset = offset },
	});
}
ev_code_t ev_server_accept(ev_t ev, void *udata, ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	ev_begin(ev);

	return evi_pl_impl_add(ev, (ev_pl_event_t) {
		.ticket = udata,
		.type = EVI_POLL_ACCEPT,
		.fd = (int)(size_t)server,
		.accept = { .pres = pres, .paddr = paddr, .pport = pport },
	});
}

static ev_code_t evi_async_init(ev_t ev) {
	ev_code_t code = evi_pl_impl_init(ev);
	if (code != EV_OK) return code;

	int msg_pipe[2];
	if (pipe(msg_pipe) < 0) goto fail;
	if (fcntl(msg_pipe[0], F_SETFD, O_NONBLOCK) < 0) goto fail_pipe;
	if (fcntl(msg_pipe[1], F_SETFD, O_NONBLOCK) < 0) goto fail_pipe;

	ev->async->pl->usermsg_read = msg_pipe[0];
	ev->async->pl->usermsg_write = msg_pipe[1];

	evi_pl_impl_add(ev, (ev_pl_event_t) {
		.type = EVI_POLL_READ,
		.fd = ev->async->pl->usermsg_read,
	});

	return EV_OK;

fail_pipe:
	close(msg_pipe[0]);
	close(msg_pipe[1]);
fail:
	return evi_unix_conv_errno(errno);
}
static ev_code_t evi_async_free(ev_t ev) {
	ev_code_t code = evi_pl_impl_free(ev);
	if (code != EV_OK) return code;

	close(ev->async->pl->usermsg_read);
	close(ev->async->pl->usermsg_write);
	return EV_OK;
}

#define EVI_ASYNC_READ
#define EVI_ASYNC_WRITE
#define EVI_ASYNC_FILE_READ
#define EVI_ASYNC_FILE_WRITE
#define EVI_ASYNC_SERVER_ACCEPT
