#pragma once

#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

typedef enum {
	EVI_POLL_READ,
	EVI_POLL_WRITE,
	EVI_POLL_PREAD,
	EVI_POLL_PWRITE,
} ev_async_type_t;

typedef struct {
	void *ticket;
	ev_code_t err;
} ev_async_msg_t;

typedef struct ev_poll_req {
	struct ev_poll_req **slot;
	struct ev_poll_req *next;
	size_t pollfd_i;
	void *ticket;
	ev_async_type_t type;
	int fd;
	union {
		struct { char *data; size_t *pn; size_t offset; } rw;
	};
} *ev_poll_req_t;

typedef struct ev_async {
	struct pollfd *fds;
	size_t fds_cap;
	ev_poll_req_t req_head;

	int usermsg_read, usermsg_write;
} *ev_async_t, ev_async_s;
