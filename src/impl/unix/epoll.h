#pragma once

#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include "./pollish.h"

// Describes one request for one fd - read/write/accept
typedef struct ev_epoll_req {
	struct ev_epoll_req *next;
	ev_pl_event_t evn;
} *ev_epoll_req_t;
// Correlates to a single registration in epoll - so to one fd
// Contains a list of all pending operations for the fd
typedef struct ev_epoll_fd {
	struct ev_epoll_fd **slot;
	struct ev_epoll_fd *next;

	ev_epoll_req_t head;
	int fd;
	size_t read, write;
} *ev_epoll_fd_t;

typedef struct ev_async {
	ev_pl_s pl[1];
	ev_epoll_fd_t head;
	int epoll_fd;
} *ev_async_t, ev_async_s;
