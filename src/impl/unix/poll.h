#pragma once

#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include "./pollish.h"

typedef struct ev_poll_node {
	struct ev_poll_node **slot;
	struct ev_poll_node *next;

	ev_pl_event_t evn;
	size_t pollfd_i;
} *ev_poll_node_t;

typedef struct ev_async {
	struct pollfd *fds;
	size_t fds_cap;
	ev_poll_node_t req_head;
	ev_pl_s pl[1];
} *ev_async_t, ev_async_s;
