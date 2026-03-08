#pragma once

#include <ev/conf.h>
#include <ev/errno.h>
#include <ev.h>

#include "./multithread.h"

typedef struct ev_msg {
	struct ev_msg *next;
	void *udata;
	int err;
} *ev_msg_t;

typedef struct {
	ev_mutex_t lock;
	ev_msg_t head;
} *ev_queue_t, ev_queue_s;
