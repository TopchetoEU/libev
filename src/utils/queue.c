#pragma once

#include <ev/conf.h>
#include <ev/errno.h>
#include <ev.h>

#include <stdlib.h>

#include "./multithread.h"
#include "./queue.h"
#include "../ev.h"

static ev_code_t evi_queue_push(ev_t ev, void *udata, ev_code_t err) {
	ev_msg_t msg = malloc(sizeof *msg);
	if (!msg) return EV_ENOMEM;

	ev_mutex_lock(ev->queue->lock);

	msg->next = ev->queue->head;
	msg->udata = udata;
	msg->err = err;
	ev->queue->head = msg;

	ev_mutex_unlock(ev->queue->lock);

	return EV_OK;
}
static bool evi_queue_pop(ev_t ev, void **pudata, int *perr) {
	ev_mutex_lock(ev->queue->lock);

	if (!ev->queue->head) {
		ev_mutex_unlock(ev->queue->lock);
		return false;
	}

	ev_msg_t msg = ev->queue->head;
	ev->queue->head = msg->next;
	*pudata = msg->udata;
	*perr = msg->err;

	free(msg);

	ev_mutex_unlock(ev->queue->lock);
	return true;
}

static ev_code_t evi_queue_init(ev_t ev) {
	ev->queue->head = NULL;
	ev_mutex_new(ev->queue->lock);
	return EV_OK;
}
static ev_code_t evi_queue_free(ev_t ev) {
	(void)ev;
	ev_mutex_lock(ev->queue->lock);
	while (ev->queue->head) {
		ev_msg_t next = ev->queue->head->next;
		free(ev->queue->head);
		ev->queue->head = next;
	}
	ev_mutex_unlock(ev->queue->lock);
	ev_mutex_free(ev->queue->lock);
	return EV_OK;
}
