#pragma once

#include "ev/conf.h"
#include "ev.h"
#include "multithread.h"
#include "ev/errno.h"

typedef struct ev_msg {
	struct ev_msg *next;
	void *udata;
	int err;
} *ev_msg_t;

typedef struct {
	ev_mutex_t lock;
	ev_cond_t has_msg_cond;
	ev_msg_t head;
} *ev_queue_t, ev_queue_s;

ev_code_t evi_queue_push(ev_queue_t queue, void *udata, ev_code_t err) {
	ev_msg_t msg = malloc(sizeof *msg);
	if (!msg) return EV_ENOMEM;

	ev_mutex_lock(queue->lock);

	msg->next = queue->head;
	msg->udata = udata;
	msg->err = err;
	queue->head = msg;

	#ifdef EV_USE_MULTITHREAD
		ev_cond_broadcast(queue->has_msg_cond);
	#endif

	ev_mutex_unlock(queue->lock);

	return EV_OK;
}
bool evi_queue_poll(ev_queue_t queue, const ev_time_t *ptimeout, void **pudata, int *perr) {
	ev_mutex_lock(queue->lock);

	while (!queue->head) {
		#ifdef EV_USE_MULTITHREAD
			if (ptimeout) {
				if (ev_cond_timewait(queue->has_msg_cond, queue->lock, *ptimeout) == EV_ETIMEDOUT) {
					ev_mutex_unlock(queue->lock);
					return false;
				}
			}
			else {
				ev_cond_wait(queue->has_msg_cond, queue->lock);
			}
		#else
			if (ptimeout) {
				evs_sleep(*ptimeout);
			}
			else {
				// In non-threaded mode, it is impossible for us to get a message while we're blocked
				// So we disobey the user and timeout instead
			}
			return false;
		#endif
	}

	ev_msg_t msg = queue->head;
	queue->head = msg->next;
	*pudata = msg->udata;
	*perr = msg->err;

	free(msg);

	ev_mutex_unlock(queue->lock);

	return true;
}

static ev_code_t evi_queue_init(ev_queue_t queue) {
	queue->head = NULL;
	ev_cond_new(queue->has_msg_cond);
	ev_mutex_new(queue->lock);
	return EV_OK;
}
static ev_code_t evi_queue_free(ev_queue_t queue) {
	ev_cond_free(queue->has_msg_cond);
	ev_mutex_free(queue->lock);
	return EV_OK;
}
