#pragma once

#include <ev/conf.h>
#include <ev/errno.h>

#include <stddef.h>

#include "../ev.h"

#include "../utils/queue.c"

ev_code_t ev_push(ev_t ev, void *udata, ev_code_t err) {
	ev_mutex_lock(ev->async->lock);

	ev_code_t code = evi_queue_push(ev, udata, err);
	if (code != EV_OK) {
		ev_mutex_unlock(ev->async->lock);
		return code;
	}

	#ifdef EV_USE_MULTITHREAD
		ev_cond_broadcast(ev->async->cond);
	#endif

	ev_mutex_unlock(ev->async->lock);

	return EV_OK;
}
bool ev_poll(ev_t ev, const ev_time_t *ptimeout, void **pudata, int *perr) {
	ev_mutex_lock(ev->async->lock);

	while (true) {
		if (evi_queue_pop(ev, pudata, perr)) {
			ev_mutex_unlock(ev->async->lock);
			ev->active_n--;
			return true;
		}

		#ifdef EV_USE_MULTITHREAD
			if (ptimeout) {
				if (ev_cond_timewait(ev->async->cond, ev->async->lock, *ptimeout) == EV_ETIMEDOUT) {
					ev_mutex_unlock(ev->async->lock);
					return false;
				}
			}
			else {
				ev_cond_wait(ev->async->cond, ev->async->lock);
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
}

static ev_code_t evi_async_init(ev_t ev) {
	(void)ev;
	#ifdef EV_USE_MULTITHREAD
		ev_mutex_new(ev->async->lock);
		ev_cond_new(ev->async->cond);
	#endif
	return EV_OK;
}
static ev_code_t evi_async_free(ev_t ev) {
	(void)ev;
	#ifdef EV_USE_MULTITHREAD
		ev_mutex_free(ev->async->lock);
		ev_cond_free(ev->async->cond);
	#endif
	return EV_OK;
}
