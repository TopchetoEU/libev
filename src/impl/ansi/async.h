#pragma once

#include <ev/conf.h>

#ifdef EV_USE_MULTITHREAD
	#include "../../utils/multithread.h"
#endif
#include "../../utils/queue.h"

typedef struct ev_async {
	#ifdef EV_USE_MULTITHREAD
		ev_mutex_t lock;
		ev_cond_t cond;
	#endif
	ev_queue_s queue[1];
} *ev_async_t, ev_async_s;
