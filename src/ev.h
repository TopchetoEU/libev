#pragma once

#include <ev/conf.h>
#include <ev.h>

#include <stddef.h>

#include "./impl/async.h"
#include "./utils/queue.h"

#ifdef EV_USE_MULTITHREAD
	#include "./utils/pool.h"
#endif

struct ev {
	size_t active_n;

	ev_async_s async[1];
	ev_queue_s queue[1];

	ev_handle_t in, out, err;

	#ifdef EV_USE_MULTITHREAD
		ev_pool_s pool[1];
	#endif
};
