#pragma once
#include "ev/conf.h"

// IWYU pragma: begin_exports
#ifdef EV_USE_URING
	#include "../unix/uring.c"
// #elif defined EV_USE_POSIX
// 	#include "../unix/poll.c"
#else
	#include "../generic/async.c"
#endif
