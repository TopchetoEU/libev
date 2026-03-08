#pragma once
#include <ev/conf.h>

// IWYU pragma: begin_exports
#ifdef EV_USE_URING
	#include "./unix/uring.h"
// #elif defined EV_USE_POSIX
// 	#include "./unix/poll.h"
#else
	#include "./ansi/async.h"
#endif
