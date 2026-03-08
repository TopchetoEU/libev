#pragma once
#include <ev/conf.h>

// IWYU pragma: begin_exports
#ifdef EV_USE_POSIX
	#include "./unix/sync.c"
#elif defined EV_USE_WIN32
	#include "./win/sync.c"
#else
	#include "./ansi/sync.c"
#endif
